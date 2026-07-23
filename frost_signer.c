/* frost_signer.c — FROST signer node.
 *
 * Mode-aware: the coordinator's HELLO_ACK now carries 'D' (DKG) or 'S' (SIGN).
 *
 * DKG mode
 *   Participates in Pedersen DKG rounds 1-3.  On completion, persists the
 *   KeyPackage to ./shares/signer_<id>.keypkg (hex) so future signing
 *   sessions can reload it without repeating DKG.
 *
 * SIGN mode
 *   Loads KeyPackage from disk immediately after HELLO_ACK.  If no file
 *   is found, sends FROST_MSG_SHARE_LOAD_FAIL so the coordinator can
 *   exclude this node from signing sessions.  Otherwise participates in
 *   the ROAST-managed commit → sign cycle.
 *
 * Key persistence format:
 *   ./shares/signer_<id>.keypkg  — hex-encoded KeyPackage, one line
 *
 * NOTE: For production use, encrypt the share file before writing.
 *   GnuTLS provides gnutls_cipher_{encrypt,decrypt} with
 *   GNUTLS_CIPHER_AES_256_GCM.  Dropping that in requires only replacing
 *   save_key_material() and load_key_material() with versions that wrap
 *   the hex bytes with a [16-byte salt | 12-byte IV | 16-byte tag |
 *   ciphertext] envelope and derive the key with PBKDF2.  The rest of
 *   this file is unchanged.
 *
 * Usage: ./frost_signer <cert_file> <key_file> <id> <n> <t> [--fault <type>]
 *
 * <id> is the identity this signer asserts to the coordinator (1..n).
 * It must match the numeric suffix of the cert/key pair on disk at
 * certs/signer<id>.crt / certs/signer<id>key.pem — that's the same
 * naming scheme every signer uses to look up peers' public keys when
 * encrypting DKG round-2 packages, so it must line up with whichever
 * private key this process actually holds. The signer verifies those
 * files exist before connecting, then sends <id> to the coordinator in
 * HELLO. The coordinator accepts it only if no other connected signer
 * already holds that ID; otherwise it rejects and this process exits.
 */

#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/queue.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <gnutls/gnutls.h>
#include <gnutls/x509.h>

#include "frost_common.h"
#include "frost_stubs.c"

/* ══════════════════════════════════════════════════════════════════
 * Signer state
 * ══════════════════════════════════════════════════════════════════ */

static uint16_t g_my_id = 0;
static int g_id_confirmed = 0; /* set once coordinator ACKs our asserted ID */
static uint16_t g_n = 0;
static uint16_t g_t = 0;
static dkg_state_t g_state = DKG_IDLE;
static coord_mode_t g_coord_mode = COORD_MODE_DKG; /* set from HELLO_ACK */

/* DKG key material */
static uint8_t g_r1_secret[FROST_MAX_PAYLOAD];
static uint16_t g_r1_secret_len = 0;
static uint8_t g_r2_secret[FROST_MAX_PAYLOAD];
static uint16_t g_r2_secret_len = 0;
static uint8_t g_key_pkg[FROST_MAX_PAYLOAD];
static uint16_t g_key_pkg_len = 0;
static uint8_t g_pub_key_pkg[FROST_MAX_PAYLOAD];
static uint16_t g_pub_key_pkg_len = 0;

/* Signing nonces (one-time use, zeroed after signing) */
static uint8_t g_nonces[FROST_MAX_PAYLOAD];
static uint16_t g_nonces_len = 0;

/* Commitment storage for at-request and pre-computation */
static uint8_t g_commit[FROST_MAX_PAYLOAD];
static uint16_t g_commit_len = 0;
static uint8_t g_commit_is_precomputed = 0;

/* Peer round-1 packages */
static uint8_t g_peer_r1[FROST_MAX_SIGNERS][FROST_MAX_PAYLOAD];
static uint16_t g_peer_r1_len[FROST_MAX_SIGNERS];
static uint16_t g_peer_r1_ids[FROST_MAX_SIGNERS];
static int g_peer_r1_count = 0;

/* Peer round-2 packages */
static uint8_t g_peer_r2[FROST_MAX_SIGNERS][FROST_MAX_PAYLOAD];
static uint16_t g_peer_r2_len[FROST_MAX_SIGNERS];
static uint16_t g_peer_r2_ids[FROST_MAX_SIGNERS];
static int g_peer_r2_count = 0;

/* Refresh round-1 and round-2 state (separate from DKG to allow clean reuse) */
static uint8_t g_ref_r1_secret[FROST_MAX_PAYLOAD];
static uint16_t g_ref_r1_secret_len = 0;
static uint8_t g_ref_r2_secret[FROST_MAX_PAYLOAD];
static uint16_t g_ref_r2_secret_len = 0;

static uint8_t g_ref_peer_r1[FROST_MAX_SIGNERS][FROST_MAX_PAYLOAD];
static uint16_t g_ref_peer_r1_len[FROST_MAX_SIGNERS];
static uint16_t g_ref_peer_r1_ids[FROST_MAX_SIGNERS];
static int g_ref_peer_r1_count = 0;

static uint8_t g_ref_peer_r2[FROST_MAX_SIGNERS][FROST_MAX_PAYLOAD];
static uint16_t g_ref_peer_r2_len[FROST_MAX_SIGNERS];
static uint16_t g_ref_peer_r2_ids[FROST_MAX_SIGNERS];
static int g_ref_peer_r2_count = 0;

static uint8_t g_ref_r1_pkg[FROST_MAX_PAYLOAD];
static uint16_t g_ref_r1_pkg_len = 0;

/* Coordinator connection */
static int g_coord_sock = -1;
static gnutls_session_t g_coord_sess;
static uint8_t g_inbuf[FROST_FRAME_MAX];
static uint8_t *g_inptr;
static int g_want_write = 0;

gnutls_privkey_t my_priv;

TAILQ_HEAD(outq_head, outmsg) g_outq;

typedef enum {
  FAULT_NONE = 0,
  FAULT_BAD_SHARE, /* send a randomly corrupted signature share */
  FAULT_SILENT,    /* send commit but never respond with a share */
  FAULT_NO_COMMIT, /* connect and handshake but never commit     */
  FAULT_DROPOUT,   /* disconnect immediately after receiving SIGN_REQ */
} fault_mode_t;

static fault_mode_t g_fault = FAULT_NONE;

/* ══════════════════════════════════════════════════════════════════
 * Key share persistence
 * ══════════════════════════════════════════════════════════════════ */

static void keypkg_path(uint16_t id, char *buf, size_t max) {
  snprintf(buf, max, FROST_SHARES_DIR "/signer_%u.keypkg", (unsigned)id);
}

/*  Write the KeyPackage (and PublicKeyPackage) to disk after DKG.
 *
 *  Stored as a plain hex string.  For production, replace with an
 *  AES-256-GCM encrypted blob (see file header note).
 */
static int save_key_material(void) {
  check_in(CP_KEYPKG_SAVE);
  mkdir(FROST_SHARES_DIR, 0700);

  char path[256];
  keypkg_path(g_my_id, path, sizeof(path));

  char hex[FROST_MAX_PAYLOAD * 2 + 4];
  bytes_to_hex(g_key_pkg, g_key_pkg_len, hex);

  FILE *fp = fopen(path, "w");
  if (!fp) {
    perror(path);
    check_out(CP_KEYPKG_SAVE);
    return -1;
  }
  fprintf(fp, "%s\n", hex);
  fclose(fp);
  printf("signer %u: KeyPackage saved → %s\n", g_my_id, path);

  /* Also save the PublicKeyPackage so the coordinator can reload it */
  FILE *pp = fopen(FROST_PUB_PKG_HEX, "w");
  if (pp) {
    bytes_to_hex(g_pub_key_pkg, g_pub_key_pkg_len, hex);
    fprintf(pp, "%s\n", hex);
    fclose(pp);
    printf("signer %u: PublicKeyPackage saved → " FROST_PUB_PKG_HEX "\n",
           g_my_id);
  }
  check_out(CP_KEYPKG_SAVE);
  return 0;
}

/*  Read the KeyPackage from disk.
 *  Returns 0 on success, -1 if the file is absent or unreadable.
 */
static int load_key_material(void) {
  check_in(CP_KEYPKG_LOAD);
  char path[256];
  keypkg_path(g_my_id, path, sizeof(path));

  FILE *fp = fopen(path, "r");
  if (!fp) {
    check_out(CP_KEYPKG_LOAD);
    return -1; /* normal: node has never run DKG */
  }

  char hex[FROST_MAX_PAYLOAD * 2 + 4];
  if (!fgets(hex, sizeof(hex), fp)) {
    fclose(fp);
    check_out(CP_KEYPKG_LOAD);
    return -1;
  }
  fclose(fp);

  int klen = hex_to_bytes(hex, g_key_pkg, FROST_MAX_PAYLOAD);
  if (klen <= 0) {
    fprintf(stderr, "signer: bad hex in %s\n", path);
    check_out(CP_KEYPKG_LOAD);
    return -1;
  }
  g_key_pkg_len = (uint16_t)klen;

  /* Also load PublicKeyPackage (not strictly needed by signer in sign mode,
   * but useful for consistency checks and logging).                        */
  FILE *pp = fopen(FROST_PUB_PKG_HEX, "r");
  if (pp) {
    if (fgets(hex, sizeof(hex), pp)) {
      int plen = hex_to_bytes(hex, g_pub_key_pkg, FROST_MAX_PAYLOAD);
      if (plen > 0)
        g_pub_key_pkg_len = (uint16_t)plen;
    }
    fclose(pp);
  }

  printf("signer %u: KeyPackage loaded from %s (%u bytes)\n", g_my_id, path,
         g_key_pkg_len);
  check_out(CP_KEYPKG_LOAD);
  return 0;
}

/* ══════════════════════════════════════════════════════════════════
 * Network helpers
 * ══════════════════════════════════════════════════════════════════ */

static void queue_to_coord(frost_msg_t type, const uint8_t *payload,
                           uint16_t plen) {
  struct outmsg *m = malloc(sizeof(*m));
  if (!m)
    return;
  m->len = (size_t)(FROST_FRAME_HDR + plen);
  m->sent = 0;
  m->data = malloc(m->len);
  if (!m->data) {
    free(m);
    return;
  }
  frost_encode_frame(m->data, type, payload, plen);
  TAILQ_INSERT_TAIL(&g_outq, m, entries);
}

static int drain_outq(void) {
  struct outmsg *m = TAILQ_FIRST(&g_outq);
  if (!m)
    return 0;
  check_in(CP_TLS_RECORD_SEND);
  int r = gnutls_record_send(g_coord_sess, m->data + m->sent, m->len - m->sent);
  check_out(CP_TLS_RECORD_SEND);
  if (r == GNUTLS_E_AGAIN || r == GNUTLS_E_INTERRUPTED) {
    g_want_write = gnutls_record_get_direction(g_coord_sess);
    return 0;
  }
  if (r < 0) {
    fprintf(stderr, "signer: send: %s\n", gnutls_strerror(r));
    return -1;
  }
  g_want_write = 0;
  m->sent += (size_t)r;
  if (m->sent >= m->len) {
    TAILQ_REMOVE(&g_outq, m, entries);
    free(m->data);
    free(m);
  }
  return 0;
}

static int connect_to_coordinator(gnutls_certificate_credentials_t cred) {
  int sockfd;
  struct sockaddr_in addr;
  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = inet_addr(FROST_COORD_HOST);
  addr.sin_port = htons(FROST_COORD_PORT);

  if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
    perror("socket");
    return -1;
  }
  if (connect(sockfd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
    perror("connect");
    close(sockfd);
    return -1;
  }

  gnutls_init(&g_coord_sess, GNUTLS_CLIENT);
  gnutls_credentials_set(g_coord_sess, GNUTLS_CRD_CERTIFICATE, cred);
  gnutls_handshake_set_timeout(g_coord_sess, GNUTLS_DEFAULT_HANDSHAKE_TIMEOUT);
  gnutls_priority_set_direct(g_coord_sess, "NORMAL", NULL);
  gnutls_session_set_verify_cert(g_coord_sess, "coordinator", 0);
  gnutls_transport_set_int(g_coord_sess, sockfd);

  int r = 0;
  check_in(CP_TLS_HANDSHAKE);
  LOOP_CHECK(r, gnutls_handshake(g_coord_sess));
  check_out(CP_TLS_HANDSHAKE);
  if (r < 0) {
    if (r == GNUTLS_E_CERTIFICATE_VERIFICATION_ERROR) {
      gnutls_datum_t out;
      unsigned status = gnutls_session_get_verify_cert_status(g_coord_sess);
      gnutls_certificate_verification_status_print(status, GNUTLS_CRT_X509,
                                                   &out, 0);
      fprintf(stderr, "signer: cert verify failure: %s\n", out.data);
      gnutls_free(out.data);
    } else {
      fprintf(stderr, "signer: TLS handshake: %s\n", gnutls_strerror(r));
    }
    close(sockfd);
    gnutls_deinit(g_coord_sess);
    return -1;
  }
  printf("signer: TLS connected to coordinator\n");
  return sockfd;
}

/* ══════════════════════════════════════════════════════════════════
 * Frame dispatch
 * ══════════════════════════════════════════════════════════════════ */

static void process_coord_frame(frost_msg_t type, const uint8_t *payload,
                                uint16_t plen) {
  switch (type) {

  /* ── HELLO_ACK ────────────────────────────────────────────────
   * "ACK <id> <mode:D|S>\n"
   * Sets g_my_id and g_coord_mode.  In SIGN mode, immediately tries
   * to load key material from disk.
   */
  case FROST_MSG_HELLO_ACK: {
    char buf[32] = {0};
    memcpy(buf, payload, plen < 31 ? plen : 31);
    char mode_char = 'D';
    uint16_t acked_id = 0;
    if (sscanf(buf, "ACK %hu %c", &acked_id, &mode_char) < 1) {
      fprintf(stderr, "signer: malformed HELLO_ACK: '%s'\n", buf);
      return;
    }
    if (acked_id != g_my_id) {
      /* Should never happen — the coordinator is supposed to echo back
       * exactly the ID we asserted in HELLO. Treat a mismatch as fatal
       * rather than silently adopting whatever ID it sent, since that
       * would reintroduce the exact identity confusion this scheme is
       * meant to prevent.                                             */
      fprintf(stderr,
              "signer %u: coordinator ACKed ID %u instead of requested "
              "%u — aborting\n",
              g_my_id, acked_id, g_my_id);
      exit(EXIT_FAILURE);
    }
    g_id_confirmed = 1;
    g_coord_mode = (mode_char == 'S')   ? COORD_MODE_SIGN
                   : (mode_char == 'R') ? COORD_MODE_REFRESH
                                        : COORD_MODE_DKG;

    if (g_coord_mode == COORD_MODE_SIGN || g_coord_mode == COORD_MODE_REFRESH) {
      if (load_key_material() != 0) {
        fprintf(stderr, "signer %u: no key material — cannot refresh\n",
                g_my_id);
        queue_to_coord(FROST_MSG_SHARE_LOAD_FAIL, NULL, 0);
      } else {
        printf("signer %u: key material loaded for %s\n", g_my_id,
               g_coord_mode == COORD_MODE_REFRESH ? "REFRESH" : "SIGN");
      }
    }
    break;
  }

  /* ── START_DKG ────────────────────────────────────────────────
   * "START_DKG <n> <t>\n"  — run DKG part 1 and send ROUND1_PKG.
   */
  case FROST_MSG_START_DKG: {
    char buf[32] = {0};
    memcpy(buf, payload, plen < 31 ? plen : 31);
    uint16_t pn = 0, pt = 0;
    if (sscanf(buf, "START_DKG %hu %hu", &pn, &pt) != 2) {
      fprintf(stderr, "signer: malformed START_DKG\n");
      return;
    }
    g_n = pn;
    g_t = pt;
    g_state = DKG_COLLECTING_R1;
    printf("signer %u: START_DKG n=%u t=%u — running part1\n", g_my_id, g_n,
           g_t);

    uint8_t r1_pkg[FROST_MAX_PAYLOAD];
    uint16_t r1_len = 0;
    if (frost_dkg_part1(g_my_id, g_n, g_t, g_r1_secret, &g_r1_secret_len,
                        r1_pkg, &r1_len) != 0) {
      fprintf(stderr, "signer %u: dkg_part1 failed\n", g_my_id);
      return;
    }
    queue_to_coord(FROST_MSG_ROUND1_PKG, r1_pkg, r1_len);
    printf("signer %u: sent ROUND1_PKG (%u bytes)\n", g_my_id, r1_len);
    break;
  }

  /* ── RELAY_R1 ─────────────────────────────────────────────────
   * [uint16 sender_id][r1_pkg bytes]
   * Accumulate peer r1 packages.  When we have n-1, run part2.
   */
  case FROST_MSG_RELAY_R1: {
    if (plen < 2)
      return;
    uint16_t sender_id = (uint16_t)(((uint16_t)payload[0] << 8) | payload[1]);
    uint16_t pkg_len = (uint16_t)(plen - 2);
    if (g_peer_r1_count >= FROST_MAX_SIGNERS)
      return;
    int idx = g_peer_r1_count++;
    g_peer_r1_ids[idx] = sender_id;
    g_peer_r1_len[idx] = pkg_len;
    memcpy(g_peer_r1[idx], payload + 2, pkg_len);
    printf("signer %u: r1 from %u (%u bytes) [%d/%u]\n", g_my_id, sender_id,
           pkg_len, g_peer_r1_count, (unsigned)(g_n - 1));

    if (g_peer_r1_count < (int)(g_n - 1))
      return;

    /* Run DKG part 2 */
    g_state = DKG_COLLECTING_R2;
    printf("signer %u: all r1 received — running part2\n", g_my_id);

    static uint8_t r2_out[FROST_MAX_SIGNERS][FROST_MAX_PAYLOAD];
    static uint16_t r2_lens[FROST_MAX_SIGNERS];
    static uint16_t r2_ids[FROST_MAX_SIGNERS];

    if (frost_dkg_part2(g_my_id, g_r1_secret, g_r1_secret_len,
                        (const uint8_t (*)[FROST_MAX_PAYLOAD])g_peer_r1,
                        g_peer_r1_len, g_peer_r1_ids, g_peer_r1_count,
                        g_r2_secret, &g_r2_secret_len, r2_out, r2_lens,
                        r2_ids) != 0) {
      fprintf(stderr, "signer %u: dkg_part2 failed\n", g_my_id);
      return;
    }

    /* Send each peer its unicast round-2 package:
     * payload = [src_id_hi][src_id_lo][dst_id_hi][dst_id_lo][pkg bytes] */
    for (int i = 0; i < g_peer_r1_count; i++) {

      gnutls_pubkey_t pub = get_signer_pubkey(r2_ids[i]);
      if (!pub) {
        fprintf(stderr, "signer %u: no pubkey for signer %u, skipping\n",
                g_my_id, r2_ids[i]);
        continue;
      }

      /* Encrypt just the payload (r2_out[i], r2_lens[i] bytes -- always 37) */
      gnutls_datum_t plaintext = {.data = r2_out[i], .size = r2_lens[i]};
      gnutls_datum_t ciphertext;

      int rc = gnutls_pubkey_encrypt_data(pub, 0, &plaintext, &ciphertext);
      if (rc < 0) {
        fprintf(stderr, "signer %u: RSA encrypt to %u failed: %s\n", g_my_id,
                r2_ids[i], gnutls_strerror(rc));
        continue;
      }

      /* ciphertext.size will be exactly the RSA modulus size (256 bytes
       * for a 2048-bit key), regardless of the 37-byte input */

      if (ciphertext.size > 256) {
        fprintf(stderr, "signer %u: ciphertext too large (%u bytes)\n", g_my_id,
                ciphertext.size);
        gnutls_free(ciphertext.data);
        continue;
      }

      uint8_t frame[FROST_MAX_PAYLOAD + 4];
      frame[0] = (uint8_t)(g_my_id >> 8);
      frame[1] = (uint8_t)(g_my_id & 0xFF);
      frame[2] = (uint8_t)(r2_ids[i] >> 8);
      frame[3] = (uint8_t)(r2_ids[i] & 0xFF);
      // memcpy(frame + 4, r2_out[i], r2_lens[i]);
      memcpy(frame + 4, ciphertext.data, ciphertext.size);
      // queue_to_coord(FROST_MSG_ROUND2_PKG, frame, (uint16_t)(r2_lens[i] +
      // 4));
      queue_to_coord(FROST_MSG_ROUND2_PKG, frame,
                     (uint16_t)(4 + ciphertext.size));

      gnutls_free(ciphertext.data);
      // printf("r2_lens[%d] = %u\n", i, r2_lens[i]);
      printf("signer %u: plaintext to be encrypted (%u bytes)\n", g_my_id,
             plaintext.size);
      print_bytes_as_hex(plaintext.data, plaintext.size);
      printf("ciphertext.size = %u\n", ciphertext.size);
      print_bytes_as_hex(frame, 254 + 4);
      printf("signer %u: sent ROUND2_PKG → %u\n", g_my_id, r2_ids[i]);
    }
    break;
  }

  /* ── RELAY_R2 ─────────────────────────────────────────────────
   * [src_id_hi][src_id_lo][dst_id_hi][dst_id_lo][pkg bytes]
   * Accumulate peer r2 packages.  When we have n-1, run part3.
   */
  case FROST_MSG_RELAY_R2: {
    if (plen < 4)
      return;
    uint16_t sender_id = (uint16_t)(((uint16_t)payload[0] << 8) | payload[1]);
    uint16_t pkg_len = (uint16_t)(plen - 4);
    if (g_peer_r2_count >= FROST_MAX_SIGNERS)
      return;
    int idx = g_peer_r2_count++;

    gnutls_datum_t ciphertext = {.data = (unsigned char *)(payload + 4),
                                 .size = pkg_len};
    gnutls_datum_t plaintext;

    check_in(CP_R2_DECRYPT);
    int rc = gnutls_privkey_decrypt_data(my_priv, 0, &ciphertext, &plaintext);
    check_out(CP_R2_DECRYPT);
    if (rc < 0) {
      fprintf(stderr, "signer %u: decrypt failed: %s\n", g_my_id,
              gnutls_strerror(rc));
      // gnutls_privkey_deinit(my_priv);
      return;
    }
    // gnutls_privkey_deinit(my_priv);

    /* plaintext.data / plaintext.size is your original 37-byte payload */
    memcpy(g_peer_r2[idx], plaintext.data,
           plaintext.size); /* or wherever it needs to go */

    printf("signer %u: decryption found (%u bytes)\n", g_my_id, plaintext.size);
    print_bytes_as_hex(plaintext.data, plaintext.size);

    gnutls_free(plaintext.data);

    g_peer_r2_ids[idx] = sender_id;
    g_peer_r2_len[idx] = plaintext.size; // pkg_len;
    // memcpy(g_peer_r2[idx], payload + 4, pkg_len);
    printf("signer %u: r2 from %u (%u bytes) [%d/%u]\n", g_my_id, sender_id,
           pkg_len, g_peer_r2_count, (unsigned)(g_n - 1));

    if (g_peer_r2_count < (int)(g_n - 1))
      return;

    /* Run DKG part 3 */
    printf("signer %u: all r2 received — running part3\n", g_my_id);

    if (frost_dkg_part3(g_my_id, g_r2_secret, g_r2_secret_len,
                        (const uint8_t (*)[FROST_MAX_PAYLOAD])g_peer_r1,
                        g_peer_r1_len, g_peer_r1_ids, g_peer_r1_count,
                        (const uint8_t (*)[FROST_MAX_PAYLOAD])g_peer_r2,
                        g_peer_r2_len, g_peer_r2_ids, g_peer_r2_count,
                        g_key_pkg, &g_key_pkg_len, g_pub_key_pkg,
                        &g_pub_key_pkg_len) != 0) {
      fprintf(stderr, "signer %u: dkg_part3 failed\n", g_my_id);
      return;
    }
    g_state = DKG_COMPLETE;
    printf("signer %u: DKG complete (key_pkg=%u bytes)\n", g_my_id,
           g_key_pkg_len);

    /* Notify coordinator */
    uint8_t notice[2] = {(uint8_t)(g_my_id >> 8), (uint8_t)(g_my_id & 0xFF)};
    queue_to_coord(FROST_MSG_R2_COMPLETE, notice, 2);

    /* Persist key material so SIGN mode can reload without re-running DKG */
    save_key_material();

    /* Write the CA public key in OpenSSH format for human inspection.
     * Every signer produces the same aggregate public key, so all
     * frost_ca_signer_*.pub files are identical.                       */
    if (0) {
      char pub_hex[FROST_MAX_PAYLOAD * 2 + 4];
      bytes_to_hex(g_pub_key_pkg, g_pub_key_pkg_len, pub_hex);
      char cmd[FROST_MAX_PAYLOAD * 3];
      snprintf(cmd, sizeof(cmd),
               "echo '%s' | " FROST_CORE_BIN " pubkey > frost_ca_signer_%u.pub",
               pub_hex, g_my_id);
      if (system(cmd) == 0)
        printf("signer %u: wrote frost_ca_signer_%u.pub\n", g_my_id, g_my_id);
    }

    /* Send PublicKeyPackage to coordinator (coordinator stores it as
     * pub_key_pkg.hex, which sign mode loads on startup).            */
    queue_to_coord(FROST_MSG_PUB_KEY_PKG, g_pub_key_pkg, g_pub_key_pkg_len);
    printf("signer %u: sent PUB_KEY_PKG (%u bytes)\n", g_my_id,
           g_pub_key_pkg_len);
    break;
  }

  /* ── DKG_DONE ─────────────────────────────────────────────────
   * Coordinator confirms all signers completed DKG.
   */
  case FROST_MSG_DKG_DONE: {
    char buf[32] = {0};
    memcpy(buf, payload, plen < 31 ? plen : 31);
    uint16_t confirmed = 0;
    sscanf(buf, "DKG_DONE %hu", &confirmed);
    printf("signer %u: DKG_DONE — %u/%u signers confirmed\n", g_my_id,
           confirmed, g_n);
    printf("signer %u: key share is persisted at " FROST_SHARES_DIR
           "/signer_%u.keypkg\n",
           g_my_id, g_my_id);
    printf("signer %u: start coordinator in sign mode to issue certificates\n",
           g_my_id);
    break;
  }

    /* ── START_REFRESH ───────────────────────────────────────────── */
  case FROST_MSG_START_REFRESH: {
    char buf[32] = {0};
    memcpy(buf, payload, plen < 31 ? plen : 31);
    uint16_t pn = 0, pt = 0;
    if (sscanf(buf, "START_REFRESH %hu %hu", &pn, &pt) != 2) {
      fprintf(stderr, "signer: malformed START_REFRESH\n");
      return;
    }
    g_n = pn;
    g_t = pt;
    printf("signer %u: START_REFRESH n=%u t=%u — running refresh_part1\n",
           g_my_id, g_n, g_t);

    if (frost_refresh_part1(g_my_id, g_n, g_t, g_ref_r1_secret,
                            &g_ref_r1_secret_len, g_ref_r1_pkg,
                            &g_ref_r1_pkg_len) != 0) {
      fprintf(stderr, "signer %u: refresh_part1 failed\n", g_my_id);
      return;
    }
    queue_to_coord(FROST_MSG_REFRESH_R1, g_ref_r1_pkg, g_ref_r1_pkg_len);
    printf("signer %u: sent REFRESH_R1 (%u bytes)\n", g_my_id,
           g_ref_r1_pkg_len);
    break;
  }

  /* ── RELAY_REFRESH_R1 ─────────────────────────────────────────
   * Accumulate peer r1 packages.  When we have n-1, run part2.  */
  case FROST_MSG_RELAY_REFRESH_R1: {
    if (plen < 2)
      return;
    uint16_t sender_id = (uint16_t)(((uint16_t)payload[0] << 8) | payload[1]);
    uint16_t pkg_len = (uint16_t)(plen - 2);
    if (g_ref_peer_r1_count >= FROST_MAX_SIGNERS)
      return;
    int idx = g_ref_peer_r1_count++;
    g_ref_peer_r1_ids[idx] = sender_id;
    g_ref_peer_r1_len[idx] = pkg_len;
    memcpy(g_ref_peer_r1[idx], payload + 2, pkg_len);
    printf("signer %u: [REFRESH] r1 from %u [%d/%u]\n", g_my_id, sender_id,
           g_ref_peer_r1_count, (unsigned)(g_n - 1));

    if (g_ref_peer_r1_count < (int)(g_n - 1))
      return;
    printf("signer %u: [REFRESH] all r1 — running refresh_part2\n", g_my_id);

    static uint8_t r2_out[FROST_MAX_SIGNERS][FROST_MAX_PAYLOAD];
    static uint16_t r2_lens[FROST_MAX_SIGNERS];
    static uint16_t r2_ids[FROST_MAX_SIGNERS];

    if (frost_refresh_part2(g_my_id, g_ref_r1_secret, g_ref_r1_secret_len,
                            (const uint8_t (*)[FROST_MAX_PAYLOAD])g_ref_peer_r1,
                            g_ref_peer_r1_len, g_ref_peer_r1_ids,
                            g_ref_peer_r1_count, g_ref_r2_secret,
                            &g_ref_r2_secret_len, r2_out, r2_lens,
                            r2_ids) != 0) {
      fprintf(stderr, "signer %u: refresh_part2 failed\n", g_my_id);
      return;
    }

    /* Send each unicast r2 package:
     * [src_hi][src_lo][dst_hi][dst_lo][pkg bytes] */
    for (int i = 0; i < g_ref_peer_r1_count; i++) {

      gnutls_pubkey_t pub = get_signer_pubkey(r2_ids[i]);
      if (!pub) {
        fprintf(stderr, "signer %u: no pubkey for signer %u, skipping\n",
                g_my_id, r2_ids[i]);
        continue;
      }

      gnutls_datum_t plaintext = {.data = r2_out[i], .size = r2_lens[i]};
      gnutls_datum_t ciphertext;

      int rc = gnutls_pubkey_encrypt_data(pub, 0, &plaintext, &ciphertext);
      if (rc < 0) {
        fprintf(stderr, "signer %u: RSA encrypt to %u failed: %s\n", g_my_id,
                r2_ids[i], gnutls_strerror(rc));
        continue;
      }
      /* ciphertext.size will be exactly the RSA modulus size (256 bytes
       * for a 2048-bit key), regardless of the 37-byte input */

      if (ciphertext.size > 256) {
        fprintf(stderr, "signer %u: ciphertext too large (%u bytes)\n", g_my_id,
                ciphertext.size);
        gnutls_free(ciphertext.data);
        continue;
      }

      uint8_t frame[FROST_MAX_PAYLOAD + 4];
      frame[0] = (uint8_t)(g_my_id >> 8);
      frame[1] = (uint8_t)(g_my_id & 0xFF);
      frame[2] = (uint8_t)(r2_ids[i] >> 8);
      frame[3] = (uint8_t)(r2_ids[i] & 0xFF);
      // memcpy(frame + 4, r2_out[i], r2_lens[i]);
      memcpy(frame + 4, ciphertext.data, ciphertext.size);
      // queue_to_coord(FROST_MSG_REFRESH_R2, frame, (uint16_t)(r2_lens[i] +
      // 4));
      queue_to_coord(FROST_MSG_REFRESH_R2, frame,
                     (uint16_t)(ciphertext.size + 4));
      gnutls_free(ciphertext.data);
      printf("signer %u: plaintext to be encrypted (%u bytes)\n", g_my_id,
             plaintext.size);
      print_bytes_as_hex(plaintext.data, plaintext.size);
      printf("ciphertext.size = %u\n", ciphertext.size);
      print_bytes_as_hex(frame, 254 + 4);

      // printf("r2_ids[%d] = %u\n", i, r2_lens[i]);
      printf("signer %u: [REFRESH] sent R2 → %u\n", g_my_id, r2_ids[i]);
    }
    uint8_t notice[2] = {(uint8_t)(g_my_id >> 8), (uint8_t)(g_my_id & 0xFF)};
    queue_to_coord(FROST_MSG_REFRESH_R2_COMPLETE, notice, 2);
    break;
  }

  /* ── RELAY_REFRESH_R2 ─────────────────────────────────────────
   * Accumulate unicast r2 packages addressed to us.             */
  case FROST_MSG_RELAY_REFRESH_R2: {
    if (plen < 4)
      return;
    uint16_t sender_id = (uint16_t)(((uint16_t)payload[0] << 8) | payload[1]);
    uint16_t pkg_len = (uint16_t)(plen - 4);
    if (g_ref_peer_r2_count >= FROST_MAX_SIGNERS)
      return;
    int idx = g_ref_peer_r2_count++;

    gnutls_datum_t ciphertext = {.data = (unsigned char *)(payload + 4),
                                 .size = pkg_len};
    gnutls_datum_t plaintext;

    check_in(CP_R2_DECRYPT);
    int rc = gnutls_privkey_decrypt_data(my_priv, 0, &ciphertext, &plaintext);
    check_out(CP_R2_DECRYPT);
    if (rc < 0) {
      fprintf(stderr, "signer %u: decrypt failed: %s\n", g_my_id,
              gnutls_strerror(rc));
      // gnutls_privkey_deinit(my_priv);
      return;
    }
    // gnutls_privkey_deinit(my_priv);

    /* plaintext.data / plaintext.size is your original 37-byte payload */
    memcpy(g_ref_peer_r2[idx], plaintext.data,
           plaintext.size); /* or wherever it needs to go */

    printf("signer %u: decryption found (%u bytes)\n", g_my_id, plaintext.size);
    print_bytes_as_hex(plaintext.data, plaintext.size);

    gnutls_free(plaintext.data);

    g_ref_peer_r2_ids[idx] = sender_id;
    g_ref_peer_r2_len[idx] = plaintext.size;
    // memcpy(g_ref_peer_r2[idx], payload + 4, pkg_len);
    printf("signer %u: [REFRESH] r2 from %u [%d/%u]\n", g_my_id, sender_id,
           g_ref_peer_r2_count, (unsigned)(g_n - 1));

    print_bytes_as_hex(g_ref_peer_r2[idx], g_ref_peer_r2_len[idx]);

    break;
  }

  /* ── REFRESH_FINALIZE ─────────────────────────────────────────
   * All r2 packages have been routed.  Compute the refreshed key
   * package, verify the group key is unchanged, overwrite disk.  */
  case FROST_MSG_REFRESH_FINALIZE: {
    printf("signer %u: [REFRESH] FINALIZE — computing new shares\n", g_my_id);

    if (g_ref_peer_r2_count != (int)(g_n - 1)) {
      fprintf(stderr, "signer %u: [REFRESH] expected %u r2 pkgs, have %d\n",
              g_my_id, g_n - 1, g_ref_peer_r2_count);
      return;
    }

    uint8_t new_key_pkg[FROST_MAX_PAYLOAD];
    uint16_t new_key_pkg_len = 0;
    uint8_t new_pub_key_pkg[FROST_MAX_PAYLOAD];
    uint16_t new_pub_key_pkg_len = 0;

    if (frost_refresh_shares(
            g_my_id, g_n, g_ref_r2_secret, g_ref_r2_secret_len,
            (const uint8_t (*)[FROST_MAX_PAYLOAD])g_ref_peer_r1,
            g_ref_peer_r1_len, g_ref_peer_r1_ids, g_ref_peer_r1_count,
            (const uint8_t (*)[FROST_MAX_PAYLOAD])g_ref_peer_r2,
            g_ref_peer_r2_len, g_ref_peer_r2_ids, g_ref_peer_r2_count,
            g_key_pkg, g_key_pkg_len, g_pub_key_pkg, g_pub_key_pkg_len,
            new_key_pkg, &new_key_pkg_len, new_pub_key_pkg,
            &new_pub_key_pkg_len) != 0) {
      fprintf(stderr, "signer %u: [REFRESH] refresh_shares failed\n", g_my_id);
      return;
    }

    /* Overwrite persisted key material with new shares */
    memcpy(g_key_pkg, new_key_pkg, new_key_pkg_len);
    g_key_pkg_len = new_key_pkg_len;
    memcpy(g_pub_key_pkg, new_pub_key_pkg, new_pub_key_pkg_len);
    g_pub_key_pkg_len = new_pub_key_pkg_len;

    if (save_key_material() != 0) {
      fprintf(stderr, "signer %u: [REFRESH] failed to save new key material\n",
              g_my_id);
      return;
    }
    printf("signer %u: [REFRESH] *** new shares saved — old shares OVERWRITTEN "
           "***\n",
           g_my_id);

    /* Notify coordinator, including new pub_key_pkg for it to save */
    queue_to_coord(FROST_MSG_REFRESH_COMPLETE, new_pub_key_pkg,
                   new_pub_key_pkg_len);
    break;
  }

  /* ── REFRESH_CONFIRMED ────────────────────────────────────────
   * Coordinator confirms all signers saved new shares.           */
  case FROST_MSG_REFRESH_CONFIRMED:
    printf("signer %u: [REFRESH] coordinator confirmed — refresh complete\n",
           g_my_id);
    printf("signer %u: [REFRESH] CA public key is UNCHANGED; shares are new\n",
           g_my_id);
    break;

  /* ── SIGN_REQ ─────────────────────────────────────────────────
   * Payload: raw TBS bytes (informational; not used by commit call).
   * Respond with a fresh nonce commitment, or SHARE_LOAD_FAIL if we
   * have no key material.  This message may be received multiple times
   * across ROAST retry rounds.
   */
  case FROST_MSG_SIGN_REQ: {

    // FAULTS FOR TESTING
    if (g_fault == FAULT_DROPOUT) {
      printf("signer %u: [FAULT] dropout — closing connection\n", g_my_id);
      close(g_coord_sock);
      exit(0);
    }
    if (g_fault == FAULT_NO_COMMIT) {
      printf("signer %u: [FAULT] no-commit — ignoring SIGN_REQ\n", g_my_id);
      return;
    }

    if (g_key_pkg_len == 0) {
      /* Key not in memory — try loading again (covers ROAST retry case) */
      if (load_key_material() != 0) {
        fprintf(stderr, "signer %u: SIGN_REQ but no key — sending FAIL\n",
                g_my_id);
        queue_to_coord(FROST_MSG_SHARE_LOAD_FAIL, NULL, 0);
        return;
      }
    }

    printf("signer %u: SIGN_REQ (%u TBS bytes) — generating commit\n", g_my_id,
           plen);

    g_state = DKG_SIGNING;

    if (!g_commit_is_precomputed) {
      /* Reset nonces from any previous signing round to avoid reuse */
      memset(g_nonces, 0, sizeof(g_nonces));
      g_nonces_len = 0;

      if (frost_commit(g_my_id, g_key_pkg, g_key_pkg_len, g_nonces,
                       &g_nonces_len, g_commit, &g_commit_len) != 0) {
        fprintf(stderr, "signer %u: frost_commit failed\n", g_my_id);
        return;
      }
    }
    queue_to_coord(FROST_MSG_COMMIT, g_commit, g_commit_len);
    g_commit_is_precomputed = 0;
    printf("signer %u: sent COMMIT (%u bytes)\n", g_my_id, g_commit_len);
    break;
  }

  /* ── RELAY_COMMIT ─────────────────────────────────────────────
   * The signing package for our ROAST session.
   * Produce a signature share and send it back.
   */
  case FROST_MSG_RELAY_COMMIT: {

    // FAULT TESTING
    if (g_fault == FAULT_SILENT) {
      printf("signer %u: [FAULT] silent — ignoring signing package\n", g_my_id);
      return;
    }

    if (g_key_pkg_len == 0) {
      fprintf(stderr, "signer %u: RELAY_COMMIT but no key material\n", g_my_id);
      return;
    }
    printf("signer %u: signing package (%u bytes) — producing share\n", g_my_id,
           plen);

    uint8_t sig_share[FROST_MAX_PAYLOAD];
    uint16_t sig_share_len = 0;
    if (frost_sign(g_my_id, payload, plen, g_nonces, g_nonces_len, g_key_pkg,
                   g_key_pkg_len, sig_share, &sig_share_len) != 0) {
      fprintf(stderr, "signer %u: frost_sign failed\n", g_my_id);
      return;
    }

    // FAULT TESTING -- CORRUPT SHARE
    if (g_fault == FAULT_BAD_SHARE) {
      printf("signer %u: [FAULT] bad-share — corrupting signature share\n",
             g_my_id);
      /* flip random bytes in the middle of the share */
      if (sig_share_len >= 8) {
        sig_share[sig_share_len / 2] ^= 0xFF;
        sig_share[sig_share_len / 2 + 1] ^= 0xFF;
      }
    }

    queue_to_coord(FROST_MSG_SIG_SHARE, sig_share, sig_share_len);
    printf("signer %u: sent SIG_SHARE (%u bytes)\n", g_my_id, sig_share_len);

    /* Zero nonces immediately after use — they must never be reused */
    memset(g_nonces, 0, sizeof(g_nonces));
    g_nonces_len = 0;
    g_state = DKG_COMPLETE; /* ready for next signing round if needed */
    break;
  }

  /* ── CERT_OUTPUT ──────────────────────────────────────────────
   * Coordinator sends the output file path once signing succeeds.
   */
  case FROST_MSG_CERT_OUTPUT: {
    // char path[256] = {0};
    // memcpy(path, payload, plen < 255 ? plen : 255);
    // printf("signer %u: *** certificate issued → %s ***\n", g_my_id, path);
    // printf("signer %u:     inspect: ssh-keygen -L -f %s\n", g_my_id, path);
    break;
  }

  /* ── FINAL_SIG (backward compat) ──────────────────────────── */
  case FROST_MSG_FINAL_SIG: {
    char sig_hex[FROST_MAX_PAYLOAD * 2 + 4];
    bytes_to_hex(payload, plen < 64 ? plen : 64, sig_hex);
    FILE *fp = fopen("signature_pkg.hex", "w");
    if (fp) {
      fprintf(fp, "%s\n", sig_hex);
      fclose(fp);
    }
    printf("signer %u: aggregate signature saved to signature_pkg.hex\n",
           g_my_id);
    break;
  }

  case FROST_MSG_ERROR: {
    char errbuf[256] = {0};
    memcpy(errbuf, payload, plen < 255 ? plen : 255);
    fprintf(stderr, "signer %u: coordinator error: %s\n", g_my_id, errbuf);
    if (!g_id_confirmed) {
      /* Most likely our asserted ID was rejected (already taken by
       * another connected signer) or the HELLO itself was malformed.
       * There's no valid session to continue in either case.        */
      fprintf(stderr, "signer: coordinator rejected registration — exiting\n");
      exit(EXIT_FAILURE);
    }
    break;
  }

  default:
    fprintf(stderr, "signer %u: unknown msg 0x%02x\n", g_my_id, (unsigned)type);
    break;
  }
}

/* ══════════════════════════════════════════════════════════════════
 * main()
 * ══════════════════════════════════════════════════════════════════ */

int main(int argc, char **argv) {
  if (argc < 4) {
    fprintf(stderr,
            "Usage: %s <id> <n> <t> "
            "[--fault <type>]\n",
            argv[0]);
    return EXIT_FAILURE;
  }
  // const char *certfile = argv[1], *keyfile = argv[2];
  if (sscanf(argv[1], "%hu", &g_my_id) != 1 || g_my_id < 1 ||
      g_my_id > FROST_MAX_SIGNERS) {
    fprintf(stderr, "signer: invalid id '%s' (must be 1..%d)\n", argv[3],
            FROST_MAX_SIGNERS);
    return EXIT_FAILURE;
  }
  if (sscanf(argv[2], "%hu", &g_n) != 1 || g_n < 2 || g_n > FROST_MAX_SIGNERS) {
    fprintf(stderr, "signer: invalid n '%s'\n", argv[4]);
    return EXIT_FAILURE;
  }
  if (sscanf(argv[3], "%hu", &g_t) != 1 || g_t < 1 || g_t > g_n) {
    fprintf(stderr, "signer: invalid t '%s'\n", argv[5]);
    return EXIT_FAILURE;
  }
  if (g_my_id > g_n) {
    fprintf(stderr, "signer: id %u is out of range for n=%u\n", g_my_id, g_n);
    return EXIT_FAILURE;
  }

  /* The DKG round-2 relay looks up every signer's public key by
   * certs/signer<id>.crt (see get_signer_pubkey() in frost_stubs.c),
   * and this process's own private key comes from whatever <key_file>
   * was passed on the command line. Those two MUST correspond to the
   * same keypair, or every RSA decryption of a routed round-2 package
   * addressed to us will fail. Verify the identity files for the ID
   * we're about to assert actually exist before we ever connect —
   * this doesn't prove cert_file/key_file *are* those exact files, but
   * it does catch the common misconfiguration (e.g. wrong --id, or
   * certs/ never populated for this signer) up front instead of
   * failing deep inside DKG round 2.                                */
  char expected_cert[64], expected_key[64];
  snprintf(expected_cert, sizeof(expected_cert), "certs/signer%u.crt", g_my_id);
  snprintf(expected_key, sizeof(expected_key), "certs/signer%ukey.pem",
           g_my_id);

  {

    struct stat st;
    if (stat(expected_cert, &st) != 0) {
      fprintf(stderr,
              "signer: id %u asserted, but '%s' does not exist — refusing "
              "to start (peers would encrypt to this signer using that "
              "file)\n",
              g_my_id, expected_cert);
      return EXIT_FAILURE;
    }
    if (stat(expected_key, &st) != 0) {
      fprintf(stderr,
              "signer: id %u asserted, but '%s' does not exist — refusing "
              "to start (this signer's own decryption key must live "
              "there)\n",
              g_my_id, expected_key);
      return EXIT_FAILURE;
    }
  }

  /* optional fault injection */
  for (int i = 4; i < argc; i++) {
    if (!strcmp(argv[i], "--fault") && i + 1 < argc) {
      i++;
      if (!strcmp(argv[i], "bad-share"))
        g_fault = FAULT_BAD_SHARE;
      else if (!strcmp(argv[i], "silent"))
        g_fault = FAULT_SILENT;
      else if (!strcmp(argv[i], "no-commit"))
        g_fault = FAULT_NO_COMMIT;
      else if (!strcmp(argv[i], "dropout"))
        g_fault = FAULT_DROPOUT;
      else {
        fprintf(stderr, "unknown fault mode '%s'\n", argv[i]);
        fprintf(stderr, "Try bad-share, silent, no-commit, dropout\n");
        return EXIT_FAILURE;
      }
      printf("signer: *** FAULT INJECTION MODE: %s ***\n", argv[i]);
    }
  }

  gnutls_global_init();

  char log_file[32] = {'\0'};
  snprintf(log_file, 32, "log/signer%u.log", g_my_id);
  checkpoint_init(log_file);

  if (init_signer_pubkey_cache() != 0) {
    fprintf(stderr,
            "signer: one or more signer certs failed to load — aborting\n");
    return EXIT_FAILURE;
  }

  /* The stat() checks above only prove *some* files exist at the
   * expected paths. This proves the cert we were actually launched
   * with is the same keypair peers will use to encrypt to us — i.e.
   * that <cert_file> really is (a copy of) certs/signer<id>.crt, not
   * just a file that happens to sit at that path. Without this, a
   * signer could assert an ID it doesn't hold the matching private
   * key for and still pass the earlier existence check.              */
  if (verify_own_identity(g_my_id, expected_cert) != 0) {
    return EXIT_FAILURE;
  }
  printf("signer: identity verified — '%s' matches certs/signer%u.crt\n",
         expected_cert, g_my_id);

  /* GnuTLS setup */
  gnutls_certificate_credentials_t x509_cred;
  // gnutls_global_init();
  gnutls_certificate_allocate_credentials(&x509_cred);
  gnutls_certificate_set_x509_trust_file(x509_cred, FROST_CAFILE,
                                         GNUTLS_X509_FMT_PEM);
  if (gnutls_certificate_set_x509_key_file(
          x509_cred, expected_cert, expected_key, GNUTLS_X509_FMT_PEM) < 0) {
    fprintf(stderr, "signer: failed to load '%s' / '%s'\n", expected_cert,
            expected_key);
    return EXIT_FAILURE;
  }

  /* Extract tls private key for routed payload decryption */
  gnutls_privkey_init(&my_priv);

  gnutls_datum_t key_data;
  gnutls_load_file(expected_key,
                   &key_data); /* e.g. certs/signer{g_my_id}key.pem */
  gnutls_privkey_import_x509_raw(my_priv, &key_data, GNUTLS_X509_FMT_PEM, NULL,
                                 0);
  gnutls_free(key_data.data);

  g_coord_sock = connect_to_coordinator(x509_cred);
  if (g_coord_sock < 0)
    return EXIT_FAILURE;

  g_inptr = g_inbuf;
  TAILQ_INIT(&g_outq);

  /* Send HELLO */
  char hello[32];
  int hlen =
      snprintf(hello, sizeof(hello), "SIGNER %u %u %u\n", g_my_id, g_n, g_t);
  queue_to_coord(FROST_MSG_HELLO, (uint8_t *)hello, (uint16_t)hlen);
  printf("signer: sent HELLO id=%u n=%u t=%u — awaiting coordinator "
         "confirmation\n",
         g_my_id, g_n, g_t);

  /* Event loop */
  for (;;) {
    fd_set readset, writeset;
    FD_ZERO(&readset);
    FD_ZERO(&writeset);
    if (g_want_write || !TAILQ_EMPTY(&g_outq))
      FD_SET(g_coord_sock, &writeset);
    else
      FD_SET(g_coord_sock, &readset);

    struct timeval tv = {.tv_sec = 0, .tv_usec = 500000};
    check_in(CP_SELECT_BLKING_SIGNR);
    int sel = select(g_coord_sock + 1, &readset, &writeset, NULL, &tv);
    check_out(CP_SELECT_BLKING_SIGNR);
    if (sel < 0) {
      if (errno == EINTR)
        continue;
      perror("select");
      break;
    }
    if (sel == 0)
      continue;

    if (FD_ISSET(g_coord_sock, &writeset)) {
      if (drain_outq() < 0)
        break;
      continue;
    }
    if (!FD_ISSET(g_coord_sock, &readset))
      continue;

    check_in(CP_TLS_RECORD_RECV);
    int r = gnutls_record_recv(g_coord_sess, g_inptr,
                               (g_inbuf + FROST_FRAME_MAX) - g_inptr);
    check_out(CP_TLS_RECORD_RECV);
    if (r == GNUTLS_E_AGAIN || r == GNUTLS_E_INTERRUPTED) {
      g_want_write = gnutls_record_get_direction(g_coord_sess);
      continue;
    }
    if (r == 0) {
      printf("signer %u: coordinator closed connection\n", g_my_id);
      if (!g_id_confirmed) {
        fprintf(stderr,
                "signer: connection closed before ID %u was confirmed — "
                "exiting\n",
                g_my_id);
        gnutls_deinit(g_coord_sess);
        close(g_coord_sock);
        gnutls_global_deinit();
        return EXIT_FAILURE;
      }
      break;
    }
    if (r < 0) {
      fprintf(stderr, "signer: recv: %s\n", gnutls_strerror(r));
      break;
    }
    g_want_write = 0;
    g_inptr += r;

    /* Process exactly one complete frame per iteration */
    if ((g_inptr - g_inbuf) < FROST_FRAME_HDR)
      continue;
    frost_msg_t msg_type;
    uint16_t plen = frost_decode_header(g_inbuf, &msg_type);
    if ((g_inptr - g_inbuf) < (int)(FROST_FRAME_HDR + plen))
      continue;
    g_inptr = g_inbuf;
    process_coord_frame(msg_type, g_inbuf + FROST_FRAME_HDR, plen);

    /* Pre-compute commitment */
    if (g_coord_mode == COORD_MODE_SIGN) {
      if (g_state == DKG_IDLE || g_state == DKG_COMPLETE) {
        if (!g_commit_is_precomputed) {
          memset(g_nonces, 0, sizeof(g_nonces));
          g_nonces_len = 0;

          if (frost_commit(g_my_id, g_key_pkg, g_key_pkg_len, g_nonces,
                           &g_nonces_len, g_commit, &g_commit_len) != 0) {
            fprintf(stderr, "signer %u: frost_commit failed\n", g_my_id);
          } else {
            g_commit_is_precomputed = 1;
          }
        }
      }
    }
  }

  gnutls_bye(g_coord_sess, GNUTLS_SHUT_RDWR);
  gnutls_deinit(g_coord_sess);
  close(g_coord_sock);
  gnutls_global_deinit();
  return EXIT_SUCCESS;
}
