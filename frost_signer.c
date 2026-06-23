/* frost_signer.c — FROST signer node.
 *
 * Mirrors chatServer5.c in structure:
 *   - single-process, select()-based event loop
 *   - GnuTLS client to coordinator (one persistent connection)
 *   - BSD sys/queue outbound message queue with partial-write tracking
 *   - LOOP_CHECK / GNUTLS_E_AGAIN pattern throughout
 *
 * This file is the C transport/state-machine layer.  It handles all
 * framing and coordination protocol mechanics.  The actual FROST
 * cryptography (part1/part2/part3, commit, sign, aggregate) is
 * delegated to the Rust frost_signer_core binary via popen().
 *
 * Usage:
 *   ./frost_signer <cert_file> <key_file> <n> <t>
 *
 * Example (signer 1 of a 3-of-5 setup):
 *   ./frost_signer certs/beocat.crt certs/beocatkey.pem 5 3
 *
 * Compile:
 *   gcc -g -std=c99 -Wall -Wextra -o frost_signer frost_signer.c -lgnutls
 */

#define _GNU_SOURCE
#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/queue.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <gnutls/gnutls.h>
#include <gnutls/x509.h>

#include "frost_common.h"
#include "frost_stubs.c"

/* ── Per-connection send queue ────────────────────────────────── */
TAILQ_HEAD(msgqueue, outmsg);

/* ── Signer local state ───────────────────────────────────────── */
static uint16_t g_my_id = 0;
static uint16_t g_n = 0;
static uint16_t g_t = 0;
static dkg_state_t g_state = DKG_IDLE;

/* Opaque blobs produced by the Rust FROST core.
 * In a real integration these come back from popen() calls to
 * the Rust binary.  Here we reserve space and stub the calls. */
static uint8_t g_r1_secret[FROST_MAX_PAYLOAD]; /* round1 SecretPackage */
static uint16_t g_r1_secret_len = 0;
static uint8_t g_r2_secret[FROST_MAX_PAYLOAD]; /* round2 SecretPackage */
static uint16_t g_r2_secret_len = 0;
static uint8_t g_key_pkg[FROST_MAX_PAYLOAD]; /* KeyPackage           */
static uint16_t g_key_pkg_len = 0;
static uint8_t g_pub_key_pkg[FROST_MAX_PAYLOAD]; /* PublicKeyPackage     */
static uint16_t g_pub_key_pkg_len = 0;
static uint8_t g_nonces[FROST_MAX_PAYLOAD]; /* SigningNonces        */
static uint16_t g_nonces_len = 0;

/* Collected r1 packages from peers [indexed 0..n-2 in arrival order] */
static uint8_t g_peer_r1[FROST_MAX_SIGNERS][FROST_MAX_PAYLOAD];
static uint16_t g_peer_r1_len[FROST_MAX_SIGNERS];
static uint16_t g_peer_r1_ids[FROST_MAX_SIGNERS];
static int g_peer_r1_count = 0;

/* Collected r2 packages addressed to us */
static uint8_t g_peer_r2[FROST_MAX_SIGNERS][FROST_MAX_PAYLOAD];
static uint16_t g_peer_r2_len[FROST_MAX_SIGNERS];
static uint16_t g_peer_r2_ids[FROST_MAX_SIGNERS];
static int g_peer_r2_count = 0;

/* ── Coordinator connection state ─────────────────────────────── */
static int g_coord_sock = -1;
static gnutls_session_t g_coord_sess;
static uint8_t g_inbuf[FROST_FRAME_MAX];
static uint8_t *g_inptr;
static struct msgqueue g_outq;
static int g_want_write = 0;

/* ── Forward declarations ─────────────────────────────────────── */
static void queue_to_coord(frost_msg_t type, const uint8_t *payload,
                           uint16_t plen);
static int drain_outq(void);
static void process_coord_frame(frost_msg_t type, const uint8_t *payload,
                                uint16_t plen);
static int connect_to_coordinator(const char *certfile, const char *keyfile,
                                  gnutls_certificate_credentials_t cred);

/* ── FROST core stubs (replace with popen() to Rust binary) ───── */

/*  Call the Rust frost_signer_core binary for DKG part1.
 *  In a real build: popen a command like:
 *    frost_signer_core dkg_part1 --id <id> --n <n> --t <t>
 *  and read back two base64-encoded blobs separated by '\n':
 *    line 1: SecretPackage (keep locally, NEVER send)
 *    line 2: round1::Package (broadcast to coordinator as FROST_MSG_ROUND1_PKG)
 *
 *  Here we fill the buffers with placeholder bytes for compile testing.    */
/*static int frost_dkg_part1(uint16_t id, uint16_t n, uint16_t t,
                           uint8_t *secret_out, uint16_t *secret_len,
                           uint8_t *pkg_out, uint16_t *pkg_len) {
  // TODO: replace with popen() call to Rust binary
  (void)id;
  (void)n;
  (void)t;
  char cmd[256];
  snprintf(cmd, sizeof(cmd), "echo 'STUB_DKG_PART1_SECRET_%u_%u_%u' | base64",
           id, n, t);
  // placeholder: write a fixed stub blob
  *secret_len = (uint16_t)snprintf((char *)secret_out, FROST_MAX_PAYLOAD,
                                   "DKG_R1_SECRET id=%u n=%u t=%u", id, n, t);
  *pkg_len = (uint16_t)snprintf((char *)pkg_out, FROST_MAX_PAYLOAD,
                                "DKG_R1_PKG id=%u n=%u t=%u", id, n, t);
  printf("signer %u: frost_dkg_part1 stub — %u secret bytes, %u pkg bytes\n",
         id, *secret_len, *pkg_len);
  return 0;
}*/

/*static int frost_dkg_part2(uint16_t my_id, const uint8_t *r1_secret,
                           uint16_t r1_secret_len,
                           // array of (sender_id, pkg_bytes, pkg_len)
                           const uint8_t peer_r1[][FROST_MAX_PAYLOAD],
                           const uint16_t peer_r1_lens[],
                           const uint16_t peer_r1_ids[], int n_peers,
                           uint8_t *r2_secret_out, uint16_t *r2_secret_len,
                           // out: array of (target_id, pkg_bytes, pkg_len)
                           uint8_t peer_r2_out[][FROST_MAX_PAYLOAD],
                           uint16_t peer_r2_lens[], uint16_t peer_r2_ids[]) {
  // TODO: replace with popen() call to Rust binary
  (void)r1_secret;
  (void)r1_secret_len;
  *r2_secret_len = (uint16_t)snprintf((char *)r2_secret_out, FROST_MAX_PAYLOAD,
                                      "DKG_R2_SECRET id=%u", my_id);
  for (int i = 0; i < n_peers; i++) {
    (void)peer_r1[i];
    (void)peer_r1_lens[i];
    peer_r2_ids[i] = peer_r1_ids[i];
    peer_r2_lens[i] =
        (uint16_t)snprintf((char *)peer_r2_out[i], FROST_MAX_PAYLOAD,
                           "DKG_R2_PKG from=%u to=%u", my_id, peer_r1_ids[i]);
  }
  printf("signer %u: frost_dkg_part2 stub — %d r2 packages\n", my_id, n_peers);
  return 0;
}*/

/*static int frost_dkg_part3(uint16_t my_id, const uint8_t *r2_secret,
                           uint16_t r2_secret_len,
                           const uint8_t peer_r1[][FROST_MAX_PAYLOAD],
                           const uint16_t peer_r1_lens[], int n_r1,
                           const uint8_t peer_r2[][FROST_MAX_PAYLOAD],
                           const uint16_t peer_r2_lens[], int n_r2,
                           uint8_t *key_pkg_out, uint16_t *key_pkg_len) {
  // TODO: replace with popen() call
  (void)r2_secret;
  (void)r2_secret_len;
  (void)peer_r1;
  (void)peer_r1_lens;
  (void)n_r1;
  (void)peer_r2;
  (void)peer_r2_lens;
  (void)n_r2;
  *key_pkg_len = (uint16_t)snprintf((char *)key_pkg_out, FROST_MAX_PAYLOAD,
                                    "KEY_PKG id=%u", my_id);
  printf("signer %u: frost_dkg_part3 stub — key material ready\n", my_id);
  return 0;
}*/

/*static int frost_commit(uint16_t my_id, const uint8_t *key_pkg,
                        uint16_t key_pkg_len, uint8_t *nonces_out,
                        uint16_t *nonces_len, uint8_t *commit_out,
                        uint16_t *commit_len) {
  // TODO: replace with popen() call
  (void)key_pkg;
  (void)key_pkg_len;
  *nonces_len = (uint16_t)snprintf((char *)nonces_out, FROST_MAX_PAYLOAD,
                                   "NONCES id=%u", my_id);
  *commit_len = (uint16_t)snprintf((char *)commit_out, FROST_MAX_PAYLOAD,
                                   "COMMIT id=%u", my_id);
  printf("signer %u: frost_commit stub\n", my_id);
  return 0;
}*/

/* static int frost_sign(uint16_t my_id, const uint8_t *signing_pkg,
                      uint16_t signing_pkg_len, const uint8_t *nonces,
                      uint16_t nonces_len, const uint8_t *key_pkg,
                      uint16_t key_pkg_len, uint8_t *sig_share_out,
                      uint16_t *sig_share_len) {
  // TODO: replace with popen() call
  (void)signing_pkg;
  (void)signing_pkg_len;
  (void)nonces;
  (void)nonces_len;
  (void)key_pkg;
  (void)key_pkg_len;
  *sig_share_len = (uint16_t)snprintf((char *)sig_share_out, FROST_MAX_PAYLOAD,
                                      "SIG_SHARE id=%u", my_id);
  printf("signer %u: frost_sign stub\n", my_id);
  return 0;
}*/

/* ═══════════════════════════════════════════════════════════════ */
int main(int argc, char **argv) {
  if (argc != 5) {
    fprintf(stderr, "Usage: %s <cert_file> <key_file> <n> <t>\n", argv[0]);
    fprintf(stderr, "  e.g. %s certs/beocat.crt certs/beocatkey.pem 5 3\n",
            argv[0]);
    return EXIT_FAILURE;
  }

  const char *certfile = argv[1];
  const char *keyfile = argv[2];
  if (sscanf(argv[3], "%hu", &g_n) != 1 || g_n < 2 || g_n > FROST_MAX_SIGNERS) {
    fprintf(stderr, "signer: invalid n '%s'\n", argv[3]);
    return EXIT_FAILURE;
  }
  if (sscanf(argv[4], "%hu", &g_t) != 1 || g_t < 1 || g_t > g_n) {
    fprintf(stderr, "signer: invalid t '%s' (must be 1..%u)\n", argv[4], g_n);
    return EXIT_FAILURE;
  }

  /* ── Init GnuTLS ──────────────────────────────────────────── */
  gnutls_certificate_credentials_t x509_cred;
  gnutls_global_init();
  gnutls_certificate_allocate_credentials(&x509_cred);
  gnutls_certificate_set_x509_trust_file(x509_cred, FROST_CAFILE,
                                         GNUTLS_X509_FMT_PEM);
  if (gnutls_certificate_set_x509_key_file(x509_cred, certfile, keyfile,
                                           GNUTLS_X509_FMT_PEM) < 0) {
    fprintf(stderr, "signer: failed to load %s / %s\n", certfile, keyfile);
    return EXIT_FAILURE;
  }

  /* ── Connect to coordinator ───────────────────────────────── */
  g_coord_sock = connect_to_coordinator(certfile, keyfile, x509_cred);
  if (g_coord_sock < 0) {
    fprintf(stderr, "signer: failed to connect to coordinator\n");
    return EXIT_FAILURE;
  }

  g_inptr = g_inbuf;
  TAILQ_INIT(&g_outq);

  /* ── Send HELLO ───────────────────────────────────────────── */
  char hello[64];
  int hellolen = snprintf(hello, sizeof(hello), "SIGNER %u %u\n", g_n, g_t);
  queue_to_coord(FROST_MSG_HELLO, (uint8_t *)hello, (uint16_t)hellolen);
  printf("signer: sent HELLO n=%u t=%u\n", g_n, g_t);

  /* ── Event loop ───────────────────────────────────────────── */
  for (;;) {
    fd_set readset, writeset;
    FD_ZERO(&readset);
    FD_ZERO(&writeset);

    if (g_want_write || !TAILQ_EMPTY(&g_outq))
      FD_SET(g_coord_sock, &writeset);
    else
      FD_SET(g_coord_sock, &readset);

    int max_fd = g_coord_sock;
    struct timeval tv = {.tv_sec = 0, .tv_usec = 500000};
    int sel = select(max_fd + 1, &readset, &writeset, NULL, &tv);
    if (sel < 0) {
      if (errno == EINTR)
        continue;
      perror("signer: select");
      break;
    }
    if (sel == 0)
      continue;

    /* ── Drain outbound queue ─────────────────────────────── */
    if (FD_ISSET(g_coord_sock, &writeset)) {
      if (drain_outq() < 0) {
        fprintf(stderr, "signer: write error, exiting\n");
        break;
      }
      continue;
    }

    /* ── Read from coordinator ────────────────────────────── */
    if (!FD_ISSET(g_coord_sock, &readset))
      continue;

    int ret = gnutls_record_recv(g_coord_sess, g_inptr,
                                 (g_inbuf + FROST_FRAME_MAX) - g_inptr);
    if (ret == GNUTLS_E_AGAIN || ret == GNUTLS_E_INTERRUPTED) {
      g_want_write = gnutls_record_get_direction(g_coord_sess);
      continue;
    }
    if (ret == 0) {
      printf("signer: coordinator closed connection\n");
      break;
    }
    if (ret < 0) {
      fprintf(stderr, "signer: recv error: %s\n", gnutls_strerror(ret));
      break;
    }
    g_want_write = 0;
    g_inptr += ret;

    /* need at least header */
    if ((g_inptr - g_inbuf) < FROST_FRAME_HDR)
      continue;

    frost_msg_t msg_type;
    uint16_t plen = frost_decode_header(g_inbuf, &msg_type);

    /* wait for full frame */
    if ((g_inptr - g_inbuf) < (int)(FROST_FRAME_HDR + plen))
      continue;

    g_inptr = g_inbuf; /* reset for next frame */
    process_coord_frame(msg_type, g_inbuf + FROST_FRAME_HDR, plen);

  } /* for(;;) */

  gnutls_bye(g_coord_sess, GNUTLS_SHUT_RDWR);
  gnutls_deinit(g_coord_sess);
  close(g_coord_sock);
  gnutls_global_deinit();
  return EXIT_SUCCESS;
}

/* ═══════════════════════════════════════════════════════════════
 * Static helpers
 * ═══════════════════════════════════════════════════════════════ */

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

/* Returns 0 on ok, -1 on fatal error. */
static int drain_outq(void) {
  struct outmsg *m = TAILQ_FIRST(&g_outq);
  if (!m)
    return 0;

  int ret =
      gnutls_record_send(g_coord_sess, m->data + m->sent, m->len - m->sent);
  if (ret == GNUTLS_E_AGAIN || ret == GNUTLS_E_INTERRUPTED) {
    g_want_write = gnutls_record_get_direction(g_coord_sess);
    return 0;
  }
  if (ret < 0) {
    fprintf(stderr, "signer: send error: %s\n", gnutls_strerror(ret));
    return -1;
  }
  g_want_write = 0;
  m->sent += (size_t)ret;
  if (m->sent >= m->len) {
    TAILQ_REMOVE(&g_outq, m, entries);
    free(m->data);
    free(m);
  }
  return 0;
}

/* Establish TLS connection to the coordinator. */
static int connect_to_coordinator(const char *certfile, const char *keyfile,
                                  gnutls_certificate_credentials_t cred) {
  (void)certfile;
  (void)keyfile; /* already loaded into cred before call */

  int sockfd;
  struct sockaddr_in addr;
  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = inet_addr(FROST_COORD_HOST);
  addr.sin_port = htons(FROST_COORD_PORT);

  if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
    perror("signer: socket");
    return -1;
  }
  if (connect(sockfd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
    perror("signer: connect");
    close(sockfd);
    return -1;
  }

  gnutls_init(&g_coord_sess, GNUTLS_CLIENT);
  gnutls_credentials_set(g_coord_sess, GNUTLS_CRD_CERTIFICATE, cred);
  gnutls_handshake_set_timeout(g_coord_sess, GNUTLS_DEFAULT_HANDSHAKE_TIMEOUT);
  gnutls_priority_set_direct(g_coord_sess, "NORMAL", NULL);
  gnutls_session_set_verify_cert(g_coord_sess, "localhost", 0);
  gnutls_transport_set_int(g_coord_sess, sockfd);

  int ret = 0;
  LOOP_CHECK(ret, gnutls_handshake(g_coord_sess));
  if (ret < 0) {
    fprintf(stderr, "signer: TLS handshake failed: %s\n", gnutls_strerror(ret));
    close(sockfd);
    gnutls_deinit(g_coord_sess);
    return -1;
  }
  printf("signer: TLS handshake complete with coordinator at %s:%d\n",
         FROST_COORD_HOST, FROST_COORD_PORT);
  return sockfd;
}

/* Dispatch a fully-received frame from the coordinator. */
static void process_coord_frame(frost_msg_t type, const uint8_t *payload,
                                uint16_t plen) {
  switch (type) {

  /* ── HELLO_ACK: coordinator assigned us an ID ─────────────── */
  case FROST_MSG_HELLO_ACK: {
    char ackbuf[32] = {0};
    size_t copy = plen < 31 ? plen : 31;
    memcpy(ackbuf, payload, copy);
    if (sscanf(ackbuf, "ACK %hu", &g_my_id) != 1) {
      fprintf(stderr, "signer: malformed HELLO_ACK: '%s'\n", ackbuf);
      return;
    }
    printf("signer: assigned ID %u\n", g_my_id);
    break;
  }

  /* ── START_DKG: begin DKG round 1 ────────────────────────── */
  case FROST_MSG_START_DKG: {
    char startbuf[32] = {0};
    size_t copy = plen < 31 ? plen : 31;
    memcpy(startbuf, payload, copy);
    uint16_t pn = 0, pt = 0;
    if (sscanf(startbuf, "START_DKG %hu %hu", &pn, &pt) != 2) {
      fprintf(stderr, "signer: malformed START_DKG\n");
      return;
    }
    printf("signer %u: START_DKG n=%u t=%u — running part1\n", g_my_id, pn, pt);
    g_state = DKG_COLLECTING_R1;

    uint8_t r1_pkg[FROST_MAX_PAYLOAD];
    uint16_t r1_pkg_len = 0;
    if (frost_dkg_part1(g_my_id, pn, pt, g_r1_secret, &g_r1_secret_len, r1_pkg,
                        &r1_pkg_len) != 0) {
      fprintf(stderr, "signer %u: frost_dkg_part1 failed\n", g_my_id);
      return;
    }
    /* send round-1 package to coordinator for broadcast */
    queue_to_coord(FROST_MSG_ROUND1_PKG, r1_pkg, r1_pkg_len);
    printf("signer %u: sent ROUND1_PKG (%u bytes)\n", g_my_id, r1_pkg_len);
    break;
  }

  /* ── RELAY_R1: received peer's round-1 package ────────────── */
  case FROST_MSG_RELAY_R1: {
    if (plen < 2) {
      fprintf(stderr, "signer: r1 relay too short\n");
      return;
    }
    uint16_t sender_id = (uint16_t)(((uint16_t)payload[0] << 8) | payload[1]);
    uint16_t pkg_len = (uint16_t)(plen - 2);

    if (g_peer_r1_count >= FROST_MAX_SIGNERS) {
      fprintf(stderr, "signer %u: too many r1 packages\n", g_my_id);
      return;
    }
    int idx = g_peer_r1_count++;
    g_peer_r1_ids[idx] = sender_id;
    g_peer_r1_len[idx] = pkg_len;
    memcpy(g_peer_r1[idx], payload + 2, pkg_len);
    printf("signer %u: stored r1 from peer %u (%u bytes) [%d/%u]\n", g_my_id,
           sender_id, pkg_len, g_peer_r1_count, (unsigned)(g_n - 1));

    /* once we have all n-1 peer packages, run part2 */
    if (g_peer_r1_count < (int)(g_n - 1))
      return;

    printf("signer %u: all r1 packages received — running part2\n", g_my_id);
    g_state = DKG_COLLECTING_R2;

    static uint8_t r2_out[FROST_MAX_SIGNERS][FROST_MAX_PAYLOAD];
    static uint16_t r2_lens[FROST_MAX_SIGNERS];
    static uint16_t r2_ids[FROST_MAX_SIGNERS];

    if (frost_dkg_part2(g_my_id, g_r1_secret, g_r1_secret_len,
                        (const uint8_t (*)[FROST_MAX_PAYLOAD])g_peer_r1,
                        g_peer_r1_len, g_peer_r1_ids, g_peer_r1_count,
                        g_r2_secret, &g_r2_secret_len, r2_out, r2_lens,
                        r2_ids) != 0) {
      fprintf(stderr, "signer %u: frost_dkg_part2 failed\n", g_my_id);
      return;
    }

    /* send each round-2 package to coordinator for unicast routing
     * frame payload: [uint16_t target_id][r2_pkg_bytes...] */
    for (int i = 0; i < g_peer_r1_count; i++) {
      uint8_t frame[FROST_MAX_PAYLOAD + 4];
      frame[0] = (uint8_t)(g_my_id >> 8);
      frame[1] = (uint8_t)(g_my_id & 0xFF);
      frame[2] = (uint8_t)(r2_ids[i] >> 8);
      frame[3] = (uint8_t)(r2_ids[i] & 0xFF);
      memcpy(frame + 4, r2_out[i], r2_lens[i]);
      queue_to_coord(FROST_MSG_ROUND2_PKG, frame, (uint16_t)(r2_lens[i] + 4));
      printf("signer %u: sent ROUND2_PKG → %u (%u bytes)\n", g_my_id, r2_ids[i],
             r2_lens[i]);
    }
    break;
  }

  /* ── RELAY_R2: received round-2 package addressed to us ───── */
  case FROST_MSG_RELAY_R2: {
    if (plen < 4) {
      fprintf(stderr, "signer: r2 relay too short\n");
      return;
    }
    uint16_t sender_id = (uint16_t)(((uint16_t)payload[0] << 8) | payload[1]);
    uint16_t pkg_len = (uint16_t)(plen - 4);

    if (g_peer_r2_count >= FROST_MAX_SIGNERS) {
      fprintf(stderr, "signer %u: too many r2 packages\n", g_my_id);
      return;
    }
    int idx = g_peer_r2_count++;
    g_peer_r2_ids[idx] = sender_id;
    g_peer_r2_len[idx] = pkg_len;
    memcpy(g_peer_r2[idx], payload + 4, pkg_len);
    printf("signer %u: stored r2 from peer %u (%u bytes) [%d/%u]\n", g_my_id,
           sender_id, pkg_len, g_peer_r2_count, (unsigned)(g_n - 1));

    /* once we have all n-1 r2 packages, run part3 */
    if (g_peer_r2_count < (int)(g_n - 1))
      return;

    printf("signer %u: all r2 packages received — running part3\n", g_my_id);

    if (frost_dkg_part3(g_my_id, g_r2_secret, g_r2_secret_len,
                        (const uint8_t (*)[FROST_MAX_PAYLOAD])g_peer_r1,
                        g_peer_r1_len, g_peer_r1_ids, g_peer_r1_count,
                        (const uint8_t (*)[FROST_MAX_PAYLOAD])g_peer_r2,
                        g_peer_r2_len, g_peer_r2_ids, g_peer_r2_count,
                        g_key_pkg, &g_key_pkg_len, g_pub_key_pkg,
                        &g_pub_key_pkg_len) != 0) {
      fprintf(stderr, "signer %u: frost_dkg_part3 failed\n", g_my_id);
      return;
    }
    g_state = DKG_COMPLETE;
    printf("signer %u: DKG complete — key material ready (%u bytes)\n", g_my_id,
           g_key_pkg_len);

    uint8_t notice[2];
    notice[0] = (uint8_t)(g_my_id >> 8);
    notice[1] = (uint8_t)(g_my_id & 0xFF);
    queue_to_coord(FROST_MSG_R2_COMPLETE, notice, 2);

    /* Write CA public key — only one signer needs to do this.
     * Designate signer 1 as the one that writes it. */

    if (/*g_my_id == 1*/ 1) {
      /* Write pub_key_pkg hex to a temp file, pipe through pubkey subcommand */
      char pub_hex[FROST_MAX_PAYLOAD * 2 + 4];
      bytes_to_hex(g_pub_key_pkg, g_pub_key_pkg_len, pub_hex);

      char cmd[FROST_MAX_PAYLOAD * 3]; // if cmd buffer is too small key save
                                       // command might be malformed
                                       // printf("pub_hex: %s\n", pub_hex);

      /* Write raw PublicKeyPackage bytes as hex for later use */
      char pub_pkg_hex[FROST_MAX_PAYLOAD * 2 + 4];
      bytes_to_hex(g_pub_key_pkg, g_pub_key_pkg_len, pub_pkg_hex);
      FILE *fp = fopen("pub_key_pkg.hex", "w");
      if (fp) {
        fprintf(fp, "%s\n", pub_pkg_hex);
        fclose(fp);
        printf("signer %u: wrote pub_key_pkg.hex\n", g_my_id);
      }

      printf("signer %u secret: ", g_my_id);
      print_bytes_as_hex(g_key_pkg, g_key_pkg_len);
      printf("signer %u public: ", g_my_id);
      print_bytes_as_hex(g_pub_key_pkg, g_pub_key_pkg_len);

      snprintf(cmd, sizeof(cmd),
               "echo '%s' | " FROST_CORE_BIN " pubkey > frost_ca_signer_%u.pub",
               pub_hex, g_my_id);

      printf("signer %u: %s\n", g_my_id, cmd);

      int rc = system(cmd);
      if (rc != 0)
        fprintf(stderr, "signer %u: failed to write frost_ca.pub\n", g_my_id);
      else
        printf("signer %u: wrote frost_ca.pub\n", g_my_id);

      queue_to_coord(FROST_MSG_PUB_KEY_PKG, g_pub_key_pkg, g_pub_key_pkg_len);
      printf("signer %u: sent PUB_KEY_PKG to coordinator (%u bytes)\n", g_my_id,
             g_pub_key_pkg_len);
    }
    break;
  }

  /* ── SIGN_REQ: coordinator wants us to commit ─────────────── */
  case FROST_MSG_SIGN_REQ: {
    if (g_state != DKG_COMPLETE) {
      fprintf(stderr, "signer %u: SIGN_REQ but DKG not complete\n", g_my_id);
      return;
    }
    printf("signer %u: SIGN_REQ received (%u TBS bytes) — generating commit\n",
           g_my_id, plen);
    g_state = DKG_SIGNING;

    uint8_t commit[FROST_MAX_PAYLOAD];
    uint16_t commit_len = 0;

    if (frost_commit(g_my_id, g_key_pkg, g_key_pkg_len, g_nonces, &g_nonces_len,
                     commit, &commit_len) != 0) {
      fprintf(stderr, "signer %u: frost_commit failed\n", g_my_id);
      return;
    }
    queue_to_coord(FROST_MSG_COMMIT, commit, commit_len);
    printf("signer %u: sent COMMIT (%u bytes)\n", g_my_id, commit_len);
    break;
  }

  /* ── RELAY_COMMIT: assembled signing package — produce share ─ */
  case FROST_MSG_RELAY_COMMIT: {
    printf("signer %u: signing package received (%u bytes) — signing\n",
           g_my_id, plen);

    uint8_t sig_share[FROST_MAX_PAYLOAD];
    uint16_t sig_share_len = 0;

    if (frost_sign(g_my_id, payload, plen, g_nonces, g_nonces_len, g_key_pkg,
                   g_key_pkg_len, sig_share, &sig_share_len) != 0) {
      fprintf(stderr, "signer %u: frost_sign failed\n", g_my_id);
      return;
    }
    queue_to_coord(FROST_MSG_SIG_SHARE, sig_share, sig_share_len);
    printf("signer %u: sent SIG_SHARE (%u bytes)\n", g_my_id, sig_share_len);
    g_state = DKG_COMPLETE; /* ready for next signing round */
    break;
  }

  /* ── DKG_DONE: coordinator confirms all signers have r2 ──────── */
  case FROST_MSG_DKG_DONE: {
    char donebuf[32] = {0};
    size_t copy = plen < 31 ? plen : 31;
    memcpy(donebuf, payload, copy);
    uint16_t confirmed = 0;
    sscanf(donebuf, "DKG_DONE %hu", &confirmed);
    printf("signer %u: DKG_DONE — coordinator confirms %u/%u signers completed "
           "r2\n",
           g_my_id, confirmed, g_n);
    break;
  }

  /* ── FINAL_SIG: coordinator relayed the aggregated signature ─ */
  case FROST_MSG_FINAL_SIG:
    printf("signer %u: final signature received (%u bytes)\n", g_my_id, plen);
    /* In a real deployment: pass to ssh-key crate or write to cert file */

    /* Write raw PublicKeyPackage bytes as hex for later use */
    char sig_pkg_hex[FROST_MAX_PAYLOAD * 2 + 4];
    bytes_to_hex(payload, 64, sig_pkg_hex);
    FILE *fp = fopen("signature_pkg.hex", "w");
    if (fp) {
      fprintf(fp, "%s\n", sig_pkg_hex);
      fclose(fp);
      printf("signer %u: wrote signature_pkg.hex\n", g_my_id);
    }

    printf("  hex: ");
    for (uint16_t i = 0; i < plen && i < 64; i++)
      printf("%02x", payload[i]);
    printf("\n");

    break;

  case FROST_MSG_ERROR: {
    char errbuf[256] = {0};
    size_t copy = plen < 255 ? plen : 255;
    memcpy(errbuf, payload, copy);
    fprintf(stderr, "signer %u: coordinator error: %s\n", g_my_id, errbuf);
    break;
  }

  default:
    fprintf(stderr, "signer %u: unknown msg type 0x%02x\n", g_my_id,
            (unsigned)type);
    break;
  }
}
