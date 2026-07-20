/* frost_stubs.c — drop-in replacement for the five stub functions
 * in frost_signer.c.
 *
 * Replace the five static stub functions in frost_signer.c with the
 * contents of this file (or #include it before main()).
 *
 * Each function calls the Rust frost_signer_core binary via popen(),
 * writes inputs on stdin, and reads outputs from stdout.
 *
 * Wire protocol: hex-encoded lines, matching src/main.rs exactly.
 *
 * FROST_CORE_BIN can be overridden at compile time:
 *   gcc ... -DFROST_CORE_BIN=\"/usr/local/bin/frost_signer_core\" ...
 */

#ifndef FROST_CORE_BIN
#define FROST_CORE_BIN "./frost_signer_core/target/debug/frost_signer_core"
#endif

// #include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <gnutls/abstract.h>
#include <gnutls/x509.h>

#include "frost_common.h"

/* ── hex helpers ──────────────────────────────────────────────── */

static void bytes_to_hex(const uint8_t *bytes, size_t len, char *out) {
  static const char hex[] = "0123456789abcdef";
  for (size_t i = 0; i < len; i++) {
    out[2 * i] = hex[(bytes[i] >> 4) & 0xF];
    out[2 * i + 1] = hex[bytes[i] & 0xF];
  }
  out[2 * len] = '\0';
}

static void print_bytes_as_hex(const uint8_t *bytes, size_t len) {
  char hex[FROST_MAX_PAYLOAD] = {'\0'};
  bytes_to_hex(bytes, len, hex);
  printf("%s\n", hex);
}

/* Returns number of bytes decoded, or -1 on error. */
static int hex_to_bytes(const char *hex, uint8_t *out, size_t max_out) {
  size_t hexlen = strlen(hex);
  /* strip trailing newline/space */
  while (hexlen > 0 && (hex[hexlen - 1] == '\n' || hex[hexlen - 1] == '\r' ||
                        hex[hexlen - 1] == ' '))
    hexlen--;

  if (hexlen % 2 != 0)
    return -1;
  size_t nbytes = hexlen / 2;
  if (nbytes > max_out)
    return -1;

  for (size_t i = 0; i < nbytes; i++) {
    unsigned int hi, lo;
    char h[3] = {hex[2 * i], hex[2 * i + 1], '\0'};
    if (sscanf(h, "%1x%1x", &hi, &lo) != 2)
      return -1;
    out[i] = (uint8_t)((hi << 4) | lo);
  }
  return (int)nbytes;
}

/* ── popen helper: write stdin, read one stdout line ────────────
 *
 * cmd      — full shell command string
 * stdin_data — bytes to pipe into stdin (NULL if none)
 * stdin_len  — length of stdin_data
 * line_out   — buffer to receive one line of stdout
 * line_max   — size of line_out
 *
 * Returns 0 on success, -1 on error.
 */
static int popen_roundtrip(const char *cmd, const char *stdin_data,
                           size_t stdin_len, char *line_out, size_t line_max) {
  /* We need bidirectional popen.  POSIX only gives us one direction,
   * so we write stdin via a temp file and read stdout via popen("r"). */
  double t0 = now_ms();

  /* Write stdin to a temp file */
  char tmpfile[] = "/tmp/frost_stdin_XXXXXX";
  int tmpfd = mkstemp(tmpfile);
  if (tmpfd < 0) {
    perror("frost_stubs: mkstemp");
    return -1;
  }
  if (stdin_data && stdin_len > 0) {
    if (write(tmpfd, stdin_data, stdin_len) < 0) {
      perror("frost_stubs: write tmpfile");
      close(tmpfd);
      unlink(tmpfile);
      return -1;
    }
  }
  close(tmpfd);

  /* Build command: feed tmpfile as stdin */
  char full_cmd[4096];
  snprintf(full_cmd, sizeof(full_cmd), "%s < %s", cmd, tmpfile);

  FILE *fp = popen(full_cmd, "r");
  if (!fp) {
    perror("frost_stubs: popen");
    unlink(tmpfile);
    return -1;
  }

  if (fgets(line_out, (int)line_max, fp) == NULL) {
    fprintf(stderr, "frost_stubs: no output from: %s\n", full_cmd);
    pclose(fp);
    unlink(tmpfile);
    fprintf(stderr, "TIMING op=popen_roundtrip cmd=\"%s\" ms=%.3f ok=0\n", cmd,
            now_ms() - t0);
    return -1;
  }

  int exit_code = pclose(fp);
  unlink(tmpfile);

  double elapsed = now_ms() - t0;
  fprintf(stderr, "TIMING op=popen_roundtrip cmd=\"%s\" ms=%.3f ok=%d\n", cmd,
          elapsed, exit_code == 0 ? 1 : 0);

  if (exit_code != 0) {
    fprintf(stderr, "frost_stubs: command exited %d: %s\n", exit_code,
            full_cmd);
    return -1;
  }
  return 0;
}

/* ── Full bidirectional popen: write N input lines, read M output lines ──
 *
 * stdin_lines  — array of strings to write (each gets a '\n' appended)
 * n_in         — number of input lines
 * stdout_lines — array of buffers to receive output lines
 * line_maxes   — size of each output buffer
 * n_out        — number of output lines to read
 *
 * Returns 0 on success, -1 on error.
 */
static int popen_multi(const char *cmd, const char *stdin_lines[], int n_in,
                       char *stdout_lines[], const size_t line_maxes[],
                       int n_out) {
  double t0 = now_ms();
  /* Build full stdin content */
  char stdin_buf[FROST_MAX_PAYLOAD * FROST_MAX_SIGNERS * 3];
  size_t off = 0;
  for (int i = 0; i < n_in; i++) {
    size_t len = strlen(stdin_lines[i]);
    if (off + len + 2 > sizeof(stdin_buf)) {
      fprintf(stderr, "frost_stubs: stdin buffer overflow\n");
      return -1;
    }
    memcpy(stdin_buf + off, stdin_lines[i], len);
    off += len;
    stdin_buf[off++] = '\n';
  }
  stdin_buf[off] = '\0';

  /* Write to temp file */
  char tmpfile[] = "/tmp/frost_stdin_XXXXXX";
  int tmpfd = mkstemp(tmpfile);
  if (tmpfd < 0) {
    perror("mkstemp");
    return -1;
  }
  if (off > 0 && write(tmpfd, stdin_buf, off) < 0) {
    perror("write tmpfile");
    close(tmpfd);
    unlink(tmpfile);
    return -1;
  }
  close(tmpfd);

  char full_cmd[4096];
  snprintf(full_cmd, sizeof(full_cmd), "%s < %s", cmd, tmpfile);

  printf("signer: `%s`\n", full_cmd);

  FILE *fp = popen(full_cmd, "r");
  if (!fp) {
    perror("popen");
    unlink(tmpfile);
    return -1;
  }

  for (int i = 0; i < n_out; i++) {
    if (fgets(stdout_lines[i], (int)line_maxes[i], fp) == NULL) {
      fprintf(stderr, "frost_stubs: EOF reading output line %d\n", i);
      pclose(fp);
      unlink(tmpfile);
      fprintf(stderr, "TIMING op=popen_multi cmd=\"%s\" ms=%.3f ok=0\n", cmd,
              now_ms() - t0);
      return -1;
    }
    /* strip trailing newline */
    size_t slen = strlen(stdout_lines[i]);
    if (slen > 0 && stdout_lines[i][slen - 1] == '\n')
      stdout_lines[i][slen - 1] = '\0';

    /* check for ERROR: prefix */
    if (strncmp(stdout_lines[i], "ERROR:", 6) == 0) {
      fprintf(stderr, "frost_stubs: Rust error: %s\n", stdout_lines[i]);
      pclose(fp);
      unlink(tmpfile);
      fprintf(stderr, "TIMING op=popen_multi cmd=\"%s\" ms=%.3f ok=0\n", cmd,
              now_ms() - t0);
      return -1;
    }
  }

  int exit_code = pclose(fp);
  unlink(tmpfile);

  double elapsed = now_ms() - t0;
  fprintf(stderr, "TIMING op=popen_multi cmd=\"%s\" ms=%.3f ok=%d\n", cmd,
          elapsed, exit_code == 0 ? 1 : 0);

  if (exit_code != 0) {
    fprintf(stderr, "frost_stubs: command failed (exit %d): %s\n", exit_code,
            full_cmd);
    return -1;
  }
  return 0;
}

/* ── Per-call hex line buffers ──────────────────────────────────── */
/* Each hex line can be at most 2*FROST_MAX_PAYLOAD chars + '\0'    */
#define HEX_LINE_MAX (FROST_MAX_PAYLOAD * 2 + 4)

/* ═══════════════════════════════════════════════════════════════
 * frost_dkg_part1
 * ═══════════════════════════════════════════════════════════════ */
static int frost_dkg_part1(uint16_t id, uint16_t n, uint16_t t,
                           uint8_t *secret_out, uint16_t *secret_len,
                           uint8_t *pkg_out, uint16_t *pkg_len) {
  char cmd[256];
  snprintf(cmd, sizeof(cmd), FROST_CORE_BIN " dkg_part1 --id %u --n %u --t %u",
           (unsigned)id, (unsigned)n, (unsigned)t);

  static char secret_hex[HEX_LINE_MAX];
  static char pkg_hex[HEX_LINE_MAX];
  char *out_lines[2] = {secret_hex, pkg_hex};
  size_t out_maxes[2] = {HEX_LINE_MAX, HEX_LINE_MAX};

  if (popen_multi(cmd, NULL, 0, out_lines, out_maxes, 2) != 0)
    return -1;

  int slen = hex_to_bytes(secret_hex, secret_out, FROST_MAX_PAYLOAD);
  int plen = hex_to_bytes(pkg_hex, pkg_out, FROST_MAX_PAYLOAD);
  if (slen < 0 || plen < 0) {
    fprintf(stderr, "frost_stubs: dkg_part1 hex decode failed\n");
    return -1;
  }
  *secret_len = (uint16_t)slen;
  *pkg_len = (uint16_t)plen;

  printf("signer %u: dkg_part1 ok — secret=%u bytes, pkg=%u bytes\n",
         (unsigned)id, *secret_len, *pkg_len);
  return 0;
}

/* ═══════════════════════════════════════════════════════════════
 * frost_dkg_part2
 * ═══════════════════════════════════════════════════════════════ */
static int frost_dkg_part2(uint16_t my_id, const uint8_t *r1_secret,
                           uint16_t r1_secret_len,
                           const uint8_t peer_r1[][FROST_MAX_PAYLOAD],
                           const uint16_t peer_r1_lens[],
                           const uint16_t peer_r1_ids[], int n_peers,
                           uint8_t *r2_secret_out, uint16_t *r2_secret_len,
                           uint8_t peer_r2_out[][FROST_MAX_PAYLOAD],
                           uint16_t peer_r2_lens[], uint16_t peer_r2_ids[]) {
  char cmd[256];
  snprintf(cmd, sizeof(cmd), FROST_CORE_BIN " dkg_part2 --id %u --n %u",
           (unsigned)my_id, (unsigned)(n_peers + 1));

  /* Build stdin: line 1 = r1 secret hex, then n_peers peer r1 lines */
  /* We need 1 + n_peers input lines */
  int n_in = 1 + n_peers;
  const char **in_lines = malloc((size_t)n_in * sizeof(char *));
  char **in_bufs = malloc((size_t)n_in * sizeof(char *));
  if (!in_lines || !in_bufs) {
    free(in_lines);
    free(in_bufs);
    return -1;
  }

  /* line 0: r1 secret */
  in_bufs[0] = malloc(HEX_LINE_MAX);
  bytes_to_hex(r1_secret, r1_secret_len, in_bufs[0]);
  in_lines[0] = in_bufs[0];

  /* lines 1..n_peers: "<sender_id> <hex(r1_pkg)>" */
  for (int i = 0; i < n_peers; i++) {
    in_bufs[1 + i] = malloc(HEX_LINE_MAX + 8);
    char pkg_hex[HEX_LINE_MAX];
    bytes_to_hex(peer_r1[i], peer_r1_lens[i], pkg_hex);
    snprintf(in_bufs[1 + i], HEX_LINE_MAX + 8, "%u %s",
             (unsigned)peer_r1_ids[i], pkg_hex);
    in_lines[1 + i] = in_bufs[1 + i];
  }

  /* Output: line 0 = r2 secret, lines 1..n_peers = "<target_id> <hex>" */
  int n_out = 1 + n_peers;
  char **out_bufs = malloc((size_t)n_out * sizeof(char *));
  char **out_lines = malloc((size_t)n_out * sizeof(char *));
  size_t *out_maxes = malloc((size_t)n_out * sizeof(size_t));
  if (!out_bufs || !out_lines || !out_maxes) {
    /* cleanup and bail */
    for (int i = 0; i < n_in; i++)
      free(in_bufs[i]);
    free(in_lines);
    free(in_bufs);
    free(out_bufs);
    free(out_lines);
    free(out_maxes);
    return -1;
  }
  for (int i = 0; i < n_out; i++) {
    out_bufs[i] = malloc(HEX_LINE_MAX + 8);
    out_lines[i] = out_bufs[i];
    out_maxes[i] = HEX_LINE_MAX + 8;
  }

  int rc = popen_multi(cmd, in_lines, n_in, out_lines, out_maxes, n_out);

  for (int i = 0; i < n_in; i++)
    free(in_bufs[i]);
  free(in_lines);
  free(in_bufs);

  if (rc != 0) {
    for (int i = 0; i < n_out; i++)
      free(out_bufs[i]);
    free(out_bufs);
    free(out_lines);
    free(out_maxes);
    return -1;
  }

  /* decode r2 secret (line 0) */
  int slen = hex_to_bytes(out_bufs[0], r2_secret_out, FROST_MAX_PAYLOAD);
  if (slen < 0) {
    fprintf(stderr, "frost_stubs: dkg_part2 r2 secret hex decode failed\n");
    for (int i = 0; i < n_out; i++)
      free(out_bufs[i]);
    free(out_bufs);
    free(out_lines);
    free(out_maxes);
    return -1;
  }
  *r2_secret_len = (uint16_t)slen;

  /* decode r2 packages (lines 1..n_peers) */
  for (int i = 0; i < n_peers; i++) {
    char *line = out_bufs[1 + i];
    /* format: "<target_id> <hex>" */
    unsigned int tid = 0;
    char *space = strchr(line, ' ');
    if (!space) {
      fprintf(stderr, "frost_stubs: dkg_part2 bad r2 line: %s\n", line);
      for (int j = 0; j < n_out; j++)
        free(out_bufs[j]);
      free(out_bufs);
      free(out_lines);
      free(out_maxes);
      return -1;
    }
    *space = '\0';
    sscanf(line, "%u", &tid);
    peer_r2_ids[i] = (uint16_t)tid;
    int plen = hex_to_bytes(space + 1, peer_r2_out[i], FROST_MAX_PAYLOAD);
    if (plen < 0) {
      fprintf(stderr, "frost_stubs: dkg_part2 r2 pkg hex decode failed\n");
      for (int j = 0; j < n_out; j++)
        free(out_bufs[j]);
      free(out_bufs);
      free(out_lines);
      free(out_maxes);
      return -1;
    }
    peer_r2_lens[i] = (uint16_t)plen;
  }

  for (int i = 0; i < n_out; i++)
    free(out_bufs[i]);
  free(out_bufs);
  free(out_lines);
  free(out_maxes);

  printf("signer %u: dkg_part2 ok — %d r2 packages\n", (unsigned)my_id,
         n_peers);
  return 0;
}

/* ═══════════════════════════════════════════════════════════════
 * frost_dkg_part3
 * ═══════════════════════════════════════════════════════════════ */
static int
frost_dkg_part3(uint16_t my_id, const uint8_t *r2_secret,
                uint16_t r2_secret_len,
                const uint8_t peer_r1[][FROST_MAX_PAYLOAD],
                const uint16_t peer_r1_lens[], const uint16_t peer_r1_ids[],
                int n_r1, const uint8_t peer_r2[][FROST_MAX_PAYLOAD],
                const uint16_t peer_r2_lens[], const uint16_t peer_r2_ids[],
                int n_r2, uint8_t *key_pkg_out, uint16_t *key_pkg_len,
                uint8_t *pub_key_pkg_out, uint16_t *pub_key_pkg_len) {
  char cmd[256];
  snprintf(cmd, sizeof(cmd), FROST_CORE_BIN " dkg_part3 --id %u --n %u --t 0",
           (unsigned)my_id, (unsigned)(n_r1 + 1));

  /* stdin: r2_secret, then n_r1 r1 lines, then n_r2 r2 lines */
  int n_in = 1 + n_r1 + n_r2;
  char **in_bufs = malloc((size_t)n_in * sizeof(char *));
  const char **in_lines = malloc((size_t)n_in * sizeof(char *));
  if (!in_bufs || !in_lines) {
    free(in_bufs);
    free(in_lines);
    return -1;
  }

  int idx = 0;

  in_bufs[idx] = malloc(HEX_LINE_MAX);
  bytes_to_hex(r2_secret, r2_secret_len, in_bufs[idx]);
  in_lines[idx] = in_bufs[idx];
  idx++;

  /* peer r1 packages — we stored sender IDs in g_peer_r1_ids[] in
   * frost_signer.c, but that array isn't passed here.  The C caller
   * must pass them via a wrapper.  For now use sequential IDs
   * excluding my_id (matches the order they arrived). */
  for (int i = 0; i < n_r1; i++) {
    in_bufs[idx] = malloc(HEX_LINE_MAX + 8);
    char pkg_hex[HEX_LINE_MAX];
    bytes_to_hex(peer_r1[i], peer_r1_lens[i], pkg_hex);
    /* sender ID: reconstruct from position (caller fills g_peer_r1_ids) */
    snprintf(in_bufs[idx], HEX_LINE_MAX + 8, "%u %s", (unsigned)peer_r1_ids[i],
             pkg_hex); /* patched below */
    in_lines[idx] = in_bufs[idx];
    idx++;
  }

  for (int i = 0; i < n_r2; i++) {
    in_bufs[idx] = malloc(HEX_LINE_MAX + 8);
    char pkg_hex[HEX_LINE_MAX];
    bytes_to_hex(peer_r2[i], peer_r2_lens[i], pkg_hex);
    snprintf(in_bufs[idx], HEX_LINE_MAX + 8, "%u %s", (unsigned)peer_r2_ids[i],
             pkg_hex); /* patched below */
    in_lines[idx] = in_bufs[idx];
    idx++;
  }

  /* 2 output lines: KeyPackage, PublicKeyPackage */
  char key_hex[HEX_LINE_MAX], pub_hex[HEX_LINE_MAX];
  char *out_lines[2] = {key_hex, pub_hex};
  size_t out_maxes[2] = {HEX_LINE_MAX, HEX_LINE_MAX};

  int rc = popen_multi(cmd, in_lines, n_in, out_lines, out_maxes, 2);

  for (int i = 0; i < n_in; i++)
    free(in_bufs[i]);
  free(in_bufs);
  free(in_lines);
  if (rc != 0)
    return -1;

  int klen = hex_to_bytes(key_hex, key_pkg_out, FROST_MAX_PAYLOAD);
  if (klen < 0) {
    fprintf(stderr, "frost_stubs: dkg_part3 key pkg hex decode failed\n");
    return -1;
  }
  *key_pkg_len = (uint16_t)klen;

  /* PublicKeyPackage is available here too if the caller wants it;
   * pub_hex contains it.  For SSH CA use, extract the verifying_key
   * by calling:  frost_signer_core pubkey < pub_hex_file  */
  int plen = hex_to_bytes(pub_hex, pub_key_pkg_out, FROST_MAX_PAYLOAD);
  if (plen < 0) {
    fprintf(stderr, "frost_stubs: dkg_part3 pub key pkg hex decode failed\n");
  }
  *pub_key_pkg_len = (uint16_t)plen;

  printf("signer %u: dkg_part3 ok — key_pkg=%u bytes, pub_key_pkg=%u bytes\n",
         (unsigned)my_id, *key_pkg_len, *pub_key_pkg_len);

  // printf("signer %u: dkg_part3 ok — key_pkg=%u bytes\n", (unsigned)my_id,
  //       *key_pkg_len);
  return 0;
}

/* ── frost_refresh_part1 ──────────────────────────────────────────
 * Calls refresh_part1 --id <id> --n <n> --t <t>.
 * Output: round1 secret package and round1 broadcast package.
 * Wire format identical to frost_dkg_part1.                       */
static int frost_refresh_part1(uint16_t my_id, uint16_t n, uint16_t t,
                               uint8_t *r1_secret_out,
                               uint16_t *r1_secret_len_out, uint8_t *r1_pkg_out,
                               uint16_t *r1_pkg_len_out) {
  char cmd[256];
  snprintf(cmd, sizeof(cmd),
           FROST_CORE_BIN " refresh_part1 --id %u --n %u --t %u",
           (unsigned)my_id, (unsigned)n, (unsigned)t);

  const char *in_lines[] = {NULL};
  static char rf1_buf0[HEX_LINE_MAX + 1];
  static char rf1_buf1[HEX_LINE_MAX + 1];
  char *out_lines[2] = {rf1_buf0, rf1_buf1};
  size_t maxes_2[2] = {HEX_LINE_MAX, HEX_LINE_MAX};
  if (popen_multi(cmd, in_lines, 0, out_lines, maxes_2, 2) != 0) {
    fprintf(stderr, "frost_stubs: refresh_part1 failed\n");
    return -1;
  }

  int r1s_len = hex_to_bytes(out_lines[0], r1_secret_out, FROST_MAX_PAYLOAD);
  int r1p_len = hex_to_bytes(out_lines[1], r1_pkg_out, FROST_MAX_PAYLOAD);

  if (r1s_len < 0 || r1p_len < 0) {
    fprintf(stderr, "frost_stubs: refresh_part1 hex decode failed\n");
    return -1;
  }
  *r1_secret_len_out = (uint16_t)r1s_len;
  *r1_pkg_len_out = (uint16_t)r1p_len;
  return 0;
}

/* ── frost_refresh_part2 ──────────────────────────────────────────
 * Calls refresh_part2 --id <id>.
 * Wire format identical to frost_dkg_part2.                       */
static int frost_refresh_part2(
    uint16_t my_id, const uint8_t *r1_secret, uint16_t r1_secret_len,
    const uint8_t peer_r1[][FROST_MAX_PAYLOAD], const uint16_t *peer_r1_lens,
    const uint16_t *peer_r1_ids, int n_r1, uint8_t *r2_secret_out,
    uint16_t *r2_secret_len_out, uint8_t r2_out[][FROST_MAX_PAYLOAD],
    uint16_t *r2_lens, uint16_t *r2_ids) {
  char cmd[256];
  snprintf(cmd, sizeof(cmd), FROST_CORE_BIN " refresh_part2 --id %u",
           (unsigned)my_id);

  /* Build input: r1_secret hex, then "<id> <r1_pkg hex>" per peer */
  char r1_secret_hex[FROST_MAX_PAYLOAD * 2 + 2];
  bytes_to_hex(r1_secret, r1_secret_len, r1_secret_hex);

  static char peer_lines[FROST_MAX_SIGNERS][FROST_MAX_PAYLOAD * 2 + 32];
  const char *in_lines[FROST_MAX_SIGNERS + 2];
  in_lines[0] = r1_secret_hex;
  for (int i = 0; i < n_r1; i++) {
    char hex[FROST_MAX_PAYLOAD * 2 + 2];
    bytes_to_hex(peer_r1[i], peer_r1_lens[i], hex);
    snprintf(peer_lines[i], sizeof(peer_lines[i]), "%u %s",
             (unsigned)peer_r1_ids[i], hex);
    in_lines[i + 1] = peer_lines[i];
  }
  in_lines[n_r1 + 1] = NULL;

  /* Output: r2_secret hex, then "<id> <r2_pkg hex>" per peer */
  // char *out_lines[FROST_MAX_SIGNERS + 2];
  // memset(out_lines, 0, sizeof(out_lines));
  static char rf2_bufs[FROST_MAX_SIGNERS + 2][HEX_LINE_MAX + 1];
  char *out_lines[FROST_MAX_SIGNERS + 2];
  for (int mi = 0; mi < n_r1 + 1; mi++)
    out_lines[mi] = rf2_bufs[mi];

  size_t maxes_r2[FROST_MAX_SIGNERS + 2];
  for (int mi = 0; mi < n_r1 + 1; mi++)
    maxes_r2[mi] = HEX_LINE_MAX;
  if (popen_multi(cmd, in_lines, n_r1 + 1, out_lines, maxes_r2, n_r1 + 1) !=
      0) {
    fprintf(stderr, "frost_stubs: refresh_part2 failed\n");
    return -1;
  }

  int r2s_len = hex_to_bytes(out_lines[0], r2_secret_out, FROST_MAX_PAYLOAD);
  // free(out_lines[0]);
  if (r2s_len < 0) {
    return -1;
  }
  *r2_secret_len_out = (uint16_t)r2s_len;

  for (int i = 0; i < n_r1; i++) {
    if (!out_lines[i + 1])
      return -1;
    char *sp = strchr(out_lines[i + 1], ' ');
    if (!sp) {
      // free(out_lines[i + 1]);
      return -1;
    }
    *sp = '\0';
    r2_ids[i] = (uint16_t)atoi(out_lines[i + 1]);
    int r2len = hex_to_bytes(sp + 1, r2_out[i], FROST_MAX_PAYLOAD);
    // free(out_lines[i + 1]);
    if (r2len < 0)
      return -1;
    r2_lens[i] = (uint16_t)r2len;
  }
  return 0;
}

/* ── frost_refresh_shares ─────────────────────────────────────────
 * Calls refresh_shares --n <n>.
 * Passes old KeyPackage and PublicKeyPackage as the final two stdin
 * lines; receives new KeyPackage and PublicKeyPackage on stdout.
 *
 * The group verifying key is guaranteed unchanged by the Rust binary.*/
static int frost_refresh_shares(
    uint16_t my_id, uint16_t n, const uint8_t *r2_secret,
    uint16_t r2_secret_len, const uint8_t peer_r1[][FROST_MAX_PAYLOAD],
    const uint16_t *peer_r1_lens, const uint16_t *peer_r1_ids, int n_r1,
    const uint8_t peer_r2[][FROST_MAX_PAYLOAD], const uint16_t *peer_r2_lens,
    const uint16_t *peer_r2_ids, int n_r2, const uint8_t *old_key_pkg,
    uint16_t old_key_pkg_len, const uint8_t *old_pub_key_pkg,
    uint16_t old_pub_key_pkg_len, uint8_t *new_key_pkg_out,
    uint16_t *new_key_pkg_len_out, uint8_t *new_pub_key_pkg_out,
    uint16_t *new_pub_key_pkg_len_out) {
  (void)my_id;
  char cmd[256];
  snprintf(cmd, sizeof(cmd), FROST_CORE_BIN " refresh_shares --n %u",
           (unsigned)n);

  /* Build stdin:
   *   line 0:         hex(r2_secret)
   *   lines 1..n_r1:  "<id> <hex(r1_pkg)>"
   *   lines n_r1+1..n_r1+n_r2:  "<id> <hex(r2_pkg)>"
   *   line n_r1+n_r2+1: hex(old_pub_key_pkg)
   *   line n_r1+n_r2+2: hex(old_key_pkg)          */
  static char r2_secret_hex_buf[FROST_MAX_PAYLOAD * 2 + 2];
  static char peer_r1_lines[FROST_MAX_SIGNERS][FROST_MAX_PAYLOAD * 2 + 32];
  static char peer_r2_lines[FROST_MAX_SIGNERS][FROST_MAX_PAYLOAD * 2 + 32];
  static char old_pub_hex[FROST_MAX_PAYLOAD * 2 + 2];
  static char old_key_hex[FROST_MAX_PAYLOAD * 2 + 2];

  bytes_to_hex(r2_secret, r2_secret_len, r2_secret_hex_buf);
  bytes_to_hex(old_pub_key_pkg, old_pub_key_pkg_len, old_pub_hex);
  bytes_to_hex(old_key_pkg, old_key_pkg_len, old_key_hex);

  const char *in_lines[FROST_MAX_SIGNERS * 2 + 8];
  int idx = 0;
  in_lines[idx++] = r2_secret_hex_buf;
  for (int i = 0; i < n_r1; i++) {
    char hex[FROST_MAX_PAYLOAD * 2 + 2];
    bytes_to_hex(peer_r1[i], peer_r1_lens[i], hex);
    snprintf(peer_r1_lines[i], sizeof(peer_r1_lines[i]), "%u %s",
             (unsigned)peer_r1_ids[i], hex);
    in_lines[idx++] = peer_r1_lines[i];
  }
  for (int i = 0; i < n_r2; i++) {
    char hex[FROST_MAX_PAYLOAD * 2 + 2];
    bytes_to_hex(peer_r2[i], peer_r2_lens[i], hex);
    snprintf(peer_r2_lines[i], sizeof(peer_r2_lines[i]), "%u %s",
             (unsigned)peer_r2_ids[i], hex);
    in_lines[idx++] = peer_r2_lines[i];
  }
  in_lines[idx++] = old_pub_hex;
  in_lines[idx++] = old_key_hex;
  in_lines[idx] = NULL;

  static char rfs_buf0[HEX_LINE_MAX + 1];
  static char rfs_buf1[HEX_LINE_MAX + 1];
  char *out_lines[2] = {rfs_buf0, rfs_buf1};
  size_t maxes_rs[2] = {HEX_LINE_MAX, HEX_LINE_MAX};
  if (popen_multi(cmd, in_lines, idx, out_lines, maxes_rs, 2) != 0) {
    fprintf(stderr, "frost_stubs: refresh_shares failed\n");
    return -1;
  }

  int klen = hex_to_bytes(out_lines[0], new_key_pkg_out, FROST_MAX_PAYLOAD);
  int plen = hex_to_bytes(out_lines[1], new_pub_key_pkg_out, FROST_MAX_PAYLOAD);
  // free(out_lines[0]);
  // free(out_lines[1]);

  if (klen < 0 || plen < 0) {
    fprintf(stderr, "frost_stubs: refresh_shares hex decode failed\n");
    return -1;
  }
  *new_key_pkg_len_out = (uint16_t)klen;
  *new_pub_key_pkg_len_out = (uint16_t)plen;
  return 0;
}

/* ═══════════════════════════════════════════════════════════════
 * frost_commit
 * ═══════════════════════════════════════════════════════════════ */
static int frost_commit(uint16_t my_id, const uint8_t *key_pkg,
                        uint16_t key_pkg_len, uint8_t *nonces_out,
                        uint16_t *nonces_len, uint8_t *commit_out,
                        uint16_t *commit_len) {
  char cmd[256];
  snprintf(cmd, sizeof(cmd), FROST_CORE_BIN " commit --id %u", (unsigned)my_id);

  /* stdin: KeyPackage hex */
  char key_hex[HEX_LINE_MAX];
  bytes_to_hex(key_pkg, key_pkg_len, key_hex);
  const char *in_lines[1] = {key_hex};

  char nonces_hex[HEX_LINE_MAX], commit_hex[HEX_LINE_MAX];
  char *out_lines[2] = {nonces_hex, commit_hex};
  size_t out_maxes[2] = {HEX_LINE_MAX, HEX_LINE_MAX};

  if (popen_multi(cmd, in_lines, 1, out_lines, out_maxes, 2) != 0)
    return -1;

  int nlen = hex_to_bytes(nonces_hex, nonces_out, FROST_MAX_PAYLOAD);
  int clen = hex_to_bytes(commit_hex, commit_out, FROST_MAX_PAYLOAD);
  if (nlen < 0 || clen < 0) {
    fprintf(stderr, "frost_stubs: commit hex decode failed\n");
    return -1;
  }
  *nonces_len = (uint16_t)nlen;
  *commit_len = (uint16_t)clen;

  printf("signer %u: commit ok — nonces=%u bytes, commit=%u bytes\n",
         (unsigned)my_id, *nonces_len, *commit_len);
  return 0;
}

/* ═══════════════════════════════════════════════════════════════
 * frost_sign
 * ═══════════════════════════════════════════════════════════════ */
static int frost_sign(uint16_t my_id, const uint8_t *signing_pkg,
                      uint16_t signing_pkg_len, const uint8_t *nonces,
                      uint16_t nonces_len, const uint8_t *key_pkg,
                      uint16_t key_pkg_len, uint8_t *sig_share_out,
                      uint16_t *sig_share_len) {
  char cmd[256];
  snprintf(cmd, sizeof(cmd), FROST_CORE_BIN " sign --id %u", (unsigned)my_id);

  char nonces_hex[HEX_LINE_MAX], key_hex[HEX_LINE_MAX],
      signing_hex[HEX_LINE_MAX];
  bytes_to_hex(nonces, nonces_len, nonces_hex);
  bytes_to_hex(key_pkg, key_pkg_len, key_hex);
  bytes_to_hex(signing_pkg, signing_pkg_len, signing_hex);

  /* stdin order must match cmd_sign() in main.rs:
   *   line 1 — nonces
   *   line 2 — key_pkg
   *   line 3 — signing_pkg  */
  const char *in_lines[3] = {nonces_hex, key_hex, signing_hex};

  char share_hex[HEX_LINE_MAX];
  char *out_lines[1] = {share_hex};
  size_t out_maxes[1] = {HEX_LINE_MAX};

  if (popen_multi(cmd, in_lines, 3, out_lines, out_maxes, 1) != 0)
    return -1;

  int slen = hex_to_bytes(share_hex, sig_share_out, FROST_MAX_PAYLOAD);
  if (slen < 0) {
    fprintf(stderr, "frost_stubs: sign hex decode failed\n");
    return -1;
  }
  *sig_share_len = (uint16_t)slen;

  printf("signer %u: sign ok — share=%u bytes\n", (unsigned)my_id,
         *sig_share_len);
  return 0;
}

/* Simple cache so we don't reopen/reparse the same cert file repeatedly */

static gnutls_pubkey_t g_pubkey_cache[FROST_MAX_SIGNERS + 1] = {0};

/* Load a single signer's public key from certs/signer{id}.crt
 * Returns 0 on success, -1 on failure. */
static int load_signer_pubkey(uint16_t id) {
  char path[64];
  snprintf(path, sizeof(path), "certs/signer%u.crt", id);

  gnutls_datum_t cert_data;
  if (gnutls_load_file(path, &cert_data) != GNUTLS_E_SUCCESS) {
    fprintf(stderr, "signer: failed to load cert '%s'\n", path);
    return -1;
  }

  gnutls_x509_crt_t cert;
  gnutls_x509_crt_init(&cert);
  if (gnutls_x509_crt_import(cert, &cert_data, GNUTLS_X509_FMT_PEM) !=
      GNUTLS_E_SUCCESS) {
    fprintf(stderr, "signer: failed to parse cert '%s'\n", path);
    gnutls_free(cert_data.data);
    gnutls_x509_crt_deinit(cert);
    return -1;
  }
  gnutls_free(cert_data.data);

  gnutls_pubkey_t pubkey;
  gnutls_pubkey_init(&pubkey);
  if (gnutls_pubkey_import_x509(pubkey, cert, 0) != GNUTLS_E_SUCCESS) {
    fprintf(stderr, "signer: failed to extract pubkey from '%s'\n", path);
    gnutls_x509_crt_deinit(cert);
    gnutls_pubkey_deinit(pubkey);
    return -1;
  }
  gnutls_x509_crt_deinit(cert);

  g_pubkey_cache[id] = pubkey;
  return 0;
}

/* Preload all signer public keys (1..FROST_MAX_SIGNERS) into the cache.
 * Call once during signer initialization, before the DKG ceremony starts.
 * Returns 0 if all loaded successfully, -1 if any failed. */
static int init_signer_pubkey_cache(void) {
  int rc = 0;
  for (uint16_t id = 1; id <= FROST_MAX_SIGNERS; id++) {
    if (load_signer_pubkey(id) != 0) {
      fprintf(stderr, "signer: failed to preload pubkey for signer %u\n", id);
      rc = -1;
      /* keep going so we report all missing/broken certs at once,
       * rather than bailing on the first failure */
    }
  }
  return rc;
}

/* Cleanup — call at shutdown to free cached pubkey handles */
static void free_signer_pubkey_cache(void) {
  for (uint16_t id = 0; id <= FROST_MAX_SIGNERS; id++) {
    if (g_pubkey_cache[id] != NULL) {
      gnutls_pubkey_deinit(g_pubkey_cache[id]);
      g_pubkey_cache[id] = NULL;
    }
  }
}

/* Accessor for use in your send loop */
static gnutls_pubkey_t get_signer_pubkey(uint16_t id) {
  if (id > FROST_MAX_SIGNERS || g_pubkey_cache[id] == NULL) {
    fprintf(stderr, "signer: no cached pubkey for signer %u\n", id);
    return NULL;
  }
  return g_pubkey_cache[id];
}

/* Cryptographically verify that `cert_file` (the --cert argument the
 * user passed on the command line) holds the SAME public key as the
 * cached certs/signer<id>.crt — i.e. that the identity this process is
 * about to assert as <id> really is backed by that keypair, and not
 * merely a coincidentally-present file at the expected path.
 *
 * Compares DER encodings of the two SubjectPublicKeyInfo structures
 * rather than e.g. comparing raw cert bytes, so it still matches even
 * if the two certs differ in serial number, validity window, or any
 * other field — only the key material itself has to agree.
 *
 * Must be called after init_signer_pubkey_cache() has populated
 * g_pubkey_cache[id]. Returns 0 on match, -1 on any mismatch or error
 * (a diagnostic is printed in every failure case).                   */
static int verify_own_identity(uint16_t id, const char *cert_file) {
  gnutls_datum_t cert_data;
  if (gnutls_load_file(cert_file, &cert_data) != GNUTLS_E_SUCCESS) {
    fprintf(stderr, "signer: failed to load '%s' for identity check\n",
            cert_file);
    return -1;
  }

  gnutls_x509_crt_t cert;
  gnutls_x509_crt_init(&cert);
  if (gnutls_x509_crt_import(cert, &cert_data, GNUTLS_X509_FMT_PEM) !=
      GNUTLS_E_SUCCESS) {
    fprintf(stderr, "signer: failed to parse '%s' for identity check\n",
            cert_file);
    gnutls_free(cert_data.data);
    gnutls_x509_crt_deinit(cert);
    return -1;
  }
  gnutls_free(cert_data.data);

  gnutls_pubkey_t supplied_pub;
  gnutls_pubkey_init(&supplied_pub);
  if (gnutls_pubkey_import_x509(supplied_pub, cert, 0) != GNUTLS_E_SUCCESS) {
    fprintf(stderr, "signer: failed to extract pubkey from '%s'\n", cert_file);
    gnutls_x509_crt_deinit(cert);
    gnutls_pubkey_deinit(supplied_pub);
    return -1;
  }
  gnutls_x509_crt_deinit(cert);

  /* Borrowed handle — owned by g_pubkey_cache, do not deinit it here. */
  gnutls_pubkey_t expected_pub = get_signer_pubkey(id);
  if (!expected_pub) {
    gnutls_pubkey_deinit(supplied_pub);
    return -1; /* get_signer_pubkey() already printed a diagnostic */
  }

  gnutls_datum_t supplied_der = {0};
  gnutls_datum_t expected_der = {0};
  int rc = -1;

  if (gnutls_pubkey_export2(supplied_pub, GNUTLS_X509_FMT_DER, &supplied_der) !=
          GNUTLS_E_SUCCESS ||
      gnutls_pubkey_export2(expected_pub, GNUTLS_X509_FMT_DER, &expected_der) !=
          GNUTLS_E_SUCCESS) {
    fprintf(stderr, "signer: failed to export a public key for comparison\n");
    goto out;
  }

  if (supplied_der.size == expected_der.size &&
      memcmp(supplied_der.data, expected_der.data, supplied_der.size) == 0) {
    rc = 0;
  } else {
    fprintf(stderr,
            "signer: public key in '%s' does NOT match "
            "certs/signer%u.crt — refusing to assert id %u with a "
            "mismatched identity\n",
            cert_file, id, id);
  }

out:
  gnutls_free(supplied_der.data);
  gnutls_free(expected_der.data);
  gnutls_pubkey_deinit(supplied_pub);
  return rc;
}
