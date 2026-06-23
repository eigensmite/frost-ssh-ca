/* frost_common.h — shared constants and message types for the FROST
 * coordinator transport layer.
 *
 * Mirrors the style of common.h / inet.h from the base project:
 * same fixed-width framing, same GnuTLS conventions, same select loop.
 *
 * Wire format (every frame):
 *   [uint8_t  msg_type ]  — one of FROST_MSG_* below
 *   [uint16_t payload_len] — big-endian, bytes that follow
 * (0..FROST_MAX_PAYLOAD) [uint8_t  payload[payload_len]]
 *
 * Total max frame = 1 + 2 + FROST_MAX_PAYLOAD bytes.
 */

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-macros"

#ifndef FROST_COMMON_H
#define FROST_COMMON_H

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/queue.h> /* BSD linked-list macros */
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>

/* ── Coordinator / directory address ─────────────────────────── */
#define FROST_COORD_HOST "127.0.0.1"
#define FROST_COORD_PORT 60601 /* above 49151 per project convention */

/* ── Sizing ───────────────────────────────────────────────────── */
#define FROST_MAX_PAYLOAD 4096 /* max bytes in one frame payload    */
#define FROST_FRAME_HDR 3      /* 1-byte type + 2-byte length       */
#define FROST_FRAME_MAX (FROST_FRAME_HDR + FROST_MAX_PAYLOAD)
#define FROST_MAX_SIGNERS 16 /* maximum n for any DKG session     */
#define FROST_ID_LEN 8       /* signer identifier string max len  */

/* ── TLS certificate paths ────────────────────────────────────── */
#define FROST_CAFILE "certs/rootCA.crt"
#define FROST_COORD_CERT "certs/directory.crt"
#define FROST_COORD_KEY "certs/directorykey.pem"
/* Each signer uses one of the existing leaf certs; add more as needed. */
#define FROST_SIGNER1_CERT "certs/beocat.crt"
#define FROST_SIGNER1_KEY "certs/beocatkey.pem"
#define FROST_SIGNER2_CERT "certs/football.crt"
#define FROST_SIGNER2_KEY "certs/footballkey.pem"

/* ── Message type tags (one byte, first byte of every frame) ─── */
typedef enum {
  /* Signer → Coordinator */
  FROST_MSG_HELLO = 0x01,       /* "SIGNER <id> <n> <t>\n"            */
  FROST_MSG_ROUND1_PKG = 0x02,  /* DKG round-1 broadcast package      */
  FROST_MSG_ROUND2_PKG = 0x03,  /* DKG round-2 unicast package        */
  FROST_MSG_COMMIT = 0x04,      /* signing commitment (nonce pair)    */
  FROST_MSG_SIG_SHARE = 0x05,   /* signature share                    */
  FROST_MSG_R2_COMPLETE = 0x06, /* signer → coordinator: part3 done   */
  FROST_MSG_PUB_KEY_PKG = 0x07, /* signer 1 → coordinator: PublicKeyPackage */

  /* Coordinator → Signer */
  FROST_MSG_HELLO_ACK = 0x10,    /* "ACK <assigned_id>\n"               */
  FROST_MSG_START_DKG = 0x11,    /* "START_DKG <n> <t>\n"               */
  FROST_MSG_RELAY_R1 = 0x12,     /* relay: round-1 pkg from peer        */
  FROST_MSG_RELAY_R2 = 0x13,     /* relay: round-2 pkg for this signer  */
  FROST_MSG_SIGN_REQ = 0x14,     /* "SIGN_REQ <hex_cert_tbs>\n"         */
  FROST_MSG_RELAY_COMMIT = 0x15, /* relay: all commitments assembled    */
  FROST_MSG_FINAL_SIG = 0x16,    /* final aggregated signature (64 B)   */
  FROST_MSG_DKG_DONE = 0x17,     /* coordinator → all signers: all done */

  /* Bidirectional */
  FROST_MSG_ERROR = 0xFF, /* human-readable error string        */
} frost_msg_t;

/* ── DKG session state (tracked by coordinator) ──────────────── */
typedef enum {
  DKG_IDLE = 0,
  DKG_COLLECTING_R1, /* waiting for all round-1 packages   */
  DKG_COLLECTING_R2, /* waiting for all round-2 packages   */
  DKG_COMPLETE,      /* key material established           */
  DKG_SIGNING,       /* threshold signing round in flight  */
  DKG_SIGN_SENT,     /* signing package broadcast, done    */
} dkg_state_t;

/* ── Outgoing message queue node (same pattern as base project) ─ */
struct outmsg {
  size_t len;
  size_t sent;
  uint8_t *data;
  TAILQ_ENTRY(outmsg) entries;
};

/* ── Helper: GnuTLS LOOP_CHECK (from base project) ────────────── */
#define LOOP_CHECK(rval, cmd)                                                  \
  do {                                                                         \
    rval = cmd;                                                                \
  } while (rval == GNUTLS_E_AGAIN || rval == GNUTLS_E_INTERRUPTED)

/* ── Safe list iteration macros (from base project) ───────────── */
#define LIST_FOREACH_SAFE(var, head, field, tvar)                              \
  for ((var) = LIST_FIRST((head));                                             \
       (var) && ((tvar) = LIST_NEXT((var), field), 1); (var) = (tvar))

#define TAILQ_FOREACH_SAFE(var, head, field, tvar)                             \
  for ((var) = TAILQ_FIRST((head));                                            \
       (var) && ((tvar) = TAILQ_NEXT((var), field), 1); (var) = (tvar))

/* ── Frame encode/decode helpers (inline, used by both sides) ─── */

/*  Build a frame into dst[].  Returns total frame length, or -1 if
 *  payload_len > FROST_MAX_PAYLOAD.
 *  dst must be at least FROST_FRAME_MAX bytes.                      */
static inline int frost_encode_frame(uint8_t *dst, frost_msg_t type,
                                     const uint8_t *payload,
                                     uint16_t payload_len) {
  if (payload_len > FROST_MAX_PAYLOAD)
    return -1;
  dst[0] = (uint8_t)type;
  dst[1] = (uint8_t)(payload_len >> 8);
  dst[2] = (uint8_t)(payload_len & 0xFF);
  if (payload && payload_len > 0)
    memcpy(dst + FROST_FRAME_HDR, payload, payload_len);
  return FROST_FRAME_HDR + payload_len;
}

/*  Decode header from the first 3 bytes of buf.
 *  Returns payload length, sets *type_out.                          */
static inline uint16_t frost_decode_header(const uint8_t *buf,
                                           frost_msg_t *type_out) {
  *type_out = (frost_msg_t)buf[0];
  return (uint16_t)(((uint16_t)buf[1] << 8) | buf[2]);
}

/* ── Queue a pre-encoded frame for sending ────────────────────── */
/* Works for any struct that has a TAILQ_HEAD msgq and want_write   */
#define frost_queue_frame(c_ptr, frame_bytes, frame_len)                       \
  do {                                                                         \
    struct outmsg *_m = malloc(sizeof(struct outmsg));                         \
    if (_m) {                                                                  \
      _m->data = malloc((frame_len));                                          \
      if (_m->data) {                                                          \
        memcpy(_m->data, (frame_bytes), (frame_len));                          \
        _m->len = (frame_len);                                                 \
        _m->sent = 0;                                                          \
        TAILQ_INSERT_TAIL(&(c_ptr)->msgq, _m, entries);                        \
      } else {                                                                 \
        free(_m);                                                              \
      }                                                                        \
    }                                                                          \
  } while (0)

#endif /* FROST_COMMON_H */

#pragma GCC diagnostic pop
