/* frost_common.h — shared constants, message types, and ROAST structures.
 *
 * Extends the original transport layer with:
 *   - Two coordinator modes (DKG vs SIGN)
 *   - ROAST session management structures
 *   - Share-persistence paths and message types
 *   - SSH certificate output message type
 *
 * Wire format (unchanged):
 *   [uint8_t  msg_type ]
 *   [uint16_t payload_len]  big-endian
 *   [uint8_t  payload[0..payload_len]]
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
#include <sys/queue.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include "checkpoint.c"

/* ── Network ──────────────────────────────────────────────────── */
#define FROST_COORD_HOST "127.0.0.1"
#define FROST_COORD_PORT 60601

/* ── Frame sizing ─────────────────────────────────────────────── */
#define FROST_MAX_PAYLOAD 4096
#define FROST_FRAME_HDR 3
#define FROST_FRAME_MAX (FROST_FRAME_HDR + FROST_MAX_PAYLOAD)
#define FROST_MAX_SIGNERS 16

/* ── TLS certificate paths ────────────────────────────────────── */
#define FROST_CAFILE "certs/rootCA.crt"
#define FROST_COORD_CERT "certs/coordinator.crt"
#define FROST_COORD_KEY "certs/coordinatorkey.pem"
#define FROST_SIGNER1_CERT "certs/beocat.crt"
#define FROST_SIGNER1_KEY "certs/beocatkey.pem"
#define FROST_SIGNER2_CERT "certs/football.crt"
#define FROST_SIGNER2_KEY "certs/footballkey.pem"

/* ── Share persistence ────────────────────────────────────────── */
/* Each signer writes its KeyPackage (hex) to:
 *     ./shares/signer_<id>.keypkg
 * The coordinator writes the PublicKeyPackage (hex) to:
 *     ./pub_key_pkg.hex
 * (coordinator also saves frost_ca_signer_1.pub when a signer sends it)
 */
#define FROST_SHARES_DIR "shares"
#define FROST_PUB_PKG_HEX "pub_key_pkg.hex"

/* ── ROAST session tuning ─────────────────────────────────────── */
#define ROAST_MAX_SESSIONS 16
#define ROAST_SESSION_TIMEOUT_SEC 10

/* ── Checkpoint enum ids ──────────────────────────────────────── */
/* NOTE on CP_ROAST_SESSION_TOTAL: this id is intentionally NOT wired
 * to check_in()/check_out(). ROAST forms up to ROAST_MAX_SESSIONS
 * concurrent signing sessions, but the checkpoint library keeps only
 * one start-time slot per id — a second check_in() on the same id
 * before the first session's check_out() clobbers its start time.
 * Session-lifetime timing stays on the existing sess->t_formed_ms +
 * now_ms() pattern (already correct, since it's stored per-session
 * rather than in a single global slot). The id is kept here for
 * documentation/consistency with the rest of the list, not for use
 * with check_in/check_out.
 */
typedef enum {

  /* ── Shared: event loop / network (coordinator + signer) ──────            */
  CP_SELECT_BLKING_SIGNR, /* select() call each event-loop tick               */
  CP_SELECT_BLKING_COORD, /*                                                  */
  CP_TLS_HANDSHAKE, /* gnutls_handshake() — accept (coord) / connect (signer) */
  CP_TLS_RECORD_RECV, /* gnutls_record_recv()                                 */
  CP_TLS_RECORD_SEND, /* gnutls_record_send() (drain_*_write paths)           */
  CP_TEMPFILE_WRITE,  /* creating and writing mkstemp file                    */
  CP_TEMPFILE_LOAD,   /* reading mkstemp file                                 */

  /* ── Coordinator: Rust subprocess bridge (previously untimed) ── */
  CP_TBS_BASH,         /* call_tbs(): popen frost_signer_core tbs          */
  CP_TBS_PATCH_PUBKEY, /* prepare_tbs(): popen frost_signer_core pubkey    */
  CP_ASSEMBLE_BASH,    /* roast_try_form_session(): popen "assemble"       */
  CP_AGGREGATE_BASH,   /* roast_try_aggregate(): popen "aggregate"         */
  CP_MINT_BASH,        /* call_mint(): popen frost_signer_core mint        */

  /* ── Coordinator: DKG relay ───────────────────────────────────── */
  CP_DKG_RELAY_R1, /* relay_r1_to_all() broadcast loop                 */
  CP_DKG_RELAY_R2, /* relay_r2_to_target() unicast lookup+send         */

  /* ── Coordinator: ROAST session bookkeeping ──────────────────── */
  CP_COMMIT_ROUTE,       /* FROST_MSG_COMMIT handler -> triggers form_session */
  CP_ROAST_FORM_SESSION, /* roast_try_form_session(): two-pass selection scan*/
  CP_SHARE_ROUTE,        /* FROST_MSG_SIG_SHARE handler -> triggers aggregate */
  CP_ROAST_SESSION_TOTAL, /* NOT wired -- see note above                      */
  CP_SESSION_EXPIRE_SCAN, /* roast_expire_sessions(): per-tick timeout sweep  */

  /* ── Coordinator: disk I/O ────────────────────────────────────── */
  CP_PUBKEYPKG_LOAD,  /* main(): read pub_key_pkg.hex                */
  CP_PUBKEYPKG_WRITE, /* PUB_KEY_PKG / REFRESH_COMPLETE handlers writing it */

  /* ── Signer: key persistence ──────────────────────────────────── */
  CP_KEYPKG_LOAD, /* load_key_material()                              */
  CP_KEYPKG_SAVE, /* save_key_material()                              */

  /* ── Signer: startup-only identity setup ──────────────────────── */
  CP_PUBKEY_CACHE_INIT, /* init_signer_pubkey_cache(): n cert loads at boot */
  CP_VERIFY_IDENTITY,   /* verify_own_identity(): DER export + memcmp       */

  /* ── Signer: per-message crypto ────────────────────────────────── */
  CP_R2_DECRYPT,        /* gnutls_privkey_decrypt_data() on inbound r2 pkgs */
  CP_FROST_COMMIT_BASH, /* frost_commit(): popen frost_signer_core commit   */
  CP_FROST_SIGN_BASH,   /* frost_sign(): popen frost_signer_core sign       */
} cp_id_t;

/* ── Message type tags ────────────────────────────────────────── */
typedef enum {
  /* Signer → Coordinator */
  FROST_MSG_HELLO = 0x01,           /* "SIGNER <n> <t>\n"               */
  FROST_MSG_ROUND1_PKG = 0x02,      /* DKG round-1 package              */
  FROST_MSG_ROUND2_PKG = 0x03,      /* DKG round-2 package              */
  FROST_MSG_COMMIT = 0x04,          /* signing commitment               */
  FROST_MSG_SIG_SHARE = 0x05,       /* signature share                  */
  FROST_MSG_R2_COMPLETE = 0x06,     /* DKG part3 done                   */
  FROST_MSG_PUB_KEY_PKG = 0x07,     /* PublicKeyPackage from signer     */
  FROST_MSG_SHARE_LOAD_FAIL = 0x08, /* signer has no key on disk        */

  /* Coordinator → Signer */
  FROST_MSG_HELLO_ACK = 0x10,    /* "ACK <id> <mode:D|S>\n"          */
  FROST_MSG_START_DKG = 0x11,    /* "START_DKG <n> <t>\n"            */
  FROST_MSG_RELAY_R1 = 0x12,     /* relay: round-1 pkg from peer     */
  FROST_MSG_RELAY_R2 = 0x13,     /* relay: round-2 pkg for us        */
  FROST_MSG_SIGN_REQ = 0x14,     /* TBS bytes to sign                */
  FROST_MSG_RELAY_COMMIT = 0x15, /* signing package for this session */
  FROST_MSG_FINAL_SIG = 0x16,    /* aggregated signature (64 B)      */
  FROST_MSG_DKG_DONE = 0x17,     /* coordinator: all signers done    */
  FROST_MSG_CERT_OUTPUT = 0x18,  /* OpenSSH certificate text         */

  /* Coordinator → Signer (refresh mode) */
  FROST_MSG_START_REFRESH = 0x30,     /* "START_REFRESH <n> <t>\n"          */
  FROST_MSG_RELAY_REFRESH_R1 = 0x31,  /* peer's refresh round-1 package     */
  FROST_MSG_RELAY_REFRESH_R2 = 0x32,  /* refresh round-2 package for us     */
  FROST_MSG_REFRESH_FINALIZE = 0x33,  /* all r2 routed — compute new shares */
  FROST_MSG_REFRESH_CONFIRMED = 0x34, /* coordinator: all shares saved      */

  /* Signer → Coordinator (refresh mode) */
  FROST_MSG_REFRESH_R1 = 0x38,          /* refresh round-1 package            */
  FROST_MSG_REFRESH_R2 = 0x39,          /* refresh round-2 package (unicast)  */
  FROST_MSG_REFRESH_R2_COMPLETE = 0x3A, /* part2 done                         */
  FROST_MSG_REFRESH_COMPLETE = 0x3B,    /* new key saved; payload=new pub_pkg */

  /* Bidirectional */
  FROST_MSG_ERROR = 0xFF,
} frost_msg_t;

/* ── Coordinator operating mode ───────────────────────────────── */
typedef enum {
  COORD_MODE_DKG = 0,     /* generate a new shared key                  */
  COORD_MODE_SIGN = 1,    /* sign a certificate with existing key shares */
  COORD_MODE_REFRESH = 2, /* refresh shares to new security epoch */
} coord_mode_t;

/* ── DKG/signing state (both sides) ──────────────────────────── */
typedef enum {
  DKG_IDLE = 0,
  DKG_COLLECTING_R1,
  DKG_COLLECTING_R2,
  DKG_COMPLETE,
  DKG_SIGNING,
  DKG_SIGN_SENT,
} dkg_state_t;

/* ── ROAST session state ──────────────────────────────────────── */
typedef enum {
  RSESS_EMPTY = 0,       /* unused slot                            */
  RSESS_AWAITING_SHARES, /* signing pkg sent, waiting for shares   */
  RSESS_COMPLETE,        /* aggregation succeeded                  */
  RSESS_FAILED,          /* share validation failed                */
} rsess_state_t;

/* One parallel ROAST signing session. */
struct roast_session {
  uint32_t id;
  rsess_state_t state;
  time_t deadline;
  double t_formed_ms; /* CLOCK_MONOTONIC ms at formation, for timing logs */

  int n_signers; /* == g_t */
  uint16_t signer_ids[FROST_MAX_SIGNERS];

  uint8_t signing_pkg[FROST_MAX_PAYLOAD];
  uint16_t signing_pkg_len;

  uint8_t shares[FROST_MAX_SIGNERS][FROST_MAX_PAYLOAD];
  uint16_t share_lens[FROST_MAX_SIGNERS];
  int n_shares;
};

/* ── Per-signer sign-phase state (coordinator tracks) ────────── */
typedef enum {
  SPHASE_INIT = 0,        /* connected, SIGN_REQ sent                */
  SPHASE_NO_KEY = 1,      /* sent SHARE_LOAD_FAIL                    */
  SPHASE_COMMITTED = 2,   /* sent commit, not yet assigned           */
  SPHASE_IN_SESSION = 3,  /* in an active ROAST session              */
  SPHASE_SHARED = 4,      /* sent signature share                    */
  SPHASE_BLACKLISTED = 5, /* identified-abort excluded               */
  SPHASE_SUSPECT = 6,     /* signer watched for malicious silence    */
} sphase_t;

/* ── Outbound message queue node ──────────────────────────────── */
struct outmsg {
  size_t len;
  size_t sent;
  uint8_t *data;
  TAILQ_ENTRY(outmsg) entries;
};

/* ── GnuTLS helpers ───────────────────────────────────────────── */
#define LOOP_CHECK(rval, cmd)                                                  \
  do {                                                                         \
    rval = cmd;                                                                \
  } while (rval == GNUTLS_E_AGAIN || rval == GNUTLS_E_INTERRUPTED)

#define LIST_FOREACH_SAFE(var, head, field, tvar)                              \
  for ((var) = LIST_FIRST((head));                                             \
       (var) && ((tvar) = LIST_NEXT((var), field), 1); (var) = (tvar))

#define TAILQ_FOREACH_SAFE(var, head, field, tvar)                             \
  for ((var) = TAILQ_FIRST((head));                                            \
       (var) && ((tvar) = TAILQ_NEXT((var), field), 1); (var) = (tvar))

/* ── Frame helpers ────────────────────────────────────────────── */
/* ── Timing instrumentation ───────────────────────────────────────
 * now_ms() is provided by checkpoint.h (included above) — this used
 * to duplicate that definition locally, which caused a "redefinition
 * of 'now_ms'" hard error once checkpoint.h was pulled in, since
 * frost_signer.c also #includes frost_stubs.c into the same TU.
 * check_in()/check_out() (also from checkpoint.h) emit the greppable
 * per-checkpoint log lines described by the cp_id_t enum below;  the
 * ad hoc "TIMING op=..." fprintf lines elsewhere in frost_stubs.c and
 * frost_coordinator.c still use now_ms() directly and are unaffected. */

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

static inline uint16_t frost_decode_header(const uint8_t *buf,
                                           frost_msg_t *type_out) {
  *type_out = (frost_msg_t)buf[0];
  return (uint16_t)(((uint16_t)buf[1] << 8) | buf[2]);
}

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
