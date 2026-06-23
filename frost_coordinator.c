/* frost_coordinator.c — FROST DKG coordinator / relay server.
 *
 * Mirrors directoryServer5.c in structure:
 *   - single-process, select()-based event loop
 *   - GnuTLS for all connections (same LOOP_CHECK / GNUTLS_E_AGAIN pattern)
 *   - BSD sys/queue linked lists for signer tracking
 *   - staged_connection → signer promotion on HELLO handshake
 *
 * Protocol roles:
 *   1. Each signer connects, sends FROST_MSG_HELLO with its parameters.
 *   2. Once n signers are registered, coordinator broadcasts START_DKG.
 *   3. Coordinator relays all DKG round-1 packages (broadcast).
 *   4. Coordinator relays DKG round-2 packages (unicast by target ID).
 *   5. On SIGN_REQ (from stdin or external trigger), coordinator
 *      collects commitments then assembles and relays the signing package.
 *   6. Coordinator collects signature shares and calls the Rust FROST
 *      signer binary (via popen) to aggregate — or simply relays shares
 *      to a designated aggregator signer.
 *
 * Compile:
 *   gcc -g -std=c99 -Wall -Wextra -o frost_coordinator frost_coordinator.c \
 *       -lgnutls
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

/* ── Per-signer state ─────────────────────────────────────────── */
struct signer {
  gnutls_session_t session;
  int sockfd;
  struct sockaddr_in addr;

  uint16_t id; /* assigned 1..n                   */
  uint16_t n;  /* total signers declared at HELLO  */
  uint16_t t;  /* threshold declared at HELLO      */

  /* Inbound reassembly — we accumulate FROST_FRAME_MAX bytes then parse */
  uint8_t inbuf[FROST_FRAME_MAX];
  uint8_t *inptr; /* next write position in inbuf     */

  /* Outbound queue */
  TAILQ_HEAD(, outmsg) msgq;
  int want_write;

  /* Per-signer DKG material (opaque postcard blobs) */
  uint8_t r1_pkg[FROST_MAX_PAYLOAD]; /* round-1 pkg bytes */
  uint16_t r1_len;
  int r2_complete;                   /* 1 when signer sent R2_COMPLETE  */
  uint8_t commit[FROST_MAX_PAYLOAD]; /* signing commitment */
  uint16_t commit_len;
  uint8_t sig_share[FROST_MAX_PAYLOAD];
  uint16_t sig_share_len;

  LIST_ENTRY(signer) entries;
};

/* ── Staged connection (TLS done, identity not yet known) ──────── */
struct staged_conn {
  gnutls_session_t session;
  int sockfd;
  struct sockaddr_in addr;
  uint8_t inbuf[FROST_FRAME_MAX];
  uint8_t *inptr;
  TAILQ_HEAD(, outmsg) msgq;
  int want_write;
  LIST_ENTRY(staged_conn) entries;
};

LIST_HEAD(signerlist, signer);
LIST_HEAD(stagedlist, staged_conn);

/* ── Global DKG session state ─────────────────────────────────── */
static dkg_state_t g_dkg_state = DKG_IDLE;
static uint16_t g_n = 0;                 /* agreed total signers              */
static uint16_t g_t = 0;                 /* agreed threshold                  */
static uint16_t g_next_id = 1;           /* next signer ID to assign          */
static uint8_t g_tbs[FROST_MAX_PAYLOAD]; /* To Be Signed buffer               */
static uint16_t g_tbs_len = 0;           /* tbs length                        */
static uint8_t g_signing_pkg[FROST_MAX_PAYLOAD];
static uint16_t g_signing_pkg_len = 0;
static uint8_t g_pub_key_pkg[FROST_MAX_PAYLOAD];
static uint16_t g_pub_key_pkg_len = 0;

/* ── Forward declarations ─────────────────────────────────────── */
static void signer_queue_frame(struct signer *sg, frost_msg_t type,
                               const uint8_t *payload, uint16_t plen);
static void staged_queue_frame(struct staged_conn *st, frost_msg_t type,
                               const uint8_t *payload, uint16_t plen);
static void remove_signer(struct signerlist *list, struct signer *sg);
static void remove_staged(struct stagedlist *list, struct staged_conn *st);
static void drain_signer_write(struct signer *sg, struct signerlist *list);
static void drain_staged_write(struct staged_conn *st, struct stagedlist *list);
static void process_signer_frame(struct signerlist *list, struct signer *sg,
                                 frost_msg_t type, const uint8_t *payload,
                                 uint16_t plen);
static void maybe_start_dkg(struct signerlist *list);
static void relay_r1_to_all(struct signerlist *list, struct signer *sender);
static void relay_r2_to_target(struct signerlist *list, uint16_t target_id,
                               const uint8_t *payload, uint16_t plen);
static void maybe_broadcast_signing_pkg(struct signerlist *list,
                                        const uint8_t *tbs, uint16_t tbs_len);
static void maybe_aggregate(struct signerlist *list);

/* ═══════════════════════════════════════════════════════════════ */
int main(void) {
  /* ── Init GnuTLS ──────────────────────────────────────────── */
  gnutls_certificate_credentials_t x509_cred;
  gnutls_global_init();
  gnutls_certificate_allocate_credentials(&x509_cred);
  gnutls_certificate_set_x509_trust_file(x509_cred, FROST_CAFILE,
                                         GNUTLS_X509_FMT_PEM);
  if (gnutls_certificate_set_x509_key_file(x509_cred, FROST_COORD_CERT,
                                           FROST_COORD_KEY,
                                           GNUTLS_X509_FMT_PEM) < 0) {
    fprintf(stderr, "coordinator: failed to load cert/key\n");
    return EXIT_FAILURE;
  }

  /* ── Create listening socket ──────────────────────────────── */
  int listenfd;
  struct sockaddr_in serv_addr;

  if ((listenfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
    perror("coordinator: socket");
    return EXIT_FAILURE;
  }
  int yes = 1;
  setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));

  memset(&serv_addr, 0, sizeof(serv_addr));
  serv_addr.sin_family = AF_INET;
  serv_addr.sin_addr.s_addr = inet_addr(FROST_COORD_HOST);
  serv_addr.sin_port = htons(FROST_COORD_PORT);

  if (bind(listenfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
    perror("coordinator: bind");
    close(listenfd);
    return EXIT_FAILURE;
  }
  listen(listenfd, FROST_MAX_SIGNERS + 4);
  printf("coordinator: listening on %s:%d\n", FROST_COORD_HOST,
         FROST_COORD_PORT);

  /* ── Peer lists ───────────────────────────────────────────── */
  struct signerlist signers;
  struct stagedlist staged;
  LIST_INIT(&signers);
  LIST_INIT(&staged);

  /* ── Event loop ───────────────────────────────────────────── */
  for (;;) {
    fd_set readset, writeset;
    int max_fd;
    FD_ZERO(&readset);
    FD_ZERO(&writeset);

    /* listening socket always readable */
    FD_SET(listenfd, &readset);
    max_fd = listenfd;

    /* stdin for manual SIGN_REQ trigger during testing */
    FD_SET(STDIN_FILENO, &readset);

    /* signers */
    struct signer *sg, *tmp_sg;
    LIST_FOREACH_SAFE(sg, &signers, entries, tmp_sg) {
      if (sg->sockfd < 0)
        continue;
      if (sg->want_write || !TAILQ_EMPTY(&sg->msgq))
        FD_SET(sg->sockfd, &writeset);
      else
        FD_SET(sg->sockfd, &readset);
      if (sg->sockfd > max_fd)
        max_fd = sg->sockfd;
    }

    /* staged connections */
    struct staged_conn *st, *tmp_st;
    LIST_FOREACH_SAFE(st, &staged, entries, tmp_st) {
      if (st->sockfd < 0)
        continue;
      if (st->want_write || !TAILQ_EMPTY(&st->msgq))
        FD_SET(st->sockfd, &writeset);
      else
        FD_SET(st->sockfd, &readset);
      if (st->sockfd > max_fd)
        max_fd = st->sockfd;
    }

    struct timeval tv = {.tv_sec = 0, .tv_usec = 500000};
    int sel = select(max_fd + 1, &readset, &writeset, NULL, &tv);
    if (sel < 0) {
      if (errno == EINTR)
        continue;
      perror("coordinator: select");
      break;
    }
    if (sel == 0)
      continue;

    /* ── stdin: manual signing trigger ───────────────────── */
    if (FD_ISSET(STDIN_FILENO, &readset)) {
      char line[FROST_FRAME_MAX];
      if (fgets(line, sizeof(line), stdin)) {
        /* strip newline */
        line[strcspn(line, "\n")] = '\0';
        if (strncmp(line, "SIGN ", 5) == 0) {
          /* rest of line is hex TBS bytes */
          const char *hex = line + 5;
          size_t hexlen = strlen(hex);
          uint16_t tbslen = (uint16_t)(hexlen / 2);
          uint8_t tbs[FROST_MAX_PAYLOAD];
          for (uint16_t i = 0; i < tbslen && i < FROST_MAX_PAYLOAD; i++) {
            unsigned int byte;
            if (sscanf(hex + 2 * i, "%02x", &byte) == 1)
              tbs[i] = (uint8_t)byte;
          }
          maybe_broadcast_signing_pkg(&signers, tbs, tbslen);
        } else {
          fprintf(stderr, "coordinator: unknown command '%s'\n", line);
          fprintf(stderr, "  use: SIGN <hex-encoded TBS bytes>\n");
        }
      }
    }

    /* ── Accept new TCP connection ────────────────────────── */
    if (FD_ISSET(listenfd, &readset)) {
      struct sockaddr_in cli_addr;
      socklen_t clilen = sizeof(cli_addr);
      int newsock = accept(listenfd, (struct sockaddr *)&cli_addr, &clilen);
      if (newsock < 0) {
        perror("coordinator: accept");
      } else {
        /* non-blocking */
        if (fcntl(newsock, F_SETFL, O_NONBLOCK) < 0) {
          perror("fcntl O_NONBLOCK");
          close(newsock);
          goto accept_done;
        }

        /* TLS handshake */
        gnutls_session_t sess;
        gnutls_init(&sess, GNUTLS_SERVER);
        gnutls_credentials_set(sess, GNUTLS_CRD_CERTIFICATE, x509_cred);
        gnutls_certificate_server_set_request(sess, GNUTLS_CERT_IGNORE);
        gnutls_handshake_set_timeout(sess, GNUTLS_DEFAULT_HANDSHAKE_TIMEOUT);
        gnutls_priority_set_direct(sess, "NORMAL", NULL);
        gnutls_transport_set_int(sess, newsock);

        int ret = gnutls_handshake(sess);
        if (ret == GNUTLS_E_AGAIN || ret == GNUTLS_E_INTERRUPTED) {
          fprintf(stderr, "coordinator: handshake interrupted, dropping\n");
          gnutls_deinit(sess);
          close(newsock);
          goto accept_done;
        }
        if (ret < 0) {
          fprintf(stderr, "coordinator: handshake failed: %s\n",
                  gnutls_strerror(ret));
          gnutls_deinit(sess);
          close(newsock);
          goto accept_done;
        }
        printf("coordinator: TLS handshake done with %s\n",
               inet_ntoa(cli_addr.sin_addr));

        struct staged_conn *new_st = malloc(sizeof(*new_st));
        if (!new_st) {
          gnutls_deinit(sess);
          close(newsock);
          goto accept_done;
        }
        new_st->session = sess;
        new_st->sockfd = newsock;
        new_st->addr = cli_addr;
        new_st->inptr = new_st->inbuf;
        new_st->want_write = 0;
        TAILQ_INIT(&new_st->msgq);
        LIST_INSERT_HEAD(&staged, new_st, entries);
        printf("coordinator: staged connection %d from %s\n", newsock,
               inet_ntoa(cli_addr.sin_addr));
      }
    }
  accept_done:;

    /* ── Service staged connections ───────────────────────── */
    LIST_FOREACH_SAFE(st, &staged, entries, tmp_st) {

      if (FD_ISSET(st->sockfd, &writeset)) {
        drain_staged_write(st, &staged);
        /* st may be freed; next iteration is safe via FOREACH_SAFE */
        continue;
      }

      if (!FD_ISSET(st->sockfd, &readset))
        continue;

      /* read into inbuf */
      int ret = gnutls_record_recv(st->session, st->inptr,
                                   (st->inbuf + FROST_FRAME_MAX) - st->inptr);
      if (ret == GNUTLS_E_AGAIN || ret == GNUTLS_E_INTERRUPTED) {
        st->want_write = gnutls_record_get_direction(st->session);
        continue;
      }
      if (ret <= 0) {
        fprintf(stderr, "coordinator: staged %d disconnected\n", st->sockfd);
        remove_staged(&staged, st);
        continue;
      }
      st->inptr += ret;

      /* need full header first */
      if ((st->inptr - st->inbuf) < FROST_FRAME_HDR)
        continue;

      frost_msg_t msg_type;
      uint16_t plen = frost_decode_header(st->inbuf, &msg_type);

      /* wait until we have the full frame */
      if ((st->inptr - st->inbuf) < (int)(FROST_FRAME_HDR + plen))
        continue;

      /* reset for next frame */
      st->inptr = st->inbuf;

      if (msg_type != FROST_MSG_HELLO) {
        fprintf(stderr, "coordinator: unexpected msg 0x%02x from staged %d\n",
                (unsigned)msg_type, st->sockfd);
        remove_staged(&staged, st);
        continue;
      }

      /* parse HELLO payload: "SIGNER <n> <t>\n" */
      char hellobuf[64];
      uint16_t pn = 0, pt = 0;
      size_t copy_len = plen < 63 ? plen : 63;
      memcpy(hellobuf, st->inbuf + FROST_FRAME_HDR, copy_len);
      hellobuf[copy_len] = '\0';

      if (sscanf(hellobuf, "SIGNER %hu %hu", &pn, &pt) != 2 || pn < 2 ||
          pt < 1 || pt > pn || pn > FROST_MAX_SIGNERS) {
        fprintf(stderr, "coordinator: bad HELLO from staged %d: '%s'\n",
                st->sockfd, hellobuf);
        const uint8_t *errmsg = (const uint8_t *)"bad HELLO parameters";
        staged_queue_frame(st, FROST_MSG_ERROR, errmsg,
                           (uint16_t)strlen((char *)errmsg));
        continue;
      }

      /* check consistency if n/t already fixed by a prior signer */
      if (g_n == 0) {
        g_n = pn;
        g_t = pt;
      } else if (pn != g_n || pt != g_t) {
        fprintf(stderr, "coordinator: n/t mismatch from staged %d\n",
                st->sockfd);
        const uint8_t *errmsg = (const uint8_t *)"n/t mismatch";
        staged_queue_frame(st, FROST_MSG_ERROR, errmsg,
                           (uint16_t)strlen((char *)errmsg));
        continue;
      }

      /* promote to signer */
      struct signer *new_sg = malloc(sizeof(*new_sg));
      if (!new_sg) {
        remove_staged(&staged, st);
        continue;
      }

      new_sg->session = st->session;
      new_sg->sockfd = st->sockfd;
      new_sg->addr = st->addr;
      new_sg->id = g_next_id++;
      new_sg->n = g_n;
      new_sg->t = g_t;
      new_sg->inptr = new_sg->inbuf;
      new_sg->want_write = 0;
      new_sg->r1_len = 0;
      new_sg->commit_len = 0;
      new_sg->sig_share_len = 0;
      TAILQ_INIT(&new_sg->msgq);

      /* free staged shell (don't close its socket — transferred to new_sg) */
      {
        struct outmsg *_dm, *_dtm;
        TAILQ_FOREACH_SAFE(_dm, &st->msgq, entries, _dtm) {
          TAILQ_REMOVE(&st->msgq, _dm, entries);
          free(_dm->data);
          free(_dm);
        }
      }
      LIST_REMOVE(st, entries);
      free(st);

      LIST_INSERT_HEAD(&signers, new_sg, entries);
      printf("coordinator: signer %u registered (n=%u t=%u) from %s\n",
             new_sg->id, new_sg->n, new_sg->t,
             inet_ntoa(new_sg->addr.sin_addr));

      /* ACK with assigned ID */
      char ackbuf[32];
      int acklen = snprintf(ackbuf, sizeof(ackbuf), "ACK %u\n", new_sg->id);
      signer_queue_frame(new_sg, FROST_MSG_HELLO_ACK, (uint8_t *)ackbuf,
                         (uint16_t)acklen);

      maybe_start_dkg(&signers);
    } /* staged foreach */

    /* ── Service registered signers ───────────────────────── */
    LIST_FOREACH_SAFE(sg, &signers, entries, tmp_sg) {

      if (FD_ISSET(sg->sockfd, &writeset)) {
        drain_signer_write(sg, &signers);
        continue;
      }

      if (!FD_ISSET(sg->sockfd, &readset))
        continue;

      /* read into inbuf */
      int ret = gnutls_record_recv(sg->session, sg->inptr,
                                   (sg->inbuf + FROST_FRAME_MAX) - sg->inptr);
      if (ret == GNUTLS_E_AGAIN || ret == GNUTLS_E_INTERRUPTED) {
        sg->want_write = gnutls_record_get_direction(sg->session);
        continue;
      }
      if (ret <= 0) {
        if (ret < 0)
          fprintf(stderr, "coordinator: read error from signer %u: %s\n",
                  sg->id, gnutls_strerror(ret));
        else
          printf("coordinator: signer %u disconnected\n", sg->id);
        remove_signer(&signers, sg);
        continue;
      }
      sg->inptr += ret;

      if ((sg->inptr - sg->inbuf) < FROST_FRAME_HDR)
        continue;

      frost_msg_t msg_type;
      uint16_t plen = frost_decode_header(sg->inbuf, &msg_type);

      if ((sg->inptr - sg->inbuf) < (int)(FROST_FRAME_HDR + plen))
        continue;

      sg->inptr = sg->inbuf; /* reset for next frame */

      process_signer_frame(&signers, sg, msg_type, sg->inbuf + FROST_FRAME_HDR,
                           plen);
    } /* signer foreach */

  } /* for(;;) */

  gnutls_global_deinit();
  close(listenfd);
  return EXIT_SUCCESS;
}

/* ═══════════════════════════════════════════════════════════════
 * Static helpers
 * ═══════════════════════════════════════════════════════════════ */

static void signer_queue_frame(struct signer *sg, frost_msg_t type,
                               const uint8_t *payload, uint16_t plen) {
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
  TAILQ_INSERT_TAIL(&sg->msgq, m, entries);
}

static void staged_queue_frame(struct staged_conn *st, frost_msg_t type,
                               const uint8_t *payload, uint16_t plen) {
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
  TAILQ_INSERT_TAIL(&st->msgq, m, entries);
}

static void drain_signer_write(struct signer *sg, struct signerlist *list) {
  struct outmsg *m = TAILQ_FIRST(&sg->msgq);
  if (!m)
    return;

  int ret =
      gnutls_record_send(sg->session, m->data + m->sent, m->len - m->sent);
  if (ret == GNUTLS_E_AGAIN || ret == GNUTLS_E_INTERRUPTED) {
    sg->want_write = gnutls_record_get_direction(sg->session);
    return;
  }
  if (ret < 0) {
    fprintf(stderr, "coordinator: write error to signer %u: %s\n", sg->id,
            gnutls_strerror(ret));
    remove_signer(list, sg);
    return;
  }
  sg->want_write = 0;
  m->sent += (size_t)ret;
  if (m->sent >= m->len) {
    TAILQ_REMOVE(&sg->msgq, m, entries);
    free(m->data);
    free(m);
  }
}

static void drain_staged_write(struct staged_conn *st,
                               struct stagedlist *list) {
  struct outmsg *m = TAILQ_FIRST(&st->msgq);
  if (!m)
    return;

  int ret =
      gnutls_record_send(st->session, m->data + m->sent, m->len - m->sent);
  if (ret == GNUTLS_E_AGAIN || ret == GNUTLS_E_INTERRUPTED) {
    st->want_write = gnutls_record_get_direction(st->session);
    return;
  }
  if (ret < 0) {
    remove_staged(list, st);
    return;
  }
  st->want_write = 0;
  m->sent += (size_t)ret;
  if (m->sent >= m->len) {
    TAILQ_REMOVE(&st->msgq, m, entries);
    free(m->data);
    free(m);
    /* after sending error/reject, close staged connection */
    remove_staged(list, st);
  }
}

static void remove_signer(struct signerlist *list, struct signer *sg) {
  printf("coordinator: removing signer %u\n", sg->id);
  struct outmsg *m, *tmp;
  TAILQ_FOREACH_SAFE(m, &sg->msgq, entries, tmp) {
    TAILQ_REMOVE(&sg->msgq, m, entries);
    free(m->data);
    free(m);
  }
  gnutls_bye(sg->session, GNUTLS_SHUT_RDWR);
  gnutls_deinit(sg->session);
  close(sg->sockfd);
  LIST_REMOVE(sg, entries);
  free(sg);
}

static void remove_staged(struct stagedlist *list, struct staged_conn *st) {
  printf("coordinator: removing staged connection %d\n", st->sockfd);
  struct outmsg *m, *tmp;
  TAILQ_FOREACH_SAFE(m, &st->msgq, entries, tmp) {
    TAILQ_REMOVE(&st->msgq, m, entries);
    free(m->data);
    free(m);
  }
  gnutls_bye(st->session, GNUTLS_SHUT_RDWR);
  gnutls_deinit(st->session);
  close(st->sockfd);
  LIST_REMOVE(st, entries);
  free(st);
  (void)list;
}

/* Called when a new signer is promoted — check if we have n signers. */
static void maybe_start_dkg(struct signerlist *list) {
  if (g_dkg_state != DKG_IDLE)
    return;

  int count = 0;
  struct signer *sg, *tmp;
  LIST_FOREACH_SAFE(sg, list, entries, tmp) count++;

  if (count < (int)g_n) {
    printf("coordinator: %d/%u signers registered, waiting…\n", count, g_n);
    return;
  }

  printf("coordinator: all %u signers ready — broadcasting START_DKG\n", g_n);
  g_dkg_state = DKG_COLLECTING_R1;

  char startbuf[32];
  int startlen =
      snprintf(startbuf, sizeof(startbuf), "START_DKG %u %u\n", g_n, g_t);
  LIST_FOREACH_SAFE(sg, list, entries, tmp) {
    signer_queue_frame(sg, FROST_MSG_START_DKG, (uint8_t *)startbuf,
                       (uint16_t)startlen);
  }
}

/* Broadcast signer sg's round-1 package to every other signer. */
static void relay_r1_to_all(struct signerlist *list, struct signer *sender) {
  /* prepend sender ID so receivers know who sent it */
  uint8_t relay[FROST_MAX_PAYLOAD + 2];
  relay[0] = (uint8_t)(sender->id >> 8);
  relay[1] = (uint8_t)(sender->id & 0xFF);
  memcpy(relay + 2, sender->r1_pkg, sender->r1_len);
  uint16_t rlen = (uint16_t)(sender->r1_len + 2);

  struct signer *sg, *tmp;
  LIST_FOREACH_SAFE(sg, list, entries, tmp) {
    if (sg->id == sender->id)
      continue;
    signer_queue_frame(sg, FROST_MSG_RELAY_R1, relay, rlen);
  }
}

/* Unicast a round-2 package to the signer with the given target_id. */
static void relay_r2_to_target(struct signerlist *list, uint16_t target_id,
                               const uint8_t *payload, uint16_t plen) {
  struct signer *sg, *tmp;
  LIST_FOREACH_SAFE(sg, list, entries, tmp) {
    if (sg->id == target_id) {
      signer_queue_frame(sg, FROST_MSG_RELAY_R2, payload, plen);
      return;
    }
  }
  fprintf(stderr, "coordinator: relay_r2: target %u not found\n", target_id);
}

/* Check if all round-1 packages are in; if so, relay to everyone. */
static void check_r1_complete(struct signerlist *list) {
  int have = 0, need = (int)g_n;
  struct signer *sg, *tmp;
  LIST_FOREACH_SAFE(sg, list, entries, tmp) {
    if (sg->r1_len > 0)
      have++;
  }
  if (have < need) {
    printf("coordinator: r1 %d/%d collected\n", have, need);
    return;
  }
  printf("coordinator: all r1 packages collected — relaying\n");
  g_dkg_state = DKG_COLLECTING_R2;
  LIST_FOREACH_SAFE(sg, list, entries, tmp) { relay_r1_to_all(list, sg); }
}

/* Check if all commitments are in; if so, assemble signing package. */
static void check_commits_complete(struct signerlist *list, const uint8_t *tbs,
                                   uint16_t tbs_len) {

  /* Only assemble once — if already in SIGNING state, ignore late commits */
  if (g_dkg_state == DKG_SIGN_SENT) {
    printf("coordinator: late commit ignored — signing package already sent\n");
    return;
  }

  int have = 0;
  struct signer *sg, *tmp;
  LIST_FOREACH_SAFE(sg, list, entries, tmp) {
    if (sg->commit_len > 0)
      have++;
  }
  if (have < (int)g_t) {
    printf("coordinator: commits %d/%u collected\n", have, g_t);
    return;
  }
  printf("coordinator: %d commits collected — assembling signing package\n",
         have);

  /* Build stdin for frost_signer_core assemble:
   *   line 1: hex(tbs)
   *   line 2: t (number of commits)
   *   lines 3..t+2: "<id> <hex(commit)>"
   */
  char assemble_stdin[FROST_MAX_PAYLOAD * FROST_MAX_SIGNERS * 3];
  size_t off = 0;

  // fprintf(stdout, "%s\n", tbs);

  /* line 1: TBS hex */
  char tbs_hex[FROST_MAX_PAYLOAD * 2 + 2];
  bytes_to_hex(tbs, tbs_len, tbs_hex);
  off += (size_t)snprintf(assemble_stdin + off, sizeof(assemble_stdin) - off,
                          "%s\n", tbs_hex);

  /* line 2: t */
  off += (size_t)snprintf(assemble_stdin + off, sizeof(assemble_stdin) - off,
                          "%u\n", (unsigned)g_t);

  /* lines 3..t+2: one per participating signer */
  int sent = 0;
  LIST_FOREACH_SAFE(sg, list, entries, tmp) {
    if (sg->commit_len == 0)
      continue;
    if (sent >= (int)g_t)
      break;
    char commit_hex[FROST_MAX_PAYLOAD * 2 + 2];
    bytes_to_hex(sg->commit, sg->commit_len, commit_hex);
    off += (size_t)snprintf(assemble_stdin + off, sizeof(assemble_stdin) - off,
                            "%u %s\n", (unsigned)sg->id, commit_hex);
    sent++;
  }

  /* Write to temp file and call frost_signer_core assemble */
  char tmpfile[] = "/tmp/frost_assemble_XXXXXX";
  int tmpfd = mkstemp(tmpfile);
  if (tmpfd < 0) {
    // static uint8_t g_signing_pkg[FROST_MAX_PAYLOAD];
    // static uint16_t g_signing_pkg_len = 0;
    // static uint8_t g_pub_key_pkg[FROST_MAX_PAYLOAD];
    // static uint16_t g_pub_key_pkg_len = 0;
    perror("coordinator: mkstemp assemble");
    return;
  }
  fprintf(stderr, "coordinator: assemble stdin (%zu bytes):\n%s\n---\n", off,
          assemble_stdin);
  write(tmpfd, assemble_stdin, off);
  close(tmpfd);

  char assemble_cmd[256];
  snprintf(assemble_cmd, sizeof(assemble_cmd), FROST_CORE_BIN " assemble < %s",
           tmpfile);

  FILE *fp = popen(assemble_cmd, "r");
  if (!fp) {
    perror("coordinator: popen assemble");
    unlink(tmpfile);
    return;
  }

  char spkg_hex[FROST_MAX_PAYLOAD * 2 + 4];
  if (fgets(spkg_hex, sizeof(spkg_hex), fp) == NULL) {
    fprintf(stderr, "coordinator: assemble produced no output\n");
    pclose(fp);
    unlink(tmpfile);
    return;
  }
  pclose(fp);
  unlink(tmpfile);

  /* Decode the postcard SigningPackage bytes */
  uint8_t spkg[FROST_MAX_PAYLOAD];
  int spkg_len = hex_to_bytes(spkg_hex, spkg, FROST_MAX_PAYLOAD);
  if (spkg_len < 0) {
    fprintf(stderr, "coordinator: assemble hex decode failed\n");
    return;
  }

  memcpy(g_signing_pkg, spkg, (size_t)spkg_len);
  g_signing_pkg_len = (uint16_t)spkg_len;

  printf("coordinator: broadcasting signing package (%d bytes)\n", spkg_len);
  LIST_FOREACH_SAFE(sg, list, entries, tmp) {
    if (sg->commit_len == 0)
      continue;
    signer_queue_frame(sg, FROST_MSG_RELAY_COMMIT, spkg, (uint16_t)spkg_len);
  }
  g_dkg_state = DKG_SIGN_SENT;

  /* Build a flat signing package:
   *   [uint16_t tbs_len][tbs_bytes]
   *   [uint16_t n_commits]
   *   for each commit: [uint16_t signer_id][uint16_t commit_len][commit_bytes]
   */
  /*uint8_t spkg[FROST_MAX_PAYLOAD];
  size_t off = 0;

  spkg[off++] = (uint8_t)(tbs_len >> 8);
  spkg[off++] = (uint8_t)(tbs_len & 0xFF);
  if (off + tbs_len > FROST_MAX_PAYLOAD) {
    fprintf(stderr, "coordinator: TBS too large for signing package\n");
    return;
  }
  memcpy(spkg + off, tbs, tbs_len);
  off += tbs_len;

  uint16_t n_commits = (uint16_t)have;
  spkg[off++] = (uint8_t)(n_commits >> 8);
  spkg[off++] = (uint8_t)(n_commits & 0xFF);

  LIST_FOREACH_SAFE(sg, list, entries, tmp) {
    if (sg->commit_len == 0)
      continue;
    spkg[off++] = (uint8_t)(sg->id >> 8);
    spkg[off++] = (uint8_t)(sg->id & 0xFF);
    spkg[off++] = (uint8_t)(sg->commit_len >> 8);
    spkg[off++] = (uint8_t)(sg->commit_len & 0xFF);
    if (off + sg->commit_len > FROST_MAX_PAYLOAD)
      break;
    memcpy(spkg + off, sg->commit, sg->commit_len);
    off += sg->commit_len;
  }

  printf("coordinator: broadcasting signing package (%zu bytes)\n", off);
  LIST_FOREACH_SAFE(sg, list, entries, tmp) {
    if (sg->commit_len == 0)
      continue;
    signer_queue_frame(sg, FROST_MSG_RELAY_COMMIT, spkg, (uint16_t)off);
  }
  g_dkg_state = DKG_SIGNING;*/
}

/* Check if t signature shares are in; log aggregate trigger. */
static void maybe_aggregate(struct signerlist *list) {
  int have = 0;
  struct signer *sg, *tmp;
  LIST_FOREACH_SAFE(sg, list, entries, tmp) {
    if (sg->sig_share_len > 0)
      have++;
  }
  if (have < (int)g_t) {
    printf("coordinator: sig shares %d/%u\n", have, g_t);
    return;
  }
  printf("coordinator: %d signature shares collected -- aggregating\n", have);
  // printf("coordinator: *** relay shares to aggregator signer or invoke FROST
  // "
  //        "aggregate ***\n");
  /* In a full integration, call the Rust frost_signer binary here via popen,
   * passing all shares, and relay the final 64-byte signature back.
   * For now, log the event — the aggregator signer receives all shares
   * via RELAY_R2 and produces the final sig independently. */
  // g_dkg_state = DKG_COMPLETE;

  if (g_signing_pkg_len == 0) {
    fprintf(stderr,
            "coordinator: aggregate failed — no signing package stored\n");
    return;
  }
  if (g_pub_key_pkg_len == 0) {
    fprintf(stderr,
            "coordinator: aggregate failed — no public key package stored\n");
    return;
  }

  /* Build stdin for frost_signer_core aggregate:
   *   line 1: hex(SigningPackage)
   *   line 2: hex(PublicKeyPackage)
   *   lines 3..t+2: "<signer_id> <hex(SignatureShare)>"
   */
  char agg_stdin[FROST_MAX_PAYLOAD * FROST_MAX_SIGNERS * 3];
  size_t off = 0;

  char spkg_hex[FROST_MAX_PAYLOAD * 2 + 2];
  bytes_to_hex(g_signing_pkg, g_signing_pkg_len, spkg_hex);
  off += (size_t)snprintf(agg_stdin + off, sizeof(agg_stdin) - off, "%s\n",
                          spkg_hex);

  char pub_hex[FROST_MAX_PAYLOAD * 2 + 2];
  bytes_to_hex(g_pub_key_pkg, g_pub_key_pkg_len, pub_hex);
  off += (size_t)snprintf(agg_stdin + off, sizeof(agg_stdin) - off, "%s\n",
                          pub_hex);

  int sent = 0;
  LIST_FOREACH_SAFE(sg, list, entries, tmp) {
    if (sg->sig_share_len == 0)
      continue;
    if (sent >= (int)g_t)
      break;
    char share_hex[FROST_MAX_PAYLOAD * 2 + 2];
    bytes_to_hex(sg->sig_share, sg->sig_share_len, share_hex);
    off += (size_t)snprintf(agg_stdin + off, sizeof(agg_stdin) - off, "%u %s\n",
                            (unsigned)sg->id, share_hex);
    sent++;
  }

  /* Write stdin to temp file */
  char tmpfile[] = "/tmp/frost_aggregate_XXXXXX";
  int tmpfd = mkstemp(tmpfile);
  if (tmpfd < 0) {
    perror("coordinator: mkstemp aggregate");
    return;
  }
  write(tmpfd, agg_stdin, off);
  close(tmpfd);

  char agg_cmd[256];
  snprintf(agg_cmd, sizeof(agg_cmd), FROST_CORE_BIN " aggregate --t %u < %s",
           (unsigned)g_t, tmpfile);

  FILE *fp = popen(agg_cmd, "r");
  if (!fp) {
    perror("coordinator: popen aggregate");
    unlink(tmpfile);
    return;
  }

  char sig_hex[FROST_MAX_PAYLOAD * 2 + 4];
  if (fgets(sig_hex, sizeof(sig_hex), fp) == NULL) {
    fprintf(stderr, "coordinator: aggregate produced no output\n");
    pclose(fp);
    unlink(tmpfile);
    return;
  }
  pclose(fp);
  unlink(tmpfile);

  /* Decode the 64-byte signature */
  uint8_t sig[128];
  int siglen = hex_to_bytes(sig_hex, sig, sizeof(sig));
  if (siglen < 0) {
    fprintf(stderr, "coordinator: aggregate hex decode failed\n");
    return;
  }
  printf("coordinator: final signature (%d bytes): %.*s\n", siglen,
         (int)strlen(sig_hex) - 1, sig_hex);

  /* Broadcast to all signers */
  LIST_FOREACH_SAFE(sg, list, entries, tmp) {
    signer_queue_frame(sg, FROST_MSG_FINAL_SIG, sig, (uint16_t)siglen);
  }

  g_dkg_state = DKG_COMPLETE;
}

/* Count R2_COMPLETE notices; broadcast DKG_DONE when all n signers
 * have confirmed they received all round-2 packages. */
static void check_r2_complete(struct signerlist *list) {
  int have = 0;
  struct signer *sg, *tmp;
  LIST_FOREACH_SAFE(sg, list, entries, tmp) {
    if (sg->r2_complete)
      have++;
  }
  printf("coordinator: R2_COMPLETE %d/%u\n", have, g_n);
  if (have < (int)g_n)
    return;

  /* All n signers completed part3 — broadcast DKG_DONE */
  printf("coordinator: all %u signers completed r2 — broadcasting DKG_DONE\n",
         g_n);
  char donebuf[32];
  int donelen = snprintf(donebuf, sizeof(donebuf), "DKG_DONE %u\n", g_n);
  LIST_FOREACH_SAFE(sg, list, entries, tmp) {
    signer_queue_frame(sg, FROST_MSG_DKG_DONE, (uint8_t *)donebuf,
                       (uint16_t)donelen);
  }
  g_dkg_state = DKG_COMPLETE;
}

/* Broadcast a signing request to all registered signers. */
static void maybe_broadcast_signing_pkg(struct signerlist *list,
                                        const uint8_t *tbs, uint16_t tbs_len) {
  if (g_dkg_state != DKG_COMPLETE) {
    fprintf(stderr, "coordinator: SIGN_REQ ignored — DKG not complete\n");
    return;
  }

  memcpy(g_tbs, tbs, tbs_len);
  g_tbs_len = tbs_len;

  printf("coordinator: broadcasting SIGN_REQ (%u TBS bytes)\n", tbs_len);
  g_dkg_state = DKG_SIGNING;

  /* reset per-signer signing state */
  struct signer *sg, *tmp;
  LIST_FOREACH_SAFE(sg, list, entries, tmp) {
    sg->commit_len = 0;
    sg->sig_share_len = 0;
  }

  /* send SIGN_REQ with raw TBS bytes as payload */
  LIST_FOREACH_SAFE(sg, list, entries, tmp) {
    signer_queue_frame(sg, FROST_MSG_SIGN_REQ, tbs, tbs_len);
  }
}

/* Dispatch a fully-received frame from a registered signer. */
static void process_signer_frame(struct signerlist *list, struct signer *sg,
                                 frost_msg_t type, const uint8_t *payload,
                                 uint16_t plen) {

  switch (type) {

  case FROST_MSG_ROUND1_PKG:
    if (g_dkg_state != DKG_COLLECTING_R1) {
      fprintf(stderr, "coordinator: stray r1 from signer %u\n", sg->id);
      return;
    }
    if (plen > FROST_MAX_PAYLOAD) {
      fprintf(stderr, "coordinator: r1 too large\n");
      return;
    }
    memcpy(sg->r1_pkg, payload, plen);
    sg->r1_len = plen;
    printf("coordinator: r1 from signer %u (%u bytes)\n", sg->id, plen);
    check_r1_complete(list);
    break;

  case FROST_MSG_ROUND2_PKG: {
    /* payload: [uint16_t target_id][pkg_bytes...] */
    if (plen < 4) {
      fprintf(stderr, "coordinator: r2 too short\n");
      return;
    }
    uint16_t target = (uint16_t)(((uint16_t)payload[2] << 8) | payload[3]);
    printf("coordinator: r2 from signer %u → signer %u (%u bytes)\n", sg->id,
           target, (unsigned)(plen - 4));
    relay_r2_to_target(list, target, payload, plen);
    break;
  }

  case FROST_MSG_COMMIT:
    if (g_dkg_state != DKG_SIGNING) {
      fprintf(stderr, "coordinator: stray commit from signer %u\n", sg->id);
      return;
    }
    if (plen > FROST_MAX_PAYLOAD) {
      fprintf(stderr, "coordinator: commit too large\n");
      return;
    }
    memcpy(sg->commit, payload, plen);
    sg->commit_len = plen;
    printf("coordinator: commit from signer %u (%u bytes)\n", sg->id, plen);
    check_commits_complete(list, g_tbs, g_tbs_len);
    break;

  case FROST_MSG_SIG_SHARE:
    if (plen > FROST_MAX_PAYLOAD)
      return;
    memcpy(sg->sig_share, payload, plen);
    sg->sig_share_len = plen;
    printf("coordinator: sig share from signer %u (%u bytes)\n", sg->id, plen);
    maybe_aggregate(list);
    break;

  case FROST_MSG_SIGN_REQ:
    /* A signer acting as signing initiator can push a TBS blob */
    if (plen > FROST_MAX_PAYLOAD) {
      fprintf(stderr, "coordinator: TBS too large\n");
      return;
    }
    memcpy(g_tbs, payload, plen);
    g_tbs_len = plen;
    maybe_broadcast_signing_pkg(list, g_tbs, g_tbs_len);
    break;

  case FROST_MSG_R2_COMPLETE: {
    if (sg->r2_complete) {
      fprintf(stderr, "coordinator: duplicate R2_COMPLETE from signer %u\n",
              sg->id);
      break;
    }
    sg->r2_complete = 1;
    printf("coordinator: R2_COMPLETE from signer %u\n", sg->id);
    check_r2_complete(list);
    break;
  }

  case FROST_MSG_PUB_KEY_PKG:
    if (g_pub_key_pkg_len > 0)
      break; /* already have it, ignore duplicates */
    if (plen > FROST_MAX_PAYLOAD) {
      fprintf(stderr, "coordinator: pub key pkg too large\n");
      return;
    }
    memcpy(g_pub_key_pkg, payload, plen);
    g_pub_key_pkg_len = plen;
    printf("coordinator: stored PublicKeyPackage from signer %u (%u bytes)\n",
           sg->id, plen);
    break;

  default:
    fprintf(stderr, "coordinator: unknown msg type 0x%02x from signer %u\n",
            (unsigned)type, sg->id);
    break;
  }
}
