#include "checkpoint.h"

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

static FILE *g_log = NULL;
static double g_start[CHECKPOINT_MAX_IDS];
static int g_in_use[CHECKPOINT_MAX_IDS];
static int g_initialized = 0;
static char g_label[64] = "";
static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;

/* Must be called with g_lock held. Populates g_label on first use:
 * explicit checkpoint_set_label() wins if already called, otherwise
 * CHECKPOINT_LABEL env var, otherwise "pid<PID>". */
static void checkpoint_ensure_label_locked(void) {
  if (g_label[0] != '\0')
    return;

  const char *env = getenv("CHECKPOINT_LABEL");
  if (env && env[0] != '\0') {
    snprintf(g_label, sizeof(g_label), "%s", env);
  } else {
    snprintf(g_label, sizeof(g_label), "pid%d", (int)getpid());
  }
}

/* Writes an ISO-8601 wall-clock timestamp with millisecond precision,
 * e.g. "2026-07-20T18:04:12.345Z", so lines from multiple processes
 * can be sorted into one merged timeline later. */
static void checkpoint_timestamp(char *buf, size_t bufsz) {
  struct timespec rt;
  clock_gettime(CLOCK_REALTIME, &rt);

  struct tm tmv;
  gmtime_r(&rt.tv_sec, &tmv);

  int ms = (int)(rt.tv_nsec / 1000000);
  char tmp[48];
  snprintf(tmp, sizeof(tmp), "%04d-%02d-%02dT%02d:%02d:%02d.%03dZ",
           tmv.tm_year + 1900, tmv.tm_mon + 1, tmv.tm_mday, tmv.tm_hour,
           tmv.tm_min, tmv.tm_sec, ms);
  snprintf(buf, bufsz, "%s", tmp);
}

static void checkpoint_close_locked(void) {
  if (g_log && g_log != stderr) {
    fclose(g_log);
  }
  g_log = NULL;
}

static void checkpoint_atexit(void) {
  pthread_mutex_lock(&g_lock);
  checkpoint_close_locked();
  pthread_mutex_unlock(&g_lock);
}

/* Lazily open the default log if nobody called checkpoint_init(). */
static void checkpoint_ensure_init_locked(void) {
  if (g_initialized)
    return;

  g_log = fopen("checkpoint.log", "a");
  if (!g_log) {
    fprintf(stderr,
            "[checkpoint] could not open checkpoint.log, using stderr\n");
    g_log = stderr;
  }
  memset(g_in_use, 0, sizeof(g_in_use));
  checkpoint_ensure_label_locked();
  g_initialized = 1;
  atexit(checkpoint_atexit);
}

void checkpoint_set_label(const char *label) {
  pthread_mutex_lock(&g_lock);
  if (label && label[0] != '\0') {
    snprintf(g_label, sizeof(g_label), "%s", label);
  }
  pthread_mutex_unlock(&g_lock);
}

void checkpoint_init(const char *log_path) {
  pthread_mutex_lock(&g_lock);
  checkpoint_close_locked();

  if (log_path == NULL) {
    g_log = stderr;
  } else {
    g_log = fopen(log_path, "a");
    if (!g_log) {
      fprintf(stderr, "[checkpoint] could not open '%s', using stderr\n",
              log_path);
      g_log = stderr;
    }
  }

  memset(g_in_use, 0, sizeof(g_in_use));
  checkpoint_ensure_label_locked();
  if (!g_initialized) {
    atexit(checkpoint_atexit);
  }
  g_initialized = 1;
  pthread_mutex_unlock(&g_lock);
}

void checkpoint_shutdown(void) {
  pthread_mutex_lock(&g_lock);
  checkpoint_close_locked();
  g_initialized = 0;
  pthread_mutex_unlock(&g_lock);
}

void checkpoint_in_impl(int id, const char *name, const char *file, int line) {
  double t = now_ms();

  pthread_mutex_lock(&g_lock);
  checkpoint_ensure_init_locked();

  if (id < 0 || id >= CHECKPOINT_MAX_IDS) {
    fprintf(stderr, "[checkpoint] id %d out of range (max %d) at %s:%d\n", id,
            CHECKPOINT_MAX_IDS, file, line);
    pthread_mutex_unlock(&g_lock);
    return;
  }

  if (g_in_use[id]) {
    char ts[48];
    checkpoint_timestamp(ts, sizeof(ts));
    fprintf(g_log,
            "%s [%s] WARNING: check_in(%s) called again before matching "
            "check_out, overwriting start time (%s:%d)\n",
            ts, g_label, name, file, line);
  }

  g_start[id] = t;
  g_in_use[id] = 1;
  pthread_mutex_unlock(&g_lock);
}

void checkpoint_out_impl(int id, const char *name, const char *file, int line) {
  double t = now_ms();

  pthread_mutex_lock(&g_lock);
  checkpoint_ensure_init_locked();

  if (id < 0 || id >= CHECKPOINT_MAX_IDS) {
    fprintf(stderr, "[checkpoint] id %d out of range (max %d) at %s:%d\n", id,
            CHECKPOINT_MAX_IDS, file, line);
    pthread_mutex_unlock(&g_lock);
    return;
  }

  char ts[48];
  checkpoint_timestamp(ts, sizeof(ts));

  if (!g_in_use[id]) {
    fprintf(g_log,
            "%s [%s] WARNING: check_out(%s) called with no matching "
            "check_in (%s:%d)\n",
            ts, g_label, name, file, line);
    fflush(g_log);
    pthread_mutex_unlock(&g_lock);
    return;
  }

  double dt = t - g_start[id];
  g_in_use[id] = 0;

  fprintf(g_log, "%s [%s] %s: %.3f ms (%s:%d)\n", ts, g_label, name, dt, file,
          line);
  fflush(g_log);

  pthread_mutex_unlock(&g_lock);
}
