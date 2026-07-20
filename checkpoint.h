/*
 * checkpoint.h - lightweight in/out timing instrumentation
 *
 * Usage:
 *
 *   typedef enum {
 *       CP_PARSE_INPUT,
 *       CP_RUN_DKG,
 *       CP_SIGN_ROUND1,
 *       CP_SIGN_ROUND2,
 *       CP_ID_COUNT        // keep last, used only for CHECKPOINT_MAX_IDS
 * sizing } my_checkpoints_t;
 *
 *   check_in(CP_RUN_DKG);
 *   ... work ...
 *   check_out(CP_RUN_DKG);   // logs "CP_RUN_DKG: 12.345 ms (file:line)"
 *
 * By default, elapsed times are appended to "checkpoint.log" in the
 * current working directory. Call checkpoint_init() once at program
 * start to choose a different path.
 *
 * Thread-safe: each id has its own slot, guarded by a single mutex.
 * Not reentrant per-id: calling check_in() twice on the same id before
 * a matching check_out() overwrites the first start time.
 *
 * Multi-process use (e.g. one signer per process): each process gets
 * its own start-time slots automatically (separate address spaces),
 * so there's no cross-signer clobbering to worry about. If several
 * such processes share one log file path, the file is opened with
 * O_APPEND, so concurrent writes from different processes cannot
 * tear a single line apart as long as each line stays under PIPE_BUF
 * (4096 bytes on Linux) -- lines from different signers may interleave
 * with each other in the file, but each individual line stays intact.
 * Use checkpoint_set_label() (or CHECKPOINT_LABEL env var) so lines
 * are attributable, and sort by the leading timestamp to reconstruct
 * a single merged timeline across processes.
 */

#ifndef CHECKPOINT_H
#define CHECKPOINT_H

/* Needed for clock_gettime()/CLOCK_MONOTONIC under strict -std=c11 etc. */
#if !defined(_POSIX_C_SOURCE) || _POSIX_C_SOURCE < 199309L
#undef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 199309L
#endif

#include <time.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Maximum number of distinct checkpoint ids supported. Raise if needed. */
#define CHECKPOINT_MAX_IDS 256

/* Monotonic clock in milliseconds, as a double. */
static inline double now_ms(void) {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (double)ts.tv_sec * 1000.0 + (double)ts.tv_nsec / 1e6;
}

/*
 * Set the log file path. Safe to call at any time; reopens the log.
 * If never called, the library lazily opens "checkpoint.log" on first
 * check_in()/check_out() call. Pass NULL to log to stderr instead.
 */
void checkpoint_init(const char *log_path);

/*
 * Set a label that is prefixed to every log line from this process,
 * e.g. checkpoint_set_label("signer-2"). Useful when several signer
 * processes append to the same shared log file.
 *
 * If never called, the label falls back to the CHECKPOINT_LABEL
 * environment variable, and if that's unset, to "pid<PID>". This
 * means a multi-process signer setup can get per-signer labels with
 * zero code changes, just by launching each binary as:
 *
 *   CHECKPOINT_LABEL=signer-1 ./signer &
 *   CHECKPOINT_LABEL=signer-2 ./signer &
 *   CHECKPOINT_LABEL=signer-3 ./signer &
 */
void checkpoint_set_label(const char *label);

/* Flush and close the log file. Optional; also runs at exit. */
void checkpoint_shutdown(void);

/* Implementation functions behind the check_in/check_out macros. */
void checkpoint_in_impl(int id, const char *name, const char *file, int line);
void checkpoint_out_impl(int id, const char *name, const char *file, int line);

/* Mark the start of a timed region for `id`. */
#define check_in(id) checkpoint_in_impl((int)(id), #id, __FILE__, __LINE__)

/* Mark the end of a timed region for `id`; logs the elapsed time. */
#define check_out(id) checkpoint_out_impl((int)(id), #id, __FILE__, __LINE__)

#ifdef __cplusplus
}
#endif

#endif /* CHECKPOINT_H */
