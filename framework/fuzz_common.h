/*
 * Shared fuzzing infrastructure for Apache pipeline harnesses.
 *
 * Provides Apache initialization, fake connection handling, and request
 * processing. Individual harness files (full_pipeline.c, multi_pipeline.c)
 * include this header and provide only their entry points.
 */

#ifndef FUZZ_COMMON_H
#define FUZZ_COMMON_H

#include <stddef.h>
#include "apr_pools.h"

/*
 * Initialize the fuzzer: APR, Apache config, hooks, modules.
 * Call once before any fuzz_one_input().
 * Returns 0 on success, -1 on failure.
 */
int fuzz_init(const char *confname, const char *server_root);

/*
 * Process one fuzz input as a single connection through Apache's pipeline.
 * Safe to call repeatedly after fuzz_init().
 */
int fuzz_one_input(const char *data, size_t size);

/*
 * Global pool - exposed for stdin reading in entry points.
 * Valid after fuzz_init() returns 0.
 */
extern apr_pool_t *g_pool;

/*
 * Exit the harness process, flushing LLVM coverage data first.
 *
 * We must use _exit() instead of return/exit() because ap_run_child_init()
 * spawns background threads (e.g. mod_watchdog) that deadlock during normal
 * cleanup.  But _exit() skips atexit handlers, which LLVM uses to write
 * .profraw coverage data.  fuzz_exit() calls __llvm_profile_write_file()
 * (if linked) to flush coverage before _exit().
 */
void fuzz_exit(int status);

#endif /* FUZZ_COMMON_H */
