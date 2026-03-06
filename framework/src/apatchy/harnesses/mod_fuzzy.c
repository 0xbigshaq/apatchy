/*
 * @description: mod_fuzzy harness - single request per fuzz input
 *
 * Processes one fuzz input as a single HTTP request through Apache's
 * full request handling pipeline. See fuzz_common.c for shared infrastructure.
 */

#include "fuzz_common.h"

#include "httpd.h"
#include "apr.h"
#include "apr_general.h"
#include "apr_getopt.h"
#include "apr_pools.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* ----------------------------------------------------------------
 * Stdin reading helper (used by AFL non-persistent and standalone)
 * ---------------------------------------------------------------- */

static int read_stdin_and_process(void)
{
    char buf[4096];
    apr_size_t total = 0;
    apr_size_t capacity = 16384;
    ssize_t n;
    char *input_buf;

    input_buf = apr_palloc(g_pool, capacity);

    while ((n = read(STDIN_FILENO, buf, sizeof(buf))) > 0) {
        if (total + n > capacity) {
            apr_size_t new_capacity = capacity * 2;
            char *new_data = apr_palloc(g_pool, new_capacity);
            memcpy(new_data, input_buf, total);
            input_buf = new_data;
            capacity = new_capacity;
        }
        memcpy(input_buf + total, buf, n);
        total += n;
    }

    if (n < 0) {
        fprintf(stderr, "Failed to read stdin\n");
        return -1;
    }

    if (total == 0) {
        fprintf(stderr, "No input data\n");
        return -1;
    }

    fuzz_one_input(input_buf, total);
    return 0;
}

/* ----------------------------------------------------------------
 * Entry points
 * ---------------------------------------------------------------- */

#ifdef LIBFUZZER

static int g_init_failed = 0;

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    static int init_done = 0;

    if (g_init_failed) {
        return 0;
    }

    if (!init_done) {
        const char *conf = getenv("FUZZ_CONF");
        const char *root = getenv("FUZZ_ROOT");

        if (!conf)
            conf = "fuzz.conf";
        if (!root)
            root = ".";

        if (fuzz_init(conf, root) < 0) {
            fprintf(stderr, "Fuzzer initialization failed\n");
            g_init_failed = 1;
            _exit(1);
        }
        init_done = 1;
    }

    fuzz_one_input((const char *)data, size);
    return 0;
}

#elif defined(AFL_FUZZ)

#ifdef __AFL_HAVE_MANUAL_CONTROL
__AFL_FUZZ_INIT();
#endif

int main(int argc, const char *const argv[])
{
    const char *conf = getenv("FUZZ_CONF");
    const char *root = getenv("FUZZ_ROOT");

    if (!conf)
        conf = "fuzz.conf";
    if (!root)
        root = ".";

    apr_status_t rv = apr_app_initialize(&argc, &argv, NULL);
    if (rv != APR_SUCCESS) {
        fprintf(stderr, "apr_app_initialize failed\n");
        return 1;
    }

    if (fuzz_init(conf, root) < 0) {
        fprintf(stderr, "Fuzzer initialization failed\n");
        return 1;
    }

#ifdef __AFL_HAVE_MANUAL_CONTROL
    __AFL_INIT();

    unsigned char *buf = __AFL_FUZZ_TESTCASE_BUF;

    if (__AFL_LOOP(10000)) {
        /* Running under afl-fuzz: use shared-memory test cases. */
        do {
            int len = __AFL_FUZZ_TESTCASE_LEN;
            if (len > 0) {
                fuzz_one_input((const char *)buf, len);
            }
        } while (__AFL_LOOP(10000));
    } else {
        /* Not under afl-fuzz (standalone triage): read from stdin. */
        read_stdin_and_process();
    }
#else
    read_stdin_and_process();
#endif

    /* Flush the HTTP response written by the output filter before
     * pool/APR teardown (which may call _exit internally). */
    fflush(stdout);

    apr_pool_destroy(g_pool);
    apr_terminate();

    return 0;
}

#else /* Standalone */

int main(int argc, const char *const argv[])
{
    apr_status_t rv;
    apr_pool_t *pcommands;
    apr_getopt_t *opt;
    const char *confname = NULL;
    const char *def_server_root = HTTPD_ROOT;
    char c;
    const char *opt_arg;

    rv = apr_app_initialize(&argc, &argv, NULL);
    if (rv != APR_SUCCESS) {
        fprintf(stderr, "apr_app_initialize failed\n");
        return 1;
    }

    apr_pool_create(&pcommands, NULL);
    apr_getopt_init(&opt, pcommands, argc, argv);
    while ((rv = apr_getopt(opt, "d:f:", &c, &opt_arg)) == APR_SUCCESS) {
        switch (c) {
        case 'd':
            def_server_root = opt_arg;
            break;
        case 'f':
            confname = opt_arg;
            break;
        }
    }
    apr_pool_destroy(pcommands);
    apr_terminate();

    if (fuzz_init(confname, def_server_root) < 0) {
        return 1;
    }

    if (read_stdin_and_process() < 0) {
        fuzz_exit(1);
    }

    /* fuzz_init() calls ap_run_child_init() which some modules (e.g.
     * mod_watchdog) use to spawn background threads.  Those threads sit
     * in an infinite loop waiting for work signals that never arrive in
     * the harness because there is no real MPM event loop driving them.
     *
     * The normal cleanup path - apr_pool_destroy() / apr_terminate() -
     * tries to pthread_join() those threads, which blocks forever
     * (main waits for threads, threads wait for work => deadlock).
     *
     * _exit() terminates the process immediately at the OS level,
     * tearing down all threads and memory without going through the
     * pool/APR cleanup.  This is safe here because the harness is a
     * short-lived, single-request process with no persistent state to
     * flush.
     *
     * TODO: can we fix this in a cleaner way?  Possible ideas:
     *   - Selectively disable modules that spawn threads (mod_watchdog)
     *   - Signal the background threads to shut down before cleanup
     *   - Skip ap_run_child_init() and manually init only what we need
     */
    fuzz_exit(0);
}

#endif /* LIBFUZZER / AFL_FUZZ */
