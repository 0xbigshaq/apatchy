/*
 * @description: Multi-request pipeline harness - processes multiple requests per fuzz input
 *
 * Like full_pipeline, but splits fuzz input on null bytes (\x00) and
 * processes each segment as a separate connection. This exercises
 * cross-connection state: sessions, connection cleanup, per-conn isolation.
 *
 * Input format: request1\x00request2\x00request3
 * (within each segment, HTTP pipelining works normally)
 *
 * See fuzz_common.c for shared infrastructure.
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
 * Multi-request splitting
 * ---------------------------------------------------------------- */

#define MAX_REQUESTS_PER_INPUT 16

static int fuzz_multi_input(const char *data, size_t size)
{
    const char *p = data;
    const char *end = data + size;
    int count = 0;

    while (p < end && count < MAX_REQUESTS_PER_INPUT) {
        const char *sep = memchr(p, '\0', end - p);
        size_t seg_len;

        if (sep) {
            seg_len = sep - p;
        } else {
            seg_len = end - p;
        }

        if (seg_len > 0) {
            fuzz_one_input(p, seg_len);
            count++;
        }

        p += seg_len + 1;
    }

    return 0;
}

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

    fuzz_multi_input(input_buf, total);
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

        if (!conf) conf = "fuzz.conf";
        if (!root) root = ".";

        if (fuzz_init(conf, root) < 0) {
            fprintf(stderr, "Fuzzer initialization failed\n");
            g_init_failed = 1;
            _exit(1);
        }
        init_done = 1;
    }

    fuzz_multi_input((const char *)data, size);
    return 0;
}

#elif defined(AFL_FUZZ)

#ifdef __AFL_HAVE_MANUAL_CONTROL
  __AFL_FUZZ_INIT();
#endif

int main(int argc, const char * const argv[])
{
    const char *conf = getenv("FUZZ_CONF");
    const char *root = getenv("FUZZ_ROOT");

    if (!conf) conf = "fuzz.conf";
    if (!root) root = ".";

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

    while (__AFL_LOOP(10000)) {
        int len = __AFL_FUZZ_TESTCASE_LEN;
        if (len > 0) {
            fuzz_multi_input((const char *)buf, len);
        }
    }
#else
    read_stdin_and_process();
#endif

    apr_pool_destroy(g_pool);
    apr_terminate();

    return 0;
}

#else /* Standalone */

int main(int argc, const char * const argv[])
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
        return 1;
    }

    apr_pool_destroy(g_pool);
    apr_terminate();

    return 0;
}

#endif /* LIBFUZZER / AFL_FUZZ */
