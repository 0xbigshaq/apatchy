/*
 * @description: Simple APR URI parser harness - parses fuzz input as a URI string
 */
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "apr_general.h"
#include "apr_pools.h"
#include "apr_uri.h"

// Basic AFL/LibFuzzer entry point
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size == 0)
        return 0;

    // Initialize APR if needed (do once)
    static int initialized = 0;
    if (!initialized) {
        if (apr_initialize() != APR_SUCCESS) {
            return 0;
        }
        initialized = 1;
    }

    apr_pool_t *pool;
    if (apr_pool_create(&pool, NULL) != APR_SUCCESS) {
        return 0;
    }

    // Trivial usage of Apache/APR function to prove linking
    // Parse the input as a URI
    char *str = malloc(size + 1);
    if (!str) {
        apr_pool_destroy(pool);
        return 0;
    }

    memcpy(str, data, size);
    str[size] = '\0';

    apr_uri_t uri;
    apr_uri_parse(pool, str, &uri);

    free(str);
    apr_pool_destroy(pool);

    return 0;
}

// main() for all build modes:
// - AFL: reads from stdin (AFL feeds input via stdin by default)
//   Uses __AFL_LOOP for persistent mode when available.
// - Standalone: runs with dummy data for verification.
// - LibFuzzer: compiled with -fsanitize=fuzzer which provides its own main().
//
// When linking against Apache's libmain.a, this main() coexists via -z muldefs.
// Our main() is an object file so it wins over the archive's main.o.
#ifndef LIBFUZZER_MODE
#include <unistd.h>

#ifndef __AFL_LOOP
#define __AFL_LOOP(x) 1
#endif

int main(int argc, char **argv)
{
    uint8_t buf[1024 * 64]; // 64KB max input

    while (__AFL_LOOP(10000)) {
        ssize_t n = read(0, buf, sizeof(buf));
        if (n <= 0)
            break;
        LLVMFuzzerTestOneInput(buf, (size_t)n);
    }
    return 0;
}
#endif
