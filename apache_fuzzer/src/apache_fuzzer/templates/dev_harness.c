/*
 * @description: Developer harness template - replace with your fuzzing logic
 */
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* APR core - always available */
#include "apr_general.h"
#include "apr_pools.h"
#include "apr_strings.h"

/* Uncomment the headers you need: */
// #include "apr_uri.h"           /* URI parsing (apr_uri_parse) */
// #include "apr_buckets.h"       /* Bucket brigades */
// #include "apr_tables.h"        /* Key-value tables */
//
// #include "httpd.h"             /* Core Apache types (request_rec, server_rec) */
// #include "http_protocol.h"     /* ap_rgetline, ap_parse_request_line */
// #include "http_config.h"       /* Configuration processing */
// #include "http_core.h"         /* Core module hooks */
// #include "http_request.h"      /* Request processing pipeline */
// #include "http_connection.h"   /* Connection handling */
// #include "http_log.h"          /* Logging */
// #include "util_filter.h"       /* Input/output filters */
// #include "ap_config.h"         /* Build configuration */

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size == 0) return 0;

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

    /* TODO: Your fuzzing logic here.
     *
     * 'data' is the fuzz input (raw bytes), 'size' is its length.
     * Use the pool for APR allocations - it's destroyed at the end.
     *
     * Example: parse input as a null-terminated string
     *   char *str = apr_pstrmemdup(pool, (const char *)data, size);
     */

    apr_pool_destroy(pool);
    return 0;
}

#ifndef LIBFUZZER_MODE
#include <unistd.h>

#ifndef __AFL_LOOP
#define __AFL_LOOP(x) 1
#endif

int main(int argc, char **argv) {
    uint8_t buf[1024 * 64];

    while (__AFL_LOOP(10000)) {
        ssize_t n = read(0, buf, sizeof(buf));
        if (n <= 0) break;   /* EOF or error - exit cleanly */
        LLVMFuzzerTestOneInput(buf, (size_t)n);
    }
    return 0;
}
#endif
