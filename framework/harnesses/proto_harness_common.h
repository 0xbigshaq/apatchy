#pragma once

#include <cstdio>
#include <cstdlib>

extern "C" {
#include "fuzz_common.h"
}

static int g_init_done = 0;
static int g_init_failed = 0;

static inline bool proto_harness_init()
{
    if (g_init_failed)
        return false;

    if (!g_init_done) {
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
        g_init_done = 1;
    }

    return true;
}
