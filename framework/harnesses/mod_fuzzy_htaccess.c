/*
 * @description: htaccess/config parser fuzzing - raw input to directive handlers
 * @ldflags: -Wl,--wrap=exit
 *
 * Feeds raw fuzz input into Apache's config parser (ap_build_config)
 * and walks the directive tree (ap_walk_config) to exercise module
 * directive handlers.
 *
 * Uses ap_pcfg_open_custom() to feed bytes from memory without filesystem
 * access. Targets: line parsing, section nesting, directive argument parsing,
 * regex compilation, expression evaluation, numeric conversions.
 *
 * Build: apatchy link libfuzzer --harness mod_fuzzy_htaccess
 * Run:   FUZZ_CONF=htaccess.conf apatchy fuzz --engine libfuzzer
 */

#include "fuzz_common.h"

#include "ap_config.h"
#include "apr.h"
#include "apr_general.h"
#include "apr_pools.h"
#include "apr_strings.h"
#include "http_core.h"

#include "http_config.h"
#include "http_log.h"
#include "httpd.h"
#include "util_cfgtree.h"

#include <setjmp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/*
 * Some directive handlers call exit() on fatal errors (e.g. failed module
 * init). Intercept via --wrap=exit and longjmp back to the harness so the
 * fuzzer can continue with the next input.
 */
static jmp_buf g_exit_jmp;
static int g_in_harness = 0;

void __real_exit(int status);
void __wrap_exit(int status)
{
    if (g_in_harness)
        longjmp(g_exit_jmp, 1);
    __real_exit(status);
}

typedef struct {
    const char *data;
    apr_size_t size;
    apr_size_t pos;
} fuzz_cfg_ctx_t;

static apr_status_t fuzz_cfg_getstr(void *buf, apr_size_t bufsiz, void *param)
{
    fuzz_cfg_ctx_t *ctx = (fuzz_cfg_ctx_t *)param;
    char *dst = (char *)buf;
    apr_size_t i = 0;

    if (ctx->pos >= ctx->size)
        return APR_EOF;

    while (i < bufsiz - 1 && ctx->pos < ctx->size) {
        char c = ctx->data[ctx->pos++];
        dst[i++] = c;
        if (c == '\n')
            break;
    }

    dst[i] = '\0';
    return APR_SUCCESS;
}

static apr_status_t fuzz_cfg_close(void *param)
{
    return APR_SUCCESS;
}

/*
 * Pool for the current iteration. Visible at file scope so it can be
 * destroyed after a longjmp from __wrap_exit.
 */
static apr_pool_t *g_ptrans = NULL;

static void fuzz_htaccess_one(const char *data, apr_size_t size)
{
    ap_configfile_t *cfp;
    ap_directive_t *conftree = NULL;
    cmd_parms parms;
    const char *errmsg;

    fuzz_cfg_ctx_t ctx;
    ctx.data = data;
    ctx.size = size;
    ctx.pos = 0;

    cfp = ap_pcfg_open_custom(g_ptrans, ".htaccess", &ctx, NULL, fuzz_cfg_getstr, fuzz_cfg_close);

    memset(&parms, 0, sizeof(parms));
    parms.pool = g_ptrans;
    parms.temp_pool = g_ptrans;
    parms.server = g_server;
    parms.override = OR_ALL | ACCESS_CONF;
    parms.override_opts = OPT_ALL | OPT_SYM_OWNER | OPT_MULTI;
    parms.config_file = cfp;
    parms.path = apr_pstrdup(g_ptrans, "/tmp/htdocs");

    errmsg = ap_build_config(&parms, g_ptrans, g_ptrans, &conftree);
    if (errmsg || !conftree)
        return;

    parms.config_file = cfp;
    ap_walk_config(conftree, &parms, ap_create_per_dir_config(g_ptrans));
}

#ifdef LIBFUZZER

static int g_init_failed = 0;

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    static int init_done = 0;

    if (g_init_failed)
        return 0;

    if (!init_done) {
        const char *conf = getenv("FUZZ_CONF");
        const char *root = getenv("FUZZ_ROOT");

        if (!conf)
            conf = "htaccess.conf";
        if (!root)
            root = ".";

        if (fuzz_init(conf, root) < 0) {
            fprintf(stderr, "Fuzzer initialization failed\n");
            g_init_failed = 1;
            _exit(1);
        }
        init_done = 1;
    }

    apr_pool_create(&g_ptrans, g_server->process->pconf);

    g_in_harness = 1;
    if (setjmp(g_exit_jmp) == 0)
        fuzz_htaccess_one((const char *)data, size);
    g_in_harness = 0;

    apr_pool_destroy(g_ptrans);
    g_ptrans = NULL;
    return 0;
}

#else /* Standalone */

int main(int argc, const char *const argv[])
{
    char buf[4096];
    apr_size_t total = 0;
    apr_size_t capacity = 16384;
    ssize_t n;
    char *input_buf;

    apr_app_initialize(&argc, &argv, NULL);

    if (fuzz_init("htaccess.conf", ".") < 0)
        return 1;

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

    if (total == 0) {
        fprintf(stderr, "No input data\n");
        fuzz_exit(1);
    }

    fuzz_htaccess_one(input_buf, total);
    fuzz_exit(0);
}

#endif /* LIBFUZZER */
