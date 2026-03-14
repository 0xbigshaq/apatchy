/*
 * @description: mod_deflate config+input fuzzing (experimental)
 *
 * Experimental harness that fuzzes both mod_deflate configuration values
 * and HTTP request payloads simultaneously.  Each fuzz input is:
 *
 *   [12-byte config seed][HTTP request]
 *
 * The config seed is decoded into mod_deflate's server and directory
 * config structs before processing the HTTP request.  After processing,
 * the original config is restored for the next iteration.
 *
 * Use with deflate_config_mutator.so for structure-aware mutation of
 * both the config seed and the HTTP payload.
 */

#include "fuzz_common.h"

#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "apr.h"
#include "apr_general.h"
#include "apr_pools.h"
#include "apr_getopt.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* Must match deflate_config_mutator.c */
#define CONFIG_SEED_SIZE 12

/* ----------------------------------------------------------------
 * mod_deflate config struct replicas
 *
 * These mirror the structs in mod_deflate.c.  We cannot include
 * mod_deflate.c directly, so we replicate the layout here.  If
 * mod_deflate's structs change, these must be updated to match.
 * ---------------------------------------------------------------- */

typedef struct {
    int windowSize;
    int memlevel;
    int compressionlevel;
    apr_size_t bufferSize;
    const char *note_ratio_name;
    const char *note_input_name;
    const char *note_output_name;
} deflate_filter_config;

typedef struct {
    apr_off_t inflate_limit;
    int ratio_limit;
    int ratio_burst;
} deflate_dirconf_t;

/* Declared in mod_deflate.c, available at link time */
extern module AP_MODULE_DECLARE_DATA deflate_module;

/* ----------------------------------------------------------------
 * Config seed decoding
 *
 * Byte layout (12 bytes):
 *   [0]       windowSize index    (mapped to -1..-15)
 *   [1]       memlevel            (mapped to 1..9)
 *   [2]       compressionlevel    (mapped to 0..9, 0 = Z_DEFAULT)
 *   [3..6]    bufferSize          (uint32_t, clamped to 64..1MB)
 *   [7..10]   inflate_limit       (uint32_t, 0 = unlimited)
 *   [11]      ratio_limit:4 | ratio_burst:4 (nibbles)
 * ---------------------------------------------------------------- */

static void
decode_config_seed(const uint8_t *seed, deflate_filter_config *sc, deflate_dirconf_t *dc)
{
    /* windowSize: mod_deflate stores this as negative (-1 to -15) */
    int ws = (seed[0] % 15) + 1;
    sc->windowSize = -ws;

    /* memlevel: 1-9 */
    sc->memlevel = (seed[1] % 9) + 1;

    /* compressionlevel: 0 (Z_DEFAULT_COMPRESSION=-1) or 1-9 */
    int cl = seed[2] % 10;
    sc->compressionlevel = (cl == 0) ? -1 : cl;

    /* bufferSize: 64 to 1MB */
    uint32_t bs = ((uint32_t)seed[3]) | ((uint32_t)seed[4] << 8) | ((uint32_t)seed[5] << 16) |
                  ((uint32_t)seed[6] << 24);
    bs = 64 + (bs % (1024 * 1024 - 64 + 1));
    sc->bufferSize = bs;

    /* inflate_limit: 0 (unlimited) or up to 100MB */
    uint32_t il = ((uint32_t)seed[7]) | ((uint32_t)seed[8] << 8) | ((uint32_t)seed[9] << 16) |
                  ((uint32_t)seed[10] << 24);
    dc->inflate_limit = (apr_off_t)(il % (100 * 1024 * 1024 + 1));

    /* ratio_limit: 1-255 (high nibble * 16 + low nibble, minimum 1) */
    int rl = (seed[11] >> 4) & 0x0f;
    dc->ratio_limit = (rl == 0) ? 1 : rl * 20; /* 20..300 */

    /* ratio_burst: 1-15 */
    int rb = seed[11] & 0x0f;
    dc->ratio_burst = (rb == 0) ? 1 : rb;
}

/* ----------------------------------------------------------------
 * Config patching
 *
 * mod_deflate has no dir merger (NULL), so Apache uses the most
 * specific <Directory> match's config directly during request
 * processing.  We must patch every deflate_dirconf_t in the
 * server's sec_dir array, not just lookup_defaults.
 * ---------------------------------------------------------------- */

/* Maximum <Directory> sections we support saving/restoring */
#define MAX_DIR_SECTIONS 32

static deflate_dirconf_t g_saved_dir_configs[MAX_DIR_SECTIONS];
static int g_num_dir_configs = 0;

static void patch_deflate_config(const uint8_t *seed, deflate_filter_config *saved_sc)
{
    /* Patch server config (windowSize, memlevel, etc.) */
    deflate_filter_config *sc = ap_get_module_config(g_server->module_config, &deflate_module);

    if (!sc)
        return;

    *saved_sc = *sc;

    /* Decode only server-level fields from seed */
    deflate_dirconf_t tmp_dc;
    const char *saved_ratio = sc->note_ratio_name;
    const char *saved_input = sc->note_input_name;
    const char *saved_output = sc->note_output_name;

    decode_config_seed(seed, sc, &tmp_dc);

    sc->note_ratio_name = saved_ratio;
    sc->note_input_name = saved_input;
    sc->note_output_name = saved_output;

    /* Patch dir config in lookup_defaults */
    deflate_dirconf_t *dc = ap_get_module_config(g_server->lookup_defaults, &deflate_module);
    g_num_dir_configs = 0;
    if (dc) {
        g_saved_dir_configs[g_num_dir_configs++] = *dc;
        dc->inflate_limit = tmp_dc.inflate_limit;
        dc->ratio_limit = tmp_dc.ratio_limit;
        dc->ratio_burst = tmp_dc.ratio_burst;
    }

    /* Walk all <Directory> sections and patch their deflate dir configs */
    core_server_config *core_cfg = ap_get_core_module_config(g_server->module_config);
    if (core_cfg && core_cfg->sec_dir) {
        ap_conf_vector_t **elts = (ap_conf_vector_t **)core_cfg->sec_dir->elts;
        int nelts = core_cfg->sec_dir->nelts;
        for (int i = 0; i < nelts && g_num_dir_configs < MAX_DIR_SECTIONS; i++) {
            deflate_dirconf_t *ddc = ap_get_module_config(elts[i], &deflate_module);
            if (ddc) {
                g_saved_dir_configs[g_num_dir_configs++] = *ddc;
                ddc->inflate_limit = tmp_dc.inflate_limit;
                ddc->ratio_limit = tmp_dc.ratio_limit;
                ddc->ratio_burst = tmp_dc.ratio_burst;
            }
        }
    }
}

static void restore_deflate_config(const deflate_filter_config *saved_sc)
{
    deflate_filter_config *sc = ap_get_module_config(g_server->module_config, &deflate_module);
    if (sc)
        *sc = *saved_sc;

    /* Restore lookup_defaults dir config */
    int idx = 0;
    deflate_dirconf_t *dc = ap_get_module_config(g_server->lookup_defaults, &deflate_module);
    if (dc && idx < g_num_dir_configs)
        *dc = g_saved_dir_configs[idx++];

    /* Restore all <Directory> section dir configs */
    core_server_config *core_cfg = ap_get_core_module_config(g_server->module_config);
    if (core_cfg && core_cfg->sec_dir) {
        ap_conf_vector_t **elts = (ap_conf_vector_t **)core_cfg->sec_dir->elts;
        int nelts = core_cfg->sec_dir->nelts;
        for (int i = 0; i < nelts && idx < g_num_dir_configs; i++) {
            deflate_dirconf_t *ddc = ap_get_module_config(elts[i], &deflate_module);
            if (ddc)
                *ddc = g_saved_dir_configs[idx++];
        }
    }

    g_num_dir_configs = 0;
}

/* ----------------------------------------------------------------
 * Stdin reading helper
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

    if (n < 0 || total == 0)
        return -1;

    /* Need at least config seed + some HTTP data */
    if (total <= CONFIG_SEED_SIZE) {
        fprintf(stderr, "Input too small (need > %d bytes)\n", CONFIG_SEED_SIZE);
        return -1;
    }

    deflate_filter_config saved_sc = {0};

    patch_deflate_config((const uint8_t *)input_buf, &saved_sc);
    fuzz_one_input(input_buf + CONFIG_SEED_SIZE, total - CONFIG_SEED_SIZE);
    restore_deflate_config(&saved_sc);

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

    if (g_init_failed)
        return 0;

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

    if (size <= CONFIG_SEED_SIZE)
        return 0;

    deflate_filter_config saved_sc = {0};

    patch_deflate_config(data, &saved_sc);
    fuzz_one_input((const char *)(data + CONFIG_SEED_SIZE), size - CONFIG_SEED_SIZE);
    restore_deflate_config(&saved_sc);

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
        do {
            int len = __AFL_FUZZ_TESTCASE_LEN;
            if (len > CONFIG_SEED_SIZE) {
                deflate_filter_config saved_sc = {0};

                patch_deflate_config(buf, &saved_sc);
                fuzz_one_input((const char *)(buf + CONFIG_SEED_SIZE), len - CONFIG_SEED_SIZE);
                restore_deflate_config(&saved_sc);
            }
        } while (__AFL_LOOP(10000));
    } else {
        read_stdin_and_process();
    }
#else
    read_stdin_and_process();
#endif

    fuzz_exit(0);
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

    if (fuzz_init(confname, def_server_root) < 0)
        return 1;

    if (read_stdin_and_process() < 0)
        fuzz_exit(1);

    fuzz_exit(0);
}

#endif /* LIBFUZZER / AFL_FUZZ */
