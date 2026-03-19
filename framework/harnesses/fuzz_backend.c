/*
 * fuzz_backend.c - Intercept proxy backend connections and serve fuzzed
 * response data instead of reading from a real socket.
 *
 * The harness entry point sets g_backend_buf/g_backend_size before
 * calling fuzz_one_input(). When mod_proxy creates a backend connection,
 * our pre_connection hook detects it (no "fuzz_client" note) and installs
 * an input filter that serves g_backend_buf as the backend response.
 */
#include "http_core.h"

#include "http_connection.h"
#include "http_log.h"
#include "httpd.h"
#include "util_filter.h"

#include "ap_config.h"
#include "apr_buckets.h"
#include "apr_errno.h"
#include "apr_strings.h"
#include "http_config.h"

#include "fuzz_backend.h"
#include "fuzz_common.h"

int g_backend_enabled = 0;        /* feature flag */
const char *g_backend_buf = NULL; /* buffer from proto harness */
apr_size_t g_backend_size = 0;    /* size from proto harness */

static ap_filter_rec_t *apatchy_input_filter; /* filter handle */
static ap_filter_rec_t *apatchy_output_filter;

typedef struct {
    apr_bucket_brigade *bb;
    int is_eos;
} apatchy_ctx_t;

static apr_status_t apatchy_input_filter_cb(
    ap_filter_t *f, apr_bucket_brigade *output_brigade, ap_input_mode_t mode, apr_read_type_e block,
    apr_off_t readbytes
)
{
    apr_bucket *b;
    apatchy_ctx_t *ctx = f->ctx;
    /* ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, APLOGNO(00042) "testing worksssssss");
     ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, "filter cb called from: %s", f->frec->name);
     ap_log_error(
         APLOG_MARK, APLOG_ERR, 0, NULL, "filter mode=%d bb_empty=%d ctx_bb_empty=%d", mode,
         APR_BRIGADE_EMPTY(output_brigade), APR_BRIGADE_EMPTY(ctx->bb)
     );*/

    if (mode == AP_MODE_INIT)
        return APR_SUCCESS;
    if (ctx->is_eos)
        return APR_EOF;

    if (g_backend_size > 0 && g_backend_buf && APR_BRIGADE_EMPTY(ctx->bb)) {
        /*
        ap_log_error(
            APLOG_MARK, APLOG_ERR, 0, NULL, "filter loading %lu bytes: %.40s",
            (unsigned long)g_backend_size, g_backend_buf
        );
        char hex[100];
        int hlen = g_backend_size < 20 ? g_backend_size : 20;
        for (int i = 0; i < hlen; i++)
            sprintf(hex + i * 3, "%02x ", (unsigned char)g_backend_buf[i]);
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, "hex dump: %s", hex);
        */
        b = apr_bucket_heap_create(g_backend_buf, g_backend_size, NULL, f->c->bucket_alloc);
        APR_BRIGADE_INSERT_TAIL(ctx->bb, b);
        b = apr_bucket_eos_create(f->c->bucket_alloc);
        APR_BRIGADE_INSERT_TAIL(ctx->bb, b);
        g_backend_buf = NULL;
        g_backend_size = 0;
    }
    if (APR_BRIGADE_EMPTY(ctx->bb)) {
        ctx->is_eos = 1;
        return APR_EOF;
    }

    if (mode == AP_MODE_GETLINE) {
        apr_status_t rc = apr_brigade_split_line(output_brigade, ctx->bb, block, HUGE_STRING_LEN);
        /*ap_log_error(
            APLOG_MARK, APLOG_ERR, 0, NULL, "split_line rc=%d out_empty=%d", rc,
            APR_BRIGADE_EMPTY(output_brigade)
        );*/
        if (rc != APR_SUCCESS)
            return rc;
    } else if (mode == AP_MODE_READBYTES) {
        /*ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, "read_bytes reabytes=%ld", readbytes);*/
        if (readbytes > 0) {
            apr_bucket *e;
            apr_bucket *cur = NULL;
            apr_status_t rc = apr_brigade_partition(ctx->bb, readbytes, &e);
            if (rc != APR_SUCCESS && !APR_STATUS_IS_EOF(rc) && rc != APR_INCOMPLETE)
                return rc;

            while (!APR_BRIGADE_EMPTY(ctx->bb)) {
                cur = APR_BRIGADE_FIRST(ctx->bb);
                if (cur == e)
                    break;
                APR_BUCKET_REMOVE(cur);
                APR_BRIGADE_INSERT_TAIL(output_brigade, cur);
            }
        }
    }
    return APR_SUCCESS;
}

static apr_status_t apatchy_output_filter_cb(ap_filter_t *f, apr_bucket_brigade *b)
{
    apr_brigade_cleanup(b);
    return APR_SUCCESS;
}

static int apatchy_pre_connection(conn_rec *c, void *csd)
{
    apatchy_ctx_t *ctx = NULL;
    if (!g_backend_enabled)
        return DECLINED; /* the module doesn't need our filter */
    if (apr_table_get(c->notes, "fuzz_client"))
        return DECLINED; /* this is our fuzzer client, not proxy backend*/
    ctx = apr_pcalloc(c->pool, sizeof(apatchy_ctx_t));
    ctx->bb = apr_brigade_create(c->pool, c->bucket_alloc);
    ctx->is_eos = 0;

    // mock/prevent null derefs
    ap_set_core_module_config(c->conn_config, apr_pcalloc(c->pool, sizeof(void *) * 64));

    ap_add_input_filter_handle(apatchy_input_filter, ctx, NULL, c);
    ap_add_output_filter_handle(apatchy_output_filter, NULL, NULL, c);
    // ap_remove_input_filter()

    /*
    ap_filter_t *cur = c->input_filters;
    while (cur) {
        ap_log_error(
            APLOG_MARK, APLOG_ERR, 0, NULL, "filter chain: %s (type=%d)", cur->frec->name,
            cur->frec->ftype
        );
        cur = cur->next;
    }
    */

    c->master = c; // mock/prevent null ptr crashes

    // ap_remove_input_filter(c->);
    return DONE;
}

void apatchy_register_hooks(apr_pool_t *p)
{
    apatchy_input_filter = ap_register_input_filter(
        "UWSGI_FUZZ_IN", apatchy_input_filter_cb, NULL, AP_FTYPE_CONNECTION
    );
    apatchy_output_filter = ap_register_output_filter(
        "UWSGI_OUT_FUZZ", apatchy_output_filter_cb, NULL, AP_FTYPE_CONNECTION
    );

    ap_hook_pre_connection(
        (ap_HOOK_pre_connection_t *)apatchy_pre_connection, NULL, NULL, APR_HOOK_FIRST
    );
}

AP_DECLARE_MODULE(apatchy_uwsgi_fuzz) = {
    STANDARD20_MODULE_STUFF, NULL, NULL, NULL, NULL, NULL,
    apatchy_register_hooks /* our module struct */
};

/*
 * Runs before main(). Sets fuzz_extra_hooks so that fuzz_init()
 * calls our register_hooks before ap_setup_prelinked_modules()
 * finalizes the hook table.
 */
__attribute__((constructor)) static void apatchy_init_callback()
{
    fuzz_extra_hooks = &apatchy_register_hooks;
}