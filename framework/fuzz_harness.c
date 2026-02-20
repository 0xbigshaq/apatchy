/*
 * @description: Multi-request pipeline harness - processes multiple requests per fuzz input
 *
 * Like full_pipeline.c, but splits fuzz input on null bytes (\x00) and
 * processes each segment as a separate connection. This exercises
 * cross-connection state: sessions, connection cleanup, per-conn isolation.
 *
 * Input format: request1\x00request2\x00request3
 * (within each segment, HTTP pipelining works normally)
 *
 * The approach:
 * 1. Initialize Apache with a config file
 * 2. Hook insert_network_bucket to inject stdin data as buckets
 * 3. Hook output filter to capture and print responses
 * 4. Split input on \x00 separators
 * 5. For each segment, create a fake connection and process it
 */

#include "apr.h"
#include "apr_strings.h"
#include "apr_getopt.h"
#include "apr_general.h"
#include "apr_lib.h"
#include "apr_buckets.h"
#include "apr_thread_proc.h"

#define APR_WANT_STDIO
#define APR_WANT_STRFUNC
#include "apr_want.h"

#include "ap_config.h"
#include "httpd.h"
#include "http_main.h"
#include "http_log.h"
#include "http_config.h"
#include "http_core.h"
#include "mod_core.h"
#include "http_request.h"
#include "http_connection.h"
#include "http_protocol.h"
#include "http_vhost.h"
#include "ap_mpm.h"
#include "util_filter.h"
#include "scoreboard.h"
#include "mpm_common.h"

#include <unistd.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <signal.h>
#include <string.h>

/*
 * ASan signal handler restoration
 *
 * Apache installs its own signal handlers (sig_coredump) which override ASan's.
 * For ASan builds, we need to restore ASan's handlers after Apache initializes
 * so that ASan can properly report memory errors.
 */
#if defined(__SANITIZE_ADDRESS__)
#define ASAN_ENABLED 1
#elif defined(__has_feature)
#if __has_feature(address_sanitizer)
#define ASAN_ENABLED 1
#endif
#endif

#ifdef ASAN_ENABLED
/* Declare ASan's internal death callback installer */
void __asan_set_death_callback(void (*callback)(void));

/* Saved stderr fd for restoration after Apache redirects it to /dev/null */
static int asan_saved_stderr_fd = -1;

static void asan_save_stderr(void)
{
    /* Save stderr fd before Apache initialization redirects it to /dev/null */
    asan_saved_stderr_fd = dup(STDERR_FILENO);

    /* Strip LD_PRELOAD so child processes (e.g. llvm-symbolizer spawned by
     * ASan) don't inherit the AFL-instrumented DSOs, which would crash
     * them with "undefined symbol: __afl_area_ptr".  The DSOs are already
     * mapped into our address space from exec-time preloading. */
    unsetenv("LD_PRELOAD");
}

static void asan_restore_stderr_and_signals(void)
{
    /*
     * Restore stderr so ASan output is visible.
     * Apache's ap_open_logs() redirects stderr to /dev/null, which hides ASan output.
     */
    if (asan_saved_stderr_fd >= 0) {
        dup2(asan_saved_stderr_fd, STDERR_FILENO);
        close(asan_saved_stderr_fd);
        asan_saved_stderr_fd = -1;
    }

    /*
     * Reset signal handlers to default so ASan can catch them.
     * Apache's mpm_unix.c installs sig_coredump handlers that override ASan's.
     */
    signal(SIGSEGV, SIG_DFL);
    signal(SIGBUS, SIG_DFL);
    signal(SIGABRT, SIG_DFL);
    signal(SIGFPE, SIG_DFL);
    signal(SIGILL, SIG_DFL);
}
#endif

/* Global state for the fuzzer */
static apr_pool_t *g_pool = NULL;
static char *g_input_data = NULL;
static apr_size_t g_input_size = 0;
static apr_size_t g_input_offset = 0;

/* Forward declarations */
static apr_status_t fuzz_insert_network_bucket(conn_rec *c, apr_bucket_brigade *bb,
                                                apr_socket_t *socket);
static apr_status_t fuzz_output_filter(ap_filter_t *f, apr_bucket_brigade *bb);

/*
 * Custom bucket type that reads from our input buffer instead of a socket
 */
typedef struct {
    apr_bucket_refcount refcount;
    const char *data;
    apr_size_t length;
    apr_size_t offset;
} fuzz_bucket_ctx;

static apr_status_t fuzz_bucket_read(apr_bucket *b, const char **str,
                                      apr_size_t *len, apr_read_type_e block)
{
    fuzz_bucket_ctx *ctx = b->data;
    apr_size_t remaining;

    if (ctx->offset >= ctx->length) {
        *str = NULL;
        *len = 0;
        return APR_EOF;
    }

    remaining = ctx->length - ctx->offset;
    *str = ctx->data + ctx->offset;
    *len = remaining;
    ctx->offset = ctx->length;  /* Mark as consumed */

    /* Convert to a heap bucket for the remaining data */
    apr_bucket_heap_make(b, *str, *len, NULL);

    return APR_SUCCESS;
}

static void fuzz_bucket_destroy(void *data)
{
    fuzz_bucket_ctx *ctx = data;
    if (apr_bucket_shared_destroy(ctx)) {
        apr_bucket_free(ctx);
    }
}

static const apr_bucket_type_t fuzz_bucket_type = {
    "FUZZ", 5, APR_BUCKET_DATA,
    fuzz_bucket_destroy,
    fuzz_bucket_read,
    apr_bucket_setaside_noop,
    apr_bucket_shared_split,
    apr_bucket_shared_copy
};

static apr_bucket *fuzz_bucket_create(const char *data, apr_size_t length,
                                       apr_bucket_alloc_t *list)
{
    apr_bucket *b = apr_bucket_alloc(sizeof(*b), list);
    fuzz_bucket_ctx *ctx = apr_bucket_alloc(sizeof(*ctx), list);

    ctx->data = data;
    ctx->length = length;
    ctx->offset = 0;

    APR_BUCKET_INIT(b);
    b->free = apr_bucket_free;
    b->list = list;
    b->type = &fuzz_bucket_type;
    b->length = length;
    b->start = 0;
    b->data = ctx;

    return b;
}

/*
 * Our insert_network_bucket hook - injects stdin data instead of socket data
 */
static apr_status_t fuzz_insert_network_bucket(conn_rec *c, apr_bucket_brigade *bb,
                                                apr_socket_t *socket)
{
    apr_bucket *b;

    if (g_input_data && g_input_size > 0) {
        /* Create a bucket from our input data */
        b = fuzz_bucket_create(g_input_data, g_input_size, c->bucket_alloc);
        APR_BRIGADE_INSERT_TAIL(bb, b);
    }

    /* Add EOS to signal end of input */
    b = apr_bucket_eos_create(c->bucket_alloc);
    APR_BRIGADE_INSERT_TAIL(bb, b);

    return APR_SUCCESS;
}

/*
 * Output filter that prints response to stdout
 */
static ap_filter_rec_t *fuzz_output_filter_handle;

static apr_status_t fuzz_output_filter(ap_filter_t *f, apr_bucket_brigade *bb)
{
    apr_bucket *b;
    apr_status_t rv;
    const char *data;
    apr_size_t len;

    for (b = APR_BRIGADE_FIRST(bb);
         b != APR_BRIGADE_SENTINEL(bb);
         b = APR_BUCKET_NEXT(b))
    {
        if (APR_BUCKET_IS_EOS(b)) {
            break;
        }

        if (APR_BUCKET_IS_FLUSH(b)) {
            fflush(stdout);
            continue;
        }

        if (APR_BUCKET_IS_METADATA(b)) {
            continue;
        }

        rv = apr_bucket_read(b, &data, &len, APR_BLOCK_READ);
        if (rv == APR_SUCCESS && len > 0) {
            fwrite(data, 1, len, stdout);
        }
    }

    return APR_SUCCESS;
}

/*
 * Our input filter - reads from global input data
 */
static ap_filter_rec_t *fuzz_input_filter_handle;

typedef struct {
    conn_rec *c;
    int eos_sent;
    apr_bucket_brigade *bb;  /* Internal brigade to hold input data */
} fuzz_net_rec;

static apr_status_t fuzz_input_filter(ap_filter_t *f, apr_bucket_brigade *bb,
                                       ap_input_mode_t mode, apr_read_type_e block,
                                       apr_off_t readbytes)
{
    apr_bucket *b;
    fuzz_net_rec *net = f->ctx;

    if (mode == AP_MODE_INIT) {
        return APR_SUCCESS;
    }

    if (net->eos_sent) {
        return APR_EOF;
    }

    /* If we haven't populated the internal brigade yet, do so now */
    if (g_input_data && g_input_size > 0 && APR_BRIGADE_EMPTY(net->bb)) {
        /* Create a bucket from our input data and store in internal brigade */
        b = apr_bucket_heap_create(g_input_data, g_input_size, NULL, f->c->bucket_alloc);
        APR_BRIGADE_INSERT_TAIL(net->bb, b);

        /* Add EOS to internal brigade */
        b = apr_bucket_eos_create(f->c->bucket_alloc);
        APR_BRIGADE_INSERT_TAIL(net->bb, b);

        /* Mark input as consumed */
        g_input_data = NULL;
        g_input_size = 0;
    }

    /* Check if internal brigade is empty */
    if (APR_BRIGADE_EMPTY(net->bb)) {
        net->eos_sent = 1;
        return APR_EOF;
    }

    if (mode == AP_MODE_GETLINE) {
        /* Return one line at a time */
        apr_status_t rv = apr_brigade_split_line(bb, net->bb, block, HUGE_STRING_LEN);
        if (APR_STATUS_IS_EAGAIN(rv) && block == APR_NONBLOCK_READ) {
            rv = APR_SUCCESS;
        }
        return rv;
    }
    else if (mode == AP_MODE_READBYTES) {
        /* Return requested number of bytes */
        apr_status_t rv;
        if (readbytes > 0) {
            rv = apr_brigade_partition(net->bb, readbytes, &b);
            if (rv != APR_SUCCESS && !APR_STATUS_IS_EOF(rv)) {
                return rv;
            }
        }
        /* Move buckets from net->bb to bb */
        APR_BRIGADE_CONCAT(bb, net->bb);
        return APR_SUCCESS;
    }
    else if (mode == AP_MODE_SPECULATIVE) {
        /* Peek at data without consuming */
        apr_bucket *e;
        for (e = APR_BRIGADE_FIRST(net->bb);
             e != APR_BRIGADE_SENTINEL(net->bb);
             e = APR_BUCKET_NEXT(e)) {
            apr_bucket *copy;
            if (apr_bucket_copy(e, &copy) != APR_SUCCESS) {
                break;
            }
            APR_BRIGADE_INSERT_TAIL(bb, copy);
            if (APR_BUCKET_IS_EOS(e)) {
                break;
            }
        }
        return APR_SUCCESS;
    }
    else if (mode == AP_MODE_EXHAUSTIVE) {
        /* Return everything */
        APR_BRIGADE_CONCAT(bb, net->bb);
        return APR_SUCCESS;
    }

    return APR_ENOTIMPL;
}

/*
 * Hook to add our filters to connections and set up for socketless operation
 * This runs at APR_HOOK_LAST (before core_pre_connection at REALLY_LAST)
 */
static int fuzz_pre_connection(conn_rec *c, void *csd)
{
    fuzz_net_rec *net;
    apr_socket_t *dummy_socket = NULL;

    /* Set up our net_rec */
    net = apr_pcalloc(c->pool, sizeof(*net));
    net->c = c;
    net->eos_sent = 0;
    net->bb = apr_brigade_create(c->pool, c->bucket_alloc);

    /* Create a dummy socket so that code expecting a socket doesn't crash.
     * Some Apache code (like apply_server_config) tries to set socket options.
     * We create a real socket but never use it for I/O.
     */
    if (apr_socket_create(&dummy_socket, APR_INET, SOCK_STREAM, APR_PROTO_TCP, c->pool) == APR_SUCCESS) {
        ap_set_core_module_config(c->conn_config, dummy_socket);
    }
    else {
        /* Fallback to NULL if socket creation fails */
        ap_set_core_module_config(c->conn_config, NULL);
    }

    /* Add our input filter - must be at NETWORK level to replace CORE_IN */
    ap_add_input_filter_handle(fuzz_input_filter_handle, net, NULL, c);

    /* Add our output filter */
    ap_add_output_filter_handle(fuzz_output_filter_handle, NULL, NULL, c);

    /* Set c->master to non-NULL to make core_pre_connection skip its work.
     * core_pre_connection checks: if (c->master) { return DONE; }
     * We use the connection itself as a sentinel value.
     */
    c->master = c;

    /* Return OK to let other pre_connection hooks run (including core) */
    return OK;
}

/*
 * Create a fake sockaddr for connection
 */
static apr_sockaddr_t *create_fake_sockaddr(apr_pool_t *p, const char *ip, apr_port_t port)
{
    apr_sockaddr_t *sa = apr_pcalloc(p, sizeof(*sa));
    sa->pool = p;
    sa->family = APR_INET;
    sa->port = port;
    sa->salen = sizeof(struct sockaddr_in);
    sa->ipaddr_len = sizeof(struct in_addr);
    sa->addr_str_len = 16;
    sa->ipaddr_ptr = &((struct sockaddr_in *)&sa->sa)->sin_addr;
    inet_pton(AF_INET, ip, sa->ipaddr_ptr);
    ((struct sockaddr_in *)&sa->sa)->sin_family = AF_INET;
    ((struct sockaddr_in *)&sa->sa)->sin_port = htons(port);
    return sa;
}

/*
 * Register our hooks
 */
static void fuzz_register_hooks(apr_pool_t *p)
{
    /* Register our input filter - at NETWORK level to replace CORE_IN */
    fuzz_input_filter_handle = ap_register_input_filter(
        "FUZZ_INPUT", fuzz_input_filter, NULL, AP_FTYPE_NETWORK);

    /* Register our output filter */
    fuzz_output_filter_handle = ap_register_output_filter(
        "FUZZ_OUTPUT", fuzz_output_filter, NULL, AP_FTYPE_NETWORK - 1);

    /* Hook to add our filter to connections - run at LAST (before core at REALLY_LAST)
     * This lets other modules like logio set up their connection configs first.
     */
    ap_hook_pre_connection(fuzz_pre_connection, NULL, NULL, APR_HOOK_LAST);

    /* Replace the network bucket insertion with our version */
    ap_hook_insert_network_bucket(fuzz_insert_network_bucket, NULL, NULL,
                                   APR_HOOK_FIRST);
}

/*
 * Our fuzzer module
 */
module AP_MODULE_DECLARE_DATA fuzz_module = {
    STANDARD20_MODULE_STUFF,
    NULL,                   /* create per-directory config */
    NULL,                   /* merge per-directory config */
    NULL,                   /* create per-server config */
    NULL,                   /* merge per-server config */
    NULL,                   /* command table */
    fuzz_register_hooks     /* register hooks */
};

/*
 * Provide a dummy mpm_event_module to satisfy the linker
 * This is referenced in modules.c but we don't use it
 */
module AP_MODULE_DECLARE_DATA mpm_event_module = {
    STANDARD20_MODULE_STUFF,
    NULL,                   /* create per-directory config */
    NULL,                   /* merge per-directory config */
    NULL,                   /* create per-server config */
    NULL,                   /* merge per-server config */
    NULL,                   /* command table */
    NULL                    /* no hooks - we use fuzz_mpm_hooks instead */
};

/*
 * Fake MPM that just processes one connection and exits
 */
static int fuzz_mpm_run(apr_pool_t *pconf, apr_pool_t *plog, server_rec *s)
{
    apr_pool_t *ptrans;
    conn_rec *c;
    apr_bucket_alloc_t *bucket_alloc;
    long conn_id = 1;

    /* Create transaction pool */
    apr_pool_create(&ptrans, pconf);
    apr_pool_tag(ptrans, "transaction");

    /* Create bucket allocator */
    bucket_alloc = apr_bucket_alloc_create(ptrans);

    /* Create connection record directly - don't use ap_run_create_connection
     * because it requires a real socket. We create the conn_rec ourselves.
     */
    c = apr_pcalloc(ptrans, sizeof(*c));
    c->pool = ptrans;
    c->base_server = s;
    c->id = conn_id;
    c->bucket_alloc = bucket_alloc;
    c->conn_config = ap_create_conn_config(ptrans);
    c->notes = apr_table_make(ptrans, 5);
    c->sbh = NULL;

    /* Create fake addresses */
    c->local_addr = create_fake_sockaddr(ptrans, "127.0.0.1", 80);
    c->client_addr = create_fake_sockaddr(ptrans, "127.0.0.1", 12345);
    c->local_ip = "127.0.0.1";
    c->client_ip = "127.0.0.1";
    c->local_host = "localhost";
    c->remote_host = "localhost";

    fprintf(stderr, "DEBUG: Created connection, local_addr=%p\n", (void*)c->local_addr);

    /* Process the connection through Apache's pipeline */
    ap_process_connection(c, NULL);

    /* Clean up */
    apr_pool_destroy(ptrans);

    return DONE;  /* Signal to exit the MPM loop */
}

static int fuzz_mpm_query(int query_code, int *result, apr_status_t *rv)
{
    switch (query_code) {
        case AP_MPMQ_MAX_DAEMON_USED:
            *result = 1;
            break;
        case AP_MPMQ_IS_THREADED:
            *result = AP_MPMQ_NOT_SUPPORTED;
            break;
        case AP_MPMQ_IS_FORKED:
            *result = AP_MPMQ_NOT_SUPPORTED;
            break;
        case AP_MPMQ_IS_ASYNC:
            *result = 0;
            break;
        case AP_MPMQ_HAS_SERF:
            *result = 0;
            break;
        case AP_MPMQ_HARD_LIMIT_DAEMONS:
            *result = 1;
            break;
        case AP_MPMQ_HARD_LIMIT_THREADS:
            *result = 1;
            break;
        case AP_MPMQ_MAX_THREADS:
            *result = 0;
            break;
        case AP_MPMQ_MIN_SPARE_DAEMONS:
            *result = 0;
            break;
        case AP_MPMQ_MIN_SPARE_THREADS:
            *result = 0;
            break;
        case AP_MPMQ_MAX_SPARE_DAEMONS:
            *result = 0;
            break;
        case AP_MPMQ_MAX_SPARE_THREADS:
            *result = 0;
            break;
        case AP_MPMQ_MAX_REQUESTS_DAEMON:
            *result = 0;
            break;
        case AP_MPMQ_MAX_DAEMONS:
            *result = 1;
            break;
        case AP_MPMQ_MPM_STATE:
            *result = AP_MPMQ_RUNNING;
            break;
        case AP_MPMQ_GENERATION:
            *result = 0;
            break;
        default:
            *rv = APR_ENOTIMPL;
            return DECLINED;
    }
    *rv = APR_SUCCESS;
    return OK;
}

static void fuzz_mpm_hooks(apr_pool_t *p)
{
    ap_hook_mpm(fuzz_mpm_run, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_mpm_query(fuzz_mpm_query, NULL, NULL, APR_HOOK_MIDDLE);
}

/*
 * Common initialization - shared between standalone and libfuzzer modes
 * Returns 0 on success, -1 on failure
 */
static int g_initialized = 0;
static apr_pool_t *g_pconf = NULL;
static apr_pool_t *g_plog = NULL;
static server_rec *g_server = NULL;

static int fuzz_init(const char *confname, const char *server_root)
{
    apr_status_t rv;
    apr_pool_t *ptemp, *pcommands;
    process_rec *process;
    const char *err;
    const char *def_server_root = server_root ? server_root : HTTPD_ROOT;

    if (g_initialized) {
        return 0;
    }

#ifdef ASAN_ENABLED
    /* Save stderr before Apache initialization redirects it to /dev/null */
    asan_save_stderr();
#endif

    /* Initialize APR */
    rv = apr_initialize();
    if (rv != APR_SUCCESS) {
        fprintf(stderr, "apr_initialize failed\n");
        return -1;
    }

    /* Create root pool */
    rv = apr_pool_create(&g_pool, NULL);
    if (rv != APR_SUCCESS) {
        fprintf(stderr, "apr_pool_create failed\n");
        return -1;
    }

    /* Open stderr log so Apache error messages are visible */
    ap_open_stderr_log(g_pool);

    /* Set up process record */
    process = apr_palloc(g_pool, sizeof(*process));
    process->pool = g_pool;
    process->pconf = NULL;
    apr_pool_create(&process->pconf, g_pool);
    apr_pool_tag(process->pconf, "pconf");
    process->argc = 1;
    process->argv = (const char * const[]){"fuzz_harness", NULL};
    process->short_name = "fuzz_harness";

    ap_pglobal = g_pool;
    g_pconf = process->pconf;

    /* Initialize arrays for config directives */
    apr_pool_create(&pcommands, g_pool);
    ap_server_pre_read_config = apr_array_make(pcommands, 1, sizeof(const char *));
    ap_server_post_read_config = apr_array_make(pcommands, 1, sizeof(const char *));
    ap_server_config_defines = apr_array_make(pcommands, 1, sizeof(const char *));

    if (!confname) {
        confname = "fuzz.conf";
    }

    /* Register our fuzz module */
    ap_server_root = def_server_root;

    /* Set up prelinked modules */
    err = ap_setup_prelinked_modules(process);
    if (err) {
        fprintf(stderr, "ap_setup_prelinked_modules: %s\n", err);
        return -1;
    }

    /* Register fuzz hooks manually after other modules */
    fuzz_register_hooks(g_pconf);
    fuzz_mpm_hooks(g_pconf);

    /* Create log pool */
    apr_pool_create(&g_plog, g_pool);
    apr_pool_tag(g_plog, "plog");

    /* Create temp pool */
    apr_pool_create(&ptemp, g_pconf);
    apr_pool_tag(ptemp, "ptemp");

    /* Initialize random number generator */
    ap_init_rng(g_pool);

    /* Read config */
    ap_server_conf = NULL;
    g_server = ap_read_config(process, ptemp, confname, &ap_conftree);
    if (!g_server) {
        fprintf(stderr, "Failed to read config file: %s\n", confname);
        return -1;
    }
    ap_server_conf = g_server;

    /* Sort hooks */
    apr_hook_sort_all();

    /* Run pre_config hooks */
    if (ap_run_pre_config(g_pconf, g_plog, ptemp) != OK) {
        fprintf(stderr, "pre_config failed\n");
        return -1;
    }

    /* Process config tree */
    if (ap_process_config_tree(g_server, ap_conftree, g_pconf, ptemp) != OK) {
        fprintf(stderr, "process_config_tree failed\n");
        return -1;
    }

    /* Finalize vhost config */
    ap_fixup_virtual_hosts(g_pconf, g_server);
    ap_fini_vhost_config(g_pconf, g_server);

    /* Sort hooks again after config */
    apr_hook_sort_all();

    /* Check config */
    if (ap_run_check_config(g_pconf, g_plog, ptemp, g_server) != OK) {
        fprintf(stderr, "check_config failed\n");
        return -1;
    }

    /* Skip open_logs in LIBFUZZER/AFL mode - it can hang due to signal handling conflicts */
#if !defined(LIBFUZZER) && !defined(AFL_FUZZ)
    apr_pool_clear(g_plog);
    if (ap_run_open_logs(g_pconf, g_plog, ptemp, g_server) != OK) {
        fprintf(stderr, "open_logs failed\n");
        return -1;
    }
#endif

    /* Run post_config */
    if (ap_run_post_config(g_pconf, g_plog, ptemp, g_server) != OK) {
        fprintf(stderr, "post_config failed\n");
        return -1;
    }

    apr_pool_destroy(ptemp);

    /* Retrieve optional functions */
    ap_run_optional_fn_retrieve();

#ifdef ASAN_ENABLED
    /*
     * Restore stderr and signal handlers for ASan.
     * Apache's ap_open_logs() redirects stderr to /dev/null, hiding ASan output.
     * Apache's mpm_unix.c installs sig_coredump handlers that override ASan's.
     */
    asan_restore_stderr_and_signals();
#endif

    g_initialized = 1;
    return 0;
}

/*
 * Process one request segment on its own connection
 */
static int fuzz_one_input(const char *data, size_t size)
{
    apr_pool_t *ptrans;
    conn_rec *c;
    apr_bucket_alloc_t *bucket_alloc;
    static long conn_id = 0;

    if (size == 0) {
        return 0;
    }

    /* Set global input data */
    g_input_data = (char *)data;
    g_input_size = size;
    g_input_offset = 0;

    /* Create transaction pool */
    apr_pool_create(&ptrans, g_pconf);
    apr_pool_tag(ptrans, "transaction");

    /* Create bucket allocator */
    bucket_alloc = apr_bucket_alloc_create(ptrans);

    /* Create connection record */
    c = apr_pcalloc(ptrans, sizeof(*c));
    c->pool = ptrans;
    c->base_server = g_server;
    c->id = ++conn_id;
    c->bucket_alloc = bucket_alloc;
    c->conn_config = ap_create_conn_config(ptrans);
    c->notes = apr_table_make(ptrans, 5);
    c->sbh = NULL;

    /* Create fake addresses */
    c->local_addr = create_fake_sockaddr(ptrans, "127.0.0.1", 80);
    c->client_addr = create_fake_sockaddr(ptrans, "127.0.0.1", 12345);
    c->local_ip = "127.0.0.1";
    c->client_ip = "127.0.0.1";
    c->local_host = "localhost";
    c->remote_host = "localhost";

    /* Process the connection through Apache's pipeline */
    ap_process_connection(c, NULL);

    /* Clean up */
    apr_pool_destroy(ptrans);

    /* Reset global input */
    g_input_data = NULL;
    g_input_size = 0;

    return 0;
}

/*
 * Split fuzz input on \x00 separators and process each segment
 * as a separate connection. This exercises cross-connection state
 * (sessions, module cleanup, per-connection isolation).
 *
 * Max 16 requests per input to bound execution time.
 */
#define MAX_REQUESTS_PER_INPUT 16

static int fuzz_multi_input(const char *data, size_t size)
{
    const char *p = data;
    const char *end = data + size;
    int count = 0;

    while (p < end && count < MAX_REQUESTS_PER_INPUT) {
        /* Find next null byte separator */
        const char *sep = memchr(p, '\0', end - p);
        size_t seg_len;

        if (sep) {
            seg_len = sep - p;
        } else {
            /* Last segment: no trailing separator */
            seg_len = end - p;
        }

        if (seg_len > 0) {
            fuzz_one_input(p, seg_len);
            count++;
        }

        /* Advance past segment + separator */
        p += seg_len + 1;
    }

    return 0;
}

#ifdef LIBFUZZER
/*
 * LibFuzzer entry point
 *
 * Configuration via environment variables:
 *   FUZZ_CONF - path to config file (default: fuzz.conf)
 *   FUZZ_ROOT - server root directory (default: current directory)
 */
static int g_init_failed = 0;

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    static int init_done = 0;

    /* If initialization already failed, don't keep trying */
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
            _exit(1);  /* Hard exit - can't fuzz without init */
        }
        init_done = 1;
    }

    fuzz_multi_input((const char *)data, size);
    return 0;
}

#elif defined(AFL_FUZZ)
/*
 * AFL/AFL++ entry point with persistent mode support
 *
 * AFL persistent mode significantly improves fuzzing speed by reusing
 * the process for multiple inputs instead of forking for each one.
 *
 * Configuration via environment variables:
 *   FUZZ_CONF - path to config file (default: fuzz.conf)
 *   FUZZ_ROOT - server root directory (default: current directory)
 */

/* AFL persistent mode macros */
#ifdef __AFL_HAVE_MANUAL_CONTROL
  __AFL_FUZZ_INIT();
#endif

int main(int argc, const char * const argv[])
{
    const char *conf = getenv("FUZZ_CONF");
    const char *root = getenv("FUZZ_ROOT");

    if (!conf) conf = "fuzz.conf";
    if (!root) root = ".";

    /* Initialize APR */
    apr_status_t rv = apr_app_initialize(&argc, &argv, NULL);
    if (rv != APR_SUCCESS) {
        fprintf(stderr, "apr_app_initialize failed\n");
        return 1;
    }

    /* Initialize the fuzzer */
    if (fuzz_init(conf, root) < 0) {
        fprintf(stderr, "Fuzzer initialization failed\n");
        return 1;
    }

#ifdef __AFL_HAVE_MANUAL_CONTROL
    /* AFL persistent mode - process multiple inputs per process */
    __AFL_INIT();

    unsigned char *buf = __AFL_FUZZ_TESTCASE_BUF;

    while (__AFL_LOOP(10000)) {
        int len = __AFL_FUZZ_TESTCASE_LEN;
        if (len > 0) {
            fuzz_multi_input((const char *)buf, len);
        }
    }
#else
    /* Fallback for non-persistent mode: read from stdin */
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

        if (total > 0) {
            fuzz_multi_input(input_buf, total);
        }
    }
#endif

    /* Cleanup */
    apr_pool_destroy(g_pool);
    apr_terminate();

    return 0;
}

#else /* !LIBFUZZER && !AFL_FUZZ */

/*
 * Standalone main entry point - reads from stdin for crash triage
 */
int main(int argc, const char * const argv[])
{
    apr_status_t rv;
    apr_pool_t *pcommands;
    apr_getopt_t *opt;
    const char *confname = NULL;
    const char *def_server_root = HTTPD_ROOT;
    char c;
    const char *opt_arg;

    /* Initialize APR for argument parsing */
    rv = apr_app_initialize(&argc, &argv, NULL);
    if (rv != APR_SUCCESS) {
        fprintf(stderr, "apr_app_initialize failed\n");
        return 1;
    }

    /* Create temp pool for argument parsing */
    apr_pool_create(&pcommands, NULL);

    /* Parse command line */
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

    /* Initialize the fuzzer */
    if (fuzz_init(confname, def_server_root) < 0) {
        return 1;
    }

    /* Read stdin into buffer */
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
            return 1;
        }

        if (total == 0) {
            fprintf(stderr, "No input data\n");
            return 1;
        }

        /* Process all request segments */
        fuzz_multi_input(input_buf, total);
    }

    /* Cleanup */
    apr_pool_destroy(g_pool);
    apr_terminate();

    return 0;
}

#endif /* LIBFUZZER / AFL_FUZZ */
