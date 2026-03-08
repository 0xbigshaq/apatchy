/*
 * Shared fuzzing infrastructure for Apache pipeline harnesses.
 *
 * Contains all the plumbing needed to run HTTP requests through Apache's
 * full pipeline without real network sockets:
 *   - Custom bucket type that reads from an in-memory buffer
 *   - Input/output filters to inject requests and capture responses
 *   - pre_connection hook for socketless operation
 *   - Apache initialization (config, hooks, modules, child_init)
 *   - Fake MPM stubs
 *   - ASan signal/stderr restoration
 */

#include "fuzz_common.h"

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

/* ----------------------------------------------------------------
 * ASan signal handler restoration
 *
 * Apache installs its own signal handlers (sig_coredump) which override
 * ASan's.  For ASan builds we restore ASan's handlers after Apache
 * initializes so that ASan can properly report memory errors.
 * ---------------------------------------------------------------- */

#if defined(__SANITIZE_ADDRESS__)
#define ASAN_ENABLED 1
#elif defined(__has_feature)
#if __has_feature(address_sanitizer)
#define ASAN_ENABLED 1
#endif
#endif

#ifdef ASAN_ENABLED
void __asan_set_death_callback(void (*callback)(void));
void __sanitizer_print_stack_trace(void);

static int asan_saved_stderr_fd = -1;

/* Signal handlers saved before Apache initialization.  ASan installs its
 * own handlers at program startup; Apache's sig_coredump overwrites them.
 * We snapshot the handlers early and restore them after Apache init. */
static const int asan_saved_signals[] = {SIGSEGV, SIGBUS, SIGABRT, SIGFPE, SIGILL};
#define ASAN_NUM_SIGNALS (sizeof(asan_saved_signals) / sizeof(asan_saved_signals[0]))
static struct sigaction asan_saved_actions[ASAN_NUM_SIGNALS];

static void asan_save_stderr_and_signals(void)
{
    asan_saved_stderr_fd = dup(STDERR_FILENO);

    for (size_t i = 0; i < ASAN_NUM_SIGNALS; i++) {
        sigaction(asan_saved_signals[i], NULL, &asan_saved_actions[i]);
    }
}

#define write_err(msg) write(STDERR_FILENO, msg, sizeof(msg) - 1);
static void ubsan_signal_handler(int sig)
{
    // write a message to stderr
    write_err("[*] ubsan_signal_handler :: custom handler triggered!\n");
    write_err("SUMMARY: UndefinedBehaviorSanitizer: undefined-behavior\n");

    // print a stack trace
    __sanitizer_print_stack_trace();

    // forward signal number
    // we could just hard-code SIGILL but we will
    // pass the original for our python triage cmd
    _exit(128 + sig);
}

static void register_ubsan_signal_handler()
{
    struct sigaction tmp_var = {0};
    tmp_var.sa_handler = &ubsan_signal_handler;
    sigaction(SIGILL, &tmp_var, NULL);
}

static void asan_restore_stderr_and_signals(void)
{
    if (asan_saved_stderr_fd >= 0) {
        dup2(asan_saved_stderr_fd, STDERR_FILENO);
        close(asan_saved_stderr_fd);
        asan_saved_stderr_fd = -1;
    }

    for (size_t i = 0; i < ASAN_NUM_SIGNALS; i++) {
        sigaction(asan_saved_signals[i], &asan_saved_actions[i], NULL);
    }
}
#endif

/* ----------------------------------------------------------------
 * Global state
 * ---------------------------------------------------------------- */

apr_pool_t *g_pool = NULL; /* Exposed via fuzz_common.h */
static char *g_input_data = NULL;
static apr_size_t g_input_size = 0;
static apr_size_t g_input_offset = 0;

/* Forward declarations */
static apr_status_t
fuzz_insert_network_bucket(conn_rec *c, apr_bucket_brigade *bb, apr_socket_t *socket);
static apr_status_t fuzz_output_filter(ap_filter_t *f, apr_bucket_brigade *bb);

/* ----------------------------------------------------------------
 * Custom bucket type - reads from in-memory buffer instead of socket
 * ---------------------------------------------------------------- */

typedef struct {
    apr_bucket_refcount refcount;
    const char *data;
    apr_size_t length;
    apr_size_t offset;
} fuzz_bucket_ctx;

static apr_status_t
fuzz_bucket_read(apr_bucket *b, const char **str, apr_size_t *len, apr_read_type_e block)
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
    ctx->offset = ctx->length;

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
    "FUZZ",
    5,
    APR_BUCKET_DATA,
    fuzz_bucket_destroy,
    fuzz_bucket_read,
    apr_bucket_setaside_noop,
    apr_bucket_shared_split,
    apr_bucket_shared_copy
};

static apr_bucket *fuzz_bucket_create(const char *data, apr_size_t length, apr_bucket_alloc_t *list)
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

/* ----------------------------------------------------------------
 * insert_network_bucket hook - injects input data instead of socket
 * ---------------------------------------------------------------- */

static apr_status_t
fuzz_insert_network_bucket(conn_rec *c, apr_bucket_brigade *bb, apr_socket_t *socket)
{
    apr_bucket *b;

    /* Only intercept the fuzz client connection.
     * Let proxy backend connections use their real socket.
     * This hook is RUN_FIRST with decline value AP_DECLINED -
     * returning the wrong value stops the chain and prevents
     * the core from inserting the real socket bucket. */
    if (!apr_table_get(c->notes, "fuzz_client")) {
        return AP_DECLINED;
    }

    if (g_input_data && g_input_size > 0) {
        b = fuzz_bucket_create(g_input_data, g_input_size, c->bucket_alloc);
        APR_BRIGADE_INSERT_TAIL(bb, b);
    }

    b = apr_bucket_eos_create(c->bucket_alloc);
    APR_BRIGADE_INSERT_TAIL(bb, b);

    return APR_SUCCESS;
}

/* ----------------------------------------------------------------
 * Output filter - prints response to stdout
 * ---------------------------------------------------------------- */

static ap_filter_rec_t *fuzz_output_filter_handle;

static apr_status_t fuzz_output_filter(ap_filter_t *f, apr_bucket_brigade *bb)
{
    apr_bucket *b;
    apr_status_t rv;
    const char *data;
    apr_size_t len;

    for (b = APR_BRIGADE_FIRST(bb); b != APR_BRIGADE_SENTINEL(bb); b = APR_BUCKET_NEXT(b)) {
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

/* ----------------------------------------------------------------
 * Input filter - reads from global input data
 * ---------------------------------------------------------------- */

static ap_filter_rec_t *fuzz_input_filter_handle;

typedef struct {
    conn_rec *c;
    int eos_sent;
    apr_bucket_brigade *bb;
} fuzz_net_rec;

static apr_status_t fuzz_input_filter(
    ap_filter_t *f, apr_bucket_brigade *bb, ap_input_mode_t mode, apr_read_type_e block,
    apr_off_t readbytes
)
{
    apr_bucket *b;
    fuzz_net_rec *net = f->ctx;

    if (mode == AP_MODE_INIT) {
        return APR_SUCCESS;
    }

    if (net->eos_sent) {
        return APR_EOF;
    }

    /* Populate the internal brigade on first read */
    if (g_input_data && g_input_size > 0 && APR_BRIGADE_EMPTY(net->bb)) {
        b = apr_bucket_heap_create(g_input_data, g_input_size, NULL, f->c->bucket_alloc);
        APR_BRIGADE_INSERT_TAIL(net->bb, b);

        b = apr_bucket_eos_create(f->c->bucket_alloc);
        APR_BRIGADE_INSERT_TAIL(net->bb, b);

        g_input_data = NULL;
        g_input_size = 0;
    }

    if (APR_BRIGADE_EMPTY(net->bb)) {
        net->eos_sent = 1;
        return APR_EOF;
    }

    if (mode == AP_MODE_GETLINE) {
        apr_status_t rv = apr_brigade_split_line(bb, net->bb, block, HUGE_STRING_LEN);
        if (APR_STATUS_IS_EAGAIN(rv) && block == APR_NONBLOCK_READ) {
            rv = APR_SUCCESS;
        }
        return rv;
    } else if (mode == AP_MODE_READBYTES) {
        apr_status_t rv;
        if (readbytes > 0) {
            rv = apr_brigade_partition(net->bb, readbytes, &b);
            if (rv != APR_SUCCESS && !APR_STATUS_IS_EOF(rv)) {
                return rv;
            }
            /* Move only the buckets before the split point (i.e. the
             * requested amount) into the output brigade.  The rest
             * stays in net->bb for subsequent reads. */
            while (!APR_BRIGADE_EMPTY(net->bb)) {
                apr_bucket *e = APR_BRIGADE_FIRST(net->bb);
                if (e == b) {
                    break;
                }
                APR_BUCKET_REMOVE(e);
                APR_BRIGADE_INSERT_TAIL(bb, e);
            }
        } else {
            APR_BRIGADE_CONCAT(bb, net->bb);
        }
        return APR_SUCCESS;
    } else if (mode == AP_MODE_SPECULATIVE) {
        apr_bucket *e;
        for (e = APR_BRIGADE_FIRST(net->bb); e != APR_BRIGADE_SENTINEL(net->bb);
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
    } else if (mode == AP_MODE_EXHAUSTIVE) {
        APR_BRIGADE_CONCAT(bb, net->bb);
        return APR_SUCCESS;
    }

    return APR_ENOTIMPL;
}

/* ----------------------------------------------------------------
 * pre_connection hook - set up socketless operation
 * ---------------------------------------------------------------- */

static int fuzz_pre_connection(conn_rec *c, void *csd)
{
    fuzz_net_rec *net;
    apr_socket_t *dummy_socket = NULL;

    /* Only intercept connections we created (tagged in fuzz_one_input).
     * Let proxy backend connections use normal socket I/O. */
    if (!apr_table_get(c->notes, "fuzz_client")) {
        return DECLINED;
    }

    net = apr_pcalloc(c->pool, sizeof(*net));
    net->c = c;
    net->eos_sent = 0;
    net->bb = apr_brigade_create(c->pool, c->bucket_alloc);

    /* Create a dummy socket so code expecting one doesn't crash */
    if (apr_socket_create(&dummy_socket, APR_INET, SOCK_STREAM, APR_PROTO_TCP, c->pool) ==
        APR_SUCCESS) {
        ap_set_core_module_config(c->conn_config, dummy_socket);
    } else {
        ap_set_core_module_config(c->conn_config, NULL);
    }

    ap_add_input_filter_handle(fuzz_input_filter_handle, net, NULL, c);
    ap_add_output_filter_handle(fuzz_output_filter_handle, NULL, NULL, c);

    /* Make core_pre_connection skip its work */
    c->master = c;

    return OK;
}

/* ----------------------------------------------------------------
 * Fake sockaddr for connections
 * ---------------------------------------------------------------- */

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

/* ----------------------------------------------------------------
 * Hook registration
 * ---------------------------------------------------------------- */

static void fuzz_register_hooks(apr_pool_t *p)
{
    fuzz_input_filter_handle =
        ap_register_input_filter("FUZZ_INPUT", fuzz_input_filter, NULL, AP_FTYPE_NETWORK);

    fuzz_output_filter_handle =
        ap_register_output_filter("FUZZ_OUTPUT", fuzz_output_filter, NULL, AP_FTYPE_NETWORK - 1);

    ap_hook_pre_connection(fuzz_pre_connection, NULL, NULL, APR_HOOK_LAST);

    ap_hook_insert_network_bucket(fuzz_insert_network_bucket, NULL, NULL, APR_HOOK_FIRST);
}

/* ----------------------------------------------------------------
 * Module declarations
 * ---------------------------------------------------------------- */

module AP_MODULE_DECLARE_DATA fuzz_module = {STANDARD20_MODULE_STUFF, NULL, NULL, NULL, NULL, NULL,
                                             fuzz_register_hooks};

/* Dummy mpm_event_module to satisfy the linker (referenced in modules.c) */
module AP_MODULE_DECLARE_DATA mpm_event_module = {
    STANDARD20_MODULE_STUFF, NULL, NULL, NULL, NULL, NULL, NULL
};

/* ----------------------------------------------------------------
 * Fake MPM - processes one connection and exits
 * ---------------------------------------------------------------- */

static int fuzz_mpm_run(apr_pool_t *pconf, apr_pool_t *plog, server_rec *s)
{
    /* This hook is registered but never invoked - we call
     * fuzz_one_input() directly from the entry points. */
    return DONE;
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

/* ----------------------------------------------------------------
 * Initialization
 * ---------------------------------------------------------------- */

static int g_initialized = 0;
static apr_pool_t *g_pconf = NULL;
static apr_pool_t *g_plog = NULL;
server_rec *g_server = NULL;

int fuzz_init(const char *confname, const char *server_root)
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
    asan_save_stderr_and_signals();
#endif

    rv = apr_initialize();
    if (rv != APR_SUCCESS) {
        fprintf(stderr, "apr_initialize failed\n");
        return -1;
    }

    rv = apr_pool_create(&g_pool, NULL);
    if (rv != APR_SUCCESS) {
        fprintf(stderr, "apr_pool_create failed\n");
        return -1;
    }

    ap_open_stderr_log(g_pool);

    process = apr_palloc(g_pool, sizeof(*process));
    process->pool = g_pool;
    process->pconf = NULL;
    apr_pool_create(&process->pconf, g_pool);
    apr_pool_tag(process->pconf, "pconf");
    process->argc = 1;
    process->argv = (const char *const[]){"fuzz_harness", NULL};
    process->short_name = "fuzz_harness";

    ap_pglobal = g_pool;
    g_pconf = process->pconf;

    apr_pool_create(&pcommands, g_pool);
    ap_server_pre_read_config = apr_array_make(pcommands, 1, sizeof(const char *));
    ap_server_post_read_config = apr_array_make(pcommands, 1, sizeof(const char *));
    ap_server_config_defines = apr_array_make(pcommands, 1, sizeof(const char *));

    if (!confname) {
        confname = "fuzz.conf";
    }

    ap_server_root = def_server_root;

    err = ap_setup_prelinked_modules(process);
    if (err) {
        fprintf(stderr, "ap_setup_prelinked_modules: %s\n", err);
        return -1;
    }

    fuzz_register_hooks(g_pconf);
    fuzz_mpm_hooks(g_pconf);

    apr_pool_create(&g_plog, g_pool);
    apr_pool_tag(g_plog, "plog");

    apr_pool_create(&ptemp, g_pconf);
    apr_pool_tag(ptemp, "ptemp");

    ap_init_rng(g_pool);

    ap_server_conf = NULL;
    g_server = ap_read_config(process, ptemp, confname, &ap_conftree);
    if (!g_server) {
        fprintf(stderr, "Failed to read config file: %s\n", confname);
        return -1;
    }
    ap_server_conf = g_server;

    apr_hook_sort_all();

    if (ap_run_pre_config(g_pconf, g_plog, ptemp) != OK) {
        fprintf(stderr, "pre_config failed\n");
        return -1;
    }

    if (ap_process_config_tree(g_server, ap_conftree, g_pconf, ptemp) != OK) {
        fprintf(stderr, "process_config_tree failed\n");
        return -1;
    }

    ap_fixup_virtual_hosts(g_pconf, g_server);
    ap_fini_vhost_config(g_pconf, g_server);

    apr_hook_sort_all();

    if (ap_run_check_config(g_pconf, g_plog, ptemp, g_server) != OK) {
        fprintf(stderr, "check_config failed\n");
        return -1;
    }

    /* Skip open_logs in LIBFUZZER/AFL mode - it can hang due to
     * signal handling conflicts */
#if !defined(LIBFUZZER) && !defined(AFL_FUZZ)
    apr_pool_clear(g_plog);
    if (ap_run_open_logs(g_pconf, g_plog, ptemp, g_server) != OK) {
        fprintf(stderr, "open_logs failed\n");
        return -1;
    }
#endif

    if (ap_run_post_config(g_pconf, g_plog, ptemp, g_server) != OK) {
        fprintf(stderr, "post_config failed\n");
        return -1;
    }

    apr_pool_destroy(ptemp);

    /* Run child_init hooks - modules like mod_proxy initialize per-process
     * state here (e.g. proxy worker connection pools). Without this,
     * proxy workers are never marked PROXY_WORKER_INITIALIZED and all
     * proxy requests fail with "disabled connection" (AH00940).
     */
    ap_run_child_init(g_pconf, g_server);

    ap_run_optional_fn_retrieve();

#ifdef ASAN_ENABLED
    asan_restore_stderr_and_signals();
    register_ubsan_signal_handler();
#endif

    g_initialized = 1;
    return 0;
}

/* ----------------------------------------------------------------
 * Process one fuzz input
 * ---------------------------------------------------------------- */

int fuzz_one_input(const char *data, size_t size)
{
    apr_pool_t *ptrans;
    conn_rec *c;
    apr_bucket_alloc_t *bucket_alloc;
    static long conn_id = 0;

    if (size == 0) {
        return 0;
    }

    g_input_data = (char *)data;
    g_input_size = size;
    g_input_offset = 0;

    apr_pool_create(&ptrans, g_pconf);
    apr_pool_tag(ptrans, "transaction");

    bucket_alloc = apr_bucket_alloc_create(ptrans);

    c = apr_pcalloc(ptrans, sizeof(*c));
    c->pool = ptrans;
    c->base_server = g_server;
    c->id = ++conn_id;
    c->bucket_alloc = bucket_alloc;
    c->conn_config = ap_create_conn_config(ptrans);
    c->notes = apr_table_make(ptrans, 5);
    c->sbh = NULL;

    c->local_addr = create_fake_sockaddr(ptrans, "127.0.0.1", 80);
    c->client_addr = create_fake_sockaddr(ptrans, "127.0.0.1", 12345);
    c->local_ip = "127.0.0.1";
    c->client_ip = "127.0.0.1";
    c->local_host = "localhost";
    c->remote_host = "localhost";

    /* Tag this as the fuzz client connection so fuzz_pre_connection
     * only intercepts it, not proxy backend connections. */
    apr_table_setn(c->notes, "fuzz_client", "1");

    ap_process_connection(c, NULL);

    apr_pool_destroy(ptrans);

    g_input_data = NULL;
    g_input_size = 0;

    return 0;
}

/* ----------------------------------------------------------------
 * Coverage-safe exit
 * ---------------------------------------------------------------- */

/*
 * Weak reference to LLVM's profile write function.  In coverage builds
 * (compiled with -fprofile-instr-generate) this resolves to the real
 * function; in all other builds it stays NULL.
 */
int __llvm_profile_write_file(void) __attribute__((weak));

void fuzz_exit(int status)
{
    /* _exit() skips atexit handlers and does NOT flush stdio buffers.
     * Flush stdout so the HTTP response (written by the output filter
     * via fwrite) is not lost when the harness is run standalone. */
    fflush(stdout);

    /* Flush LLVM coverage (.profraw) data before _exit(), because
     * _exit() skips atexit handlers where LLVM normally writes it. */
    if (__llvm_profile_write_file) {
        __llvm_profile_write_file();
    }
    _exit(status);
}
