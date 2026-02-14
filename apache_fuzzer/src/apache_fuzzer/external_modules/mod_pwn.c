/*
 * mod_pwn - Intentionally Vulnerable Apache Module for Fuzzing Practice
 *
 * This module contains several intentional vulnerabilities for testing
 * fuzzing tools and coverage analysis. DO NOT USE IN PRODUCTION.
 *
 * Vulnerabilities included:
 * 1. Stack buffer overflow (X-Pwn-Overflow header)
 * 2. Heap buffer overflow (X-Pwn-Heap header)
 * 3. Use-after-free (X-Pwn-UAF header)
 * 4. NULL pointer dereference (X-Pwn-Null header)
 * 5. Integer overflow leading to small allocation (X-Pwn-Integer header)
 * 6. Format string vulnerability (X-Pwn-Format header)
 * 7. Double free (X-Pwn-Double header)
 *
 * Trigger with specific header values or URL patterns.
 */

#include "httpd.h"
#include "http_config.h"
#include "http_protocol.h"
#include "http_log.h"
#include "http_request.h"
#include "ap_config.h"
#include "apr_strings.h"
#include "apr_hash.h"

#include <string.h>
#include <stdlib.h>

/* Module declaration */
module AP_MODULE_DECLARE_DATA pwn_module;

/* Per-directory configuration */
typedef struct {
    int enabled;
    const char *secret_key;
    int debug_level;
} pwn_dir_config;

/* Global state for UAF demo */
static char *g_cached_data = NULL;
static int g_cache_freed = 0;

/*
 * Vulnerability 1: Stack Buffer Overflow
 * Trigger: X-Pwn-Overflow header with value > 64 bytes
 */
static void vuln_stack_overflow(request_rec *r, const char *input)
{
    char buffer[64];

    /* VULNERABLE: No bounds checking on strcpy */
    if (input && strlen(input) > 0) {
        strcpy(buffer, input);  /* BUG: Stack buffer overflow */
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                      "Stack buffer contains: %.32s...", buffer);
    }
}

/*
 * Vulnerability 2: Heap Buffer Overflow
 * Trigger: X-Pwn-Heap: <size>:<data> where data length > size
 */
static void vuln_heap_overflow(request_rec *r, const char *input)
{
    char *colon;
    int alloc_size;
    char *heap_buf;

    if (!input) return;

    colon = strchr(input, ':');
    if (!colon) return;

    alloc_size = atoi(input);
    if (alloc_size <= 0 || alloc_size > 1024) return;

    heap_buf = apr_palloc(r->pool, alloc_size);

    /* VULNERABLE: Copies more data than allocated */
    strcpy(heap_buf, colon + 1);  /* BUG: Heap buffer overflow */

    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                  "Heap buffer (%d bytes): %s", alloc_size, heap_buf);
}

/*
 * Vulnerability 3: Use-After-Free
 * Trigger: X-Pwn-UAF: free then X-Pwn-UAF: use
 */
static void vuln_use_after_free(request_rec *r, const char *input)
{
    if (!input) return;

    if (strcmp(input, "alloc") == 0) {
        /* Allocate and populate cache */
        if (g_cached_data) {
            free(g_cached_data);
        }
        g_cached_data = malloc(128);
        if (g_cached_data) {
            strcpy(g_cached_data, "cached_secret_data_here");
            g_cache_freed = 0;
        }
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "Cache allocated");
    }
    else if (strcmp(input, "free") == 0) {
        /* Free the cache but don't NULL the pointer */
        if (g_cached_data) {
            free(g_cached_data);  /* BUG: Pointer not nulled */
            g_cache_freed = 1;
        }
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "Cache freed");
    }
    else if (strcmp(input, "use") == 0) {
        /* Use the (possibly freed) cache */
        if (g_cached_data) {
            /* BUG: Use-after-free if cache was freed */
            ap_rprintf(r, "Cache data: %s\n", g_cached_data);
        }
    }
}

/*
 * Vulnerability 4: NULL Pointer Dereference
 * Trigger: X-Pwn-Null: deref
 */
static void vuln_null_deref(request_rec *r, const char *input)
{
    char *ptr = NULL;

    if (!input) return;

    if (strcmp(input, "deref") == 0) {
        /* VULNERABLE: Deliberate NULL dereference */
        ap_rprintf(r, "Value: %c\n", *ptr);  /* BUG: NULL deref */
    }
    else if (strcmp(input, "partial") == 0) {
        /* Conditional NULL deref based on missing config */
        pwn_dir_config *conf = ap_get_module_config(r->per_dir_config, &pwn_module);
        /* BUG: conf->secret_key may be NULL */
        ap_rprintf(r, "Key length: %zu\n", strlen(conf->secret_key));
    }
}

/*
 * Vulnerability 5: Integer Overflow
 * Trigger: X-Pwn-Integer: <large_number>
 */
static void vuln_integer_overflow(request_rec *r, const char *input)
{
    unsigned int count;
    unsigned int alloc_size;
    char *buffer;

    if (!input) return;

    count = (unsigned int)atol(input);

    /* VULNERABLE: Integer overflow in size calculation */
    alloc_size = count * sizeof(int);  /* BUG: Can overflow to small value */

    if (alloc_size > 0 && alloc_size < 0x10000) {
        buffer = apr_palloc(r->pool, alloc_size);

        /* Write beyond allocated buffer due to overflow */
        for (unsigned int i = 0; i < count && i < 1000; i++) {
            ((int*)buffer)[i] = i;  /* BUG: Writes past buffer if overflow */
        }

        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                      "Allocated %u bytes for %u ints", alloc_size, count);
    }
}

/*
 * Vulnerability 6: Format String
 * Trigger: X-Pwn-Format: %s%s%s%s%s%n
 */
static void vuln_format_string(request_rec *r, const char *input)
{
    char log_msg[256];

    if (!input) return;

    /* VULNERABLE: User input used as format string */
    snprintf(log_msg, sizeof(log_msg), input);  /* BUG: Format string */

    ap_rprintf(r, "Log: %s\n", log_msg);
}

/*
 * Vulnerability 7: Double Free
 * Trigger: X-Pwn-Double: trigger
 */
static void vuln_double_free(request_rec *r, const char *input)
{
    static char *shared_ptr = NULL;

    if (!input) return;

    if (strcmp(input, "alloc") == 0) {
        shared_ptr = malloc(64);
        if (shared_ptr) {
            strcpy(shared_ptr, "shared_data");
        }
    }
    else if (strcmp(input, "free1") == 0) {
        if (shared_ptr) {
            free(shared_ptr);  /* First free */
            /* BUG: Pointer not nulled */
        }
    }
    else if (strcmp(input, "free2") == 0) {
        if (shared_ptr) {
            free(shared_ptr);  /* BUG: Double free */
        }
    }
}

/*
 * Vulnerability 8: Out-of-bounds read via index
 * Trigger: URL /pwn/oob/<index> where index is out of bounds
 */
static const char *secret_table[] = {
    "public_value_0",
    "public_value_1",
    "public_value_2",
    "SECRET_ADMIN_KEY",  /* Index 3 - "hidden" */
    "SECRET_API_TOKEN",  /* Index 4 - "hidden" */
};
#define SECRET_TABLE_PUBLIC_SIZE 3

static void vuln_oob_read(request_rec *r, int index)
{
    /* VULNERABLE: Index not properly bounded */
    if (index >= 0) {
        /* BUG: Should check index < SECRET_TABLE_PUBLIC_SIZE */
        /* Instead checks against larger value, leaking secrets */
        if (index < 10) {
            ap_rprintf(r, "Value[%d]: %s\n", index, secret_table[index]);
        }
    }
}

/*
 * Vulnerability 9: Path traversal in file read simulation
 * Trigger: URL /pwn/read?file=../../../etc/passwd
 */
static void vuln_path_traversal(request_rec *r, const char *filename)
{
    char path[512];

    if (!filename) return;

    /* VULNERABLE: No sanitization of path */
    snprintf(path, sizeof(path), "/var/www/data/%s", filename);

    /* In a real bug, this would read the file */
    /* For demo, we just show the constructed path */
    ap_rprintf(r, "Would read: %s\n", path);

    /* Also has a buffer overflow if filename is very long */
}

/*
 * Main request handler
 */
static int pwn_handler(request_rec *r)
{
    pwn_dir_config *conf;
    const char *header_val;

    if (!r->handler || strcmp(r->handler, "pwn-handler") != 0) {
        return DECLINED;
    }

    conf = ap_get_module_config(r->per_dir_config, &pwn_module);
    if (!conf || !conf->enabled) {
        return DECLINED;
    }

    ap_set_content_type(r, "text/plain");

    /* Check for vulnerability triggers via headers */

    /* 1. Stack overflow */
    header_val = apr_table_get(r->headers_in, "X-Pwn-Overflow");
    if (header_val) {
        vuln_stack_overflow(r, header_val);
    }

    /* 2. Heap overflow */
    header_val = apr_table_get(r->headers_in, "X-Pwn-Heap");
    if (header_val) {
        vuln_heap_overflow(r, header_val);
    }

    /* 3. Use-after-free */
    header_val = apr_table_get(r->headers_in, "X-Pwn-UAF");
    if (header_val) {
        vuln_use_after_free(r, header_val);
    }

    /* 4. NULL deref */
    header_val = apr_table_get(r->headers_in, "X-Pwn-Null");
    if (header_val) {
        vuln_null_deref(r, header_val);
    }

    /* 5. Integer overflow */
    header_val = apr_table_get(r->headers_in, "X-Pwn-Integer");
    if (header_val) {
        vuln_integer_overflow(r, header_val);
    }

    /* 6. Format string */
    header_val = apr_table_get(r->headers_in, "X-Pwn-Format");
    if (header_val) {
        vuln_format_string(r, header_val);
    }

    /* 7. Double free */
    header_val = apr_table_get(r->headers_in, "X-Pwn-Double");
    if (header_val) {
        vuln_double_free(r, header_val);
    }

    /* Check URL path for additional triggers */
    if (r->uri) {
        /* /pwn/oob/<index> - out of bounds read */
        if (strncmp(r->uri, "/pwn/oob/", 9) == 0) {
            int index = atoi(r->uri + 9);
            vuln_oob_read(r, index);
        }
        /* /pwn/read?file=<path> - path traversal */
        else if (strncmp(r->uri, "/pwn/read", 9) == 0 && r->args) {
            if (strncmp(r->args, "file=", 5) == 0) {
                vuln_path_traversal(r, r->args + 5);
            }
        }
        /* /pwn/crash - immediate segfault */
        else if (strcmp(r->uri, "/pwn/crash") == 0) {
            int *null_ptr = NULL;
            *null_ptr = 42;  /* Immediate crash */
        }
        /* Default response */
        else {
            ap_rputs("mod_pwn active\n", r);
            ap_rputs("Available endpoints:\n", r);
            ap_rputs("  /pwn/oob/<index> - Out of bounds read\n", r);
            ap_rputs("  /pwn/read?file=<path> - Path traversal\n", r);
            ap_rputs("  /pwn/crash - Immediate crash\n", r);
            ap_rputs("\nHeaders:\n", r);
            ap_rputs("  X-Pwn-Overflow: <data> - Stack overflow\n", r);
            ap_rputs("  X-Pwn-Heap: <size>:<data> - Heap overflow\n", r);
            ap_rputs("  X-Pwn-UAF: alloc|free|use - Use-after-free\n", r);
            ap_rputs("  X-Pwn-Null: deref|partial - NULL deref\n", r);
            ap_rputs("  X-Pwn-Integer: <number> - Integer overflow\n", r);
            ap_rputs("  X-Pwn-Format: <fmt> - Format string\n", r);
            ap_rputs("  X-Pwn-Double: alloc|free1|free2 - Double free\n", r);
        }
    }

    return OK;
}

/*
 * Configuration directives
 */
static void *create_pwn_dir_config(apr_pool_t *p, char *dir)
{
    pwn_dir_config *conf = apr_pcalloc(p, sizeof(*conf));
    conf->enabled = 0;
    conf->secret_key = NULL;  /* Intentionally NULL for vuln demo */
    conf->debug_level = 0;
    return conf;
}

static const char *set_pwn_enabled(cmd_parms *cmd, void *cfg, int on)
{
    pwn_dir_config *conf = cfg;
    conf->enabled = on;
    return NULL;
}

static const char *set_pwn_secret(cmd_parms *cmd, void *cfg, const char *key)
{
    pwn_dir_config *conf = cfg;
    conf->secret_key = apr_pstrdup(cmd->pool, key);
    return NULL;
}

static const command_rec pwn_cmds[] = {
    AP_INIT_FLAG("PwnEnabled", set_pwn_enabled, NULL, OR_ALL,
                 "Enable the vulnerable pwn module"),
    AP_INIT_TAKE1("PwnSecret", set_pwn_secret, NULL, OR_ALL,
                  "Set a secret key (used in some vulns)"),
    { NULL }
};

/*
 * Module hooks
 */
static void register_hooks(apr_pool_t *p)
{
    ap_hook_handler(pwn_handler, NULL, NULL, APR_HOOK_MIDDLE);
}

/*
 * Module definition
 */
module AP_MODULE_DECLARE_DATA pwn_module = {
    STANDARD20_MODULE_STUFF,
    create_pwn_dir_config,  /* per-directory config creator */
    NULL,                   /* dir config merger */
    NULL,                   /* server config creator */
    NULL,                   /* server config merger */
    pwn_cmds,               /* command table */
    register_hooks          /* register hooks */
};
