/*
 * mod_rewrite Custom Mutator for AFL++
 *
 * Structure-aware mutations targeting mod_rewrite's URL rewriting engine.
 * Focuses on crafting HTTP requests with URLs, query strings, and headers
 * that exercise rewrite rules, backreference expansion, variable lookups,
 * RewriteMap functions, and flag processing.
 *
 * Strategies:
 *  0 - Swap request URI to target a specific rewrite rule
 *  1 - Inject/corrupt query string (exercises QSA/QSD, %{QUERY_STRING})
 *  2 - Inject headers that trigger RewriteCond (%{HTTP:xxx})
 *  3 - Mutate path segments (backreference boundaries)
 *  4 - Inject encoded/special characters (exercises escape_backref, [B])
 *  5 - Generate deeply nested or very long paths
 *  6 - Inject multiple headers at once (Host, User-Agent, Accept, X-Custom)
 *  7 - Combine: swap URI + inject query + inject header
 *
 * Compile:
 *   clang -shared -fPIC -O3 -o rewrite_mutator.so rewrite_mutator.c
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct afl_state {
    void *afl;
} afl_state_t;

typedef struct my_mutator {
    afl_state_t *afl;
    unsigned int seed;
} my_mutator_t;

#define MAX_BUF (1024 * 1024)
static uint8_t tmp_buf[MAX_BUF];

/* -- URI payloads targeting specific rules in rewrite.conf ------ */

static const char *uri_payloads[] = {
    /* Rule 1: simple redirect */
    "/old/foo/bar/baz",
    "/old/../../etc/passwd",
    "/old/%2e%2e/%2e%2e/etc/passwd",
    "/old/a%00b",
    /* Rule 2: item with query */
    "/item",
    /* Rule 3: tolower map */
    "/upper/HELLO",
    "/upper/AbCdEfGhIjKlMnOpQrStUvWxYz",
    "/upper/FOO%2FBAR",
    /* Rule 4: toupper map */
    "/shout/hello-world",
    /* Rule 5: multi-backreference */
    "/user/admin/edit/12345",
    "/user/a%00b/c%0dd/e%0af",
    "/user/AAAAAAAAAAAAAAAA/BBBBBBBBBBBBBBBB/CCCCCCCCCCCCCCCC",
    /* Rule 6: search with QSA */
    "/search/test",
    "/search/foo%26bar=baz",
    /* Rule 7: QSD */
    "/clean/page",
    /* Rule 10: env setting */
    "/track/payload$1%{QUERY_STRING}",
    /* Rule 11: cookie setting */
    "/setcookie/value%3bsecure%3bhttponly",
    /* Rule 12: chain */
    "/chain/data",
    /* Rule 14: case-insensitive */
    "/CaSe/MiXeD",
    "/case/lower",
    "/CASE/UPPER",
    /* Rule 15: hash/NE */
    "/hash/section#anchor",
    "/hash/%23already-encoded",
    /* Rule 17: escape/B flag */
    "/escape/hello world",
    "/escape/<script>alert(1)</script>",
    "/escape/foo%00bar%0d%0abaz",
    /* Rule 18: method-based */
    "/method",
    /* Rule 19: fallback (file not found) */
    "/fallback/nonexistent",
    /* Rule 20: multi-condition */
    "/multi/page.html",
    /* Rule 21: OR condition */
    "/or/test",
    /* Rule 22: API versioned */
    "/api/users/list",
    "/v1/resource/action",
    "/v999/a/b/c/d/e",
    "/rest/endpoint/path/to/thing",
    /* Rule 23: nested map */
    "/nested/Hello-World",
    "/nested/ABCDEFGHIJ",
    /* Rule 26: restricted */
    "/restricted/secret",
    /* Rule 27: download */
    "/download/file.dat",
    /* Rule 28: cgi handler */
    "/cgi/test.cgi",
    /* Rule 29: N-flag loop (strip x's) */
    "/xxxxxxxxxx",
    "/xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    "/xxxfoo",
    /* Rule 30: catch-all */
    "/catchall/anything",
    /* Edge cases */
    "/",
    "",
    "/../../../etc/passwd",
    "/a"
    "?b"
    "#c",
    "/%2e%2e/%2e%2e/%2e%2e/%2e%2e/",
    "/rewrite/../rewrite/../rewrite",
};
static const int num_uris = sizeof(uri_payloads) / sizeof(uri_payloads[0]);

/* -- Query string payloads ---------------------------------------- */

static const char *qs_payloads[] = {
    "id=42",
    "id=99999999999999999",
    "id=-1",
    "id=0",
    "id=abc",
    "needle",
    "a=1&b=2&c=3&d=4&e=5&f=6&g=7&h=8",
    "foo=bar%00baz",
    "key=%0d%0aInjected-Header:%20value",
    "q=hello+world&lang=en",
    "redirect=http://evil.com",
    "path=../../../etc/passwd",
    "",
    "a="
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    "%00=%00",
    "id=1%27%20OR%201%3D1",
    "term=<script>alert(1)</script>",
    "x=1&x=2&x=3&x=4&x=5",
};
static const int num_qs = sizeof(qs_payloads) / sizeof(qs_payloads[0]);

/* -- HTTP method payloads ----------------------------------------- */

static const char *method_payloads[] = {
    "GET",   "POST",  "PUT",     "DELETE",   "HEAD", "OPTIONS",
    "PATCH", "TRACE", "CONNECT", "PROPFIND", "AAAA",
};
static const int num_methods = sizeof(method_payloads) / sizeof(method_payloads[0]);

/* -- Header payloads for RewriteCond triggers --------------------- */

static const char *host_payloads[] = {
    "Host: localhost\r\n",
    "Host: www.example.com\r\n",
    "Host: www.evil.com\r\n",
    "Host: 127.0.0.1\r\n",
    "Host: localhost:8080\r\n",
    "Host: \r\n",
    "Host: localhost\x00evil.com\r\n",
};
static const int num_hosts = sizeof(host_payloads) / sizeof(host_payloads[0]);

static const char *ua_payloads[] = {
    "User-Agent: Mozilla/5.0\r\n",
    "User-Agent: Googlebot/2.1\r\n",
    "User-Agent: crawler\r\n",
    "User-Agent: spider-bot\r\n",
    "User-Agent: \r\n",
    "User-Agent: "
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\r\n",
};
static const int num_uas = sizeof(ua_payloads) / sizeof(ua_payloads[0]);

static const char *accept_payloads[] = {
    "Accept: text/html\r\n", "Accept: application/json\r\n",
    "Accept: */*\r\n",       "Accept: text/html, application/xhtml+xml\r\n",
    "Accept: \r\n",
};
static const int num_accepts = sizeof(accept_payloads) / sizeof(accept_payloads[0]);

static const char *xcustom_payloads[] = {
    "X-Custom: needle\r\n",         "X-Custom: not-needle\r\n", "X-Custom: \r\n",
    "X-Custom: %{REQUEST_URI}\r\n", "X-Custom: $1%1\r\n",
};
static const int num_xcustoms = sizeof(xcustom_payloads) / sizeof(xcustom_payloads[0]);

/* -- Helpers ------------------------------------------------------ */

static size_t find_headers_end(const uint8_t *buf, size_t buf_size)
{
    if (buf_size < 4)
        return 0;
    for (size_t i = 0; i <= buf_size - 4; i++) {
        if (buf[i] == '\r' && buf[i + 1] == '\n' && buf[i + 2] == '\r' && buf[i + 3] == '\n') {
            return i;
        }
    }
    return 0;
}

/* Find end of request line (first \r\n) */
static size_t find_request_line_end(const uint8_t *buf, size_t buf_size)
{
    for (size_t i = 0; i + 1 < buf_size; i++) {
        if (buf[i] == '\r' && buf[i + 1] == '\n')
            return i;
    }
    return 0;
}

/* Insert a header string before \r\n\r\n */
static size_t insert_header(
    const uint8_t *buf, size_t buf_size, uint8_t *out, size_t max_size, const char *header,
    size_t hlen
)
{
    size_t hend = find_headers_end(buf, buf_size);
    if (hend == 0)
        return 0;

    size_t prefix_len = hend + 2;
    size_t rest_len = buf_size - prefix_len;

    if (prefix_len + hlen + rest_len > max_size)
        return 0;

    memcpy(out, buf, prefix_len);
    memcpy(out + prefix_len, header, hlen);
    memcpy(out + prefix_len + hlen, buf + prefix_len, rest_len);
    return prefix_len + hlen + rest_len;
}

/* -- Strategy 0: Swap the request URI ----------------------------- */

static size_t swap_uri(const uint8_t *buf, size_t buf_size, uint8_t *out, size_t max_size)
{
    size_t rle = find_request_line_end(buf, buf_size);
    if (rle == 0)
        return 0;

    /* Find spaces in request line: METHOD<sp>URI<sp>HTTP/x.y */
    const uint8_t *sp1 = memchr(buf, ' ', rle);
    if (!sp1)
        return 0;
    size_t method_len = sp1 - buf;
    sp1++;

    const uint8_t *sp2 = memchr(sp1, ' ', rle - (sp1 - buf));
    if (!sp2)
        return 0;

    /* Pick a new URI */
    const char *new_uri = uri_payloads[rand() % num_uris];
    size_t new_uri_len = strlen(new_uri);

    /* Optionally append query string */
    char uri_buf[4096];
    if (rand() % 3 == 0 && new_uri_len < sizeof(uri_buf) - 256) {
        const char *qs = qs_payloads[rand() % num_qs];
        int n = snprintf(uri_buf, sizeof(uri_buf), "%s?%s", new_uri, qs);
        if (n > 0 && (size_t)n < sizeof(uri_buf)) {
            new_uri = uri_buf;
            new_uri_len = n;
        }
    }

    /* Build: METHOD <new_uri> HTTP/... rest */
    size_t rest_start = sp2 - buf;
    size_t rest_len = buf_size - rest_start;
    size_t total = method_len + 1 + new_uri_len + rest_len;

    if (total > max_size)
        return 0;

    memcpy(out, buf, method_len + 1); /* METHOD + space */
    size_t pos = method_len + 1;
    memcpy(out + pos, new_uri, new_uri_len);
    pos += new_uri_len;
    memcpy(out + pos, buf + rest_start, rest_len);
    return pos + rest_len;
}

/* -- Strategy 1: Inject or replace query string ------------------- */

static size_t mutate_query(const uint8_t *buf, size_t buf_size, uint8_t *out, size_t max_size)
{
    size_t rle = find_request_line_end(buf, buf_size);
    if (rle == 0)
        return 0;

    /* Find URI portion */
    const uint8_t *sp1 = memchr(buf, ' ', rle);
    if (!sp1)
        return 0;
    sp1++;

    const uint8_t *sp2 = memchr(sp1, ' ', rle - (sp1 - buf));
    if (!sp2)
        return 0;

    size_t uri_start = sp1 - buf;
    size_t uri_len = sp2 - sp1;

    /* Find existing '?' in URI */
    const uint8_t *qmark = memchr(sp1, '?', uri_len);
    size_t path_len = qmark ? (size_t)(qmark - sp1) : uri_len;

    /* Build new request line with injected query string */
    const char *qs = qs_payloads[rand() % num_qs];
    char new_uri[4096];
    int n = snprintf(new_uri, sizeof(new_uri), "%.*s?%s", (int)path_len, sp1, qs);
    if (n <= 0 || (size_t)n >= sizeof(new_uri))
        return 0;

    size_t prefix_len = uri_start;
    size_t rest_start = sp2 - buf;
    size_t rest_len = buf_size - rest_start;
    size_t total = prefix_len + n + rest_len;

    if (total > max_size)
        return 0;

    memcpy(out, buf, prefix_len);
    memcpy(out + prefix_len, new_uri, n);
    memcpy(out + prefix_len + n, buf + rest_start, rest_len);
    return total;
}

/* -- Strategy 2: Inject a rewrite-triggering header --------------- */

static size_t
inject_rewrite_header(const uint8_t *buf, size_t buf_size, uint8_t *out, size_t max_size)
{
    int which = rand() % 4;
    const char *hdr;

    switch (which) {
    case 0:
        hdr = host_payloads[rand() % num_hosts];
        break;
    case 1:
        hdr = ua_payloads[rand() % num_uas];
        break;
    case 2:
        hdr = accept_payloads[rand() % num_accepts];
        break;
    default:
        hdr = xcustom_payloads[rand() % num_xcustoms];
        break;
    }

    return insert_header(buf, buf_size, out, max_size, hdr, strlen(hdr));
}

/* -- Strategy 3: Mutate path segments ----------------------------- */

static size_t
mutate_path_segments(const uint8_t *buf, size_t buf_size, uint8_t *out, size_t max_size)
{
    size_t rle = find_request_line_end(buf, buf_size);
    if (rle == 0)
        return 0;

    const uint8_t *sp1 = memchr(buf, ' ', rle);
    if (!sp1)
        return 0;
    sp1++;

    const uint8_t *sp2 = memchr(sp1, ' ', rle - (sp1 - buf));
    if (!sp2)
        return 0;

    size_t uri_start = sp1 - buf;
    size_t uri_len = sp2 - sp1;

    /* Copy URI into mutable buffer */
    char uri[4096];
    if (uri_len >= sizeof(uri))
        uri_len = sizeof(uri) - 1;
    memcpy(uri, sp1, uri_len);
    uri[uri_len] = '\0';

    /* Find '/' separators and randomly mutate segments */
    static const char *segment_mutations[] = {
        "..",
        ".",
        "%2e%2e",
        "%00",
        "AAAA",
        "a%00b",
        "${jndi:ldap://evil}",
        "%0d%0a",
        "\\",
        "//",
        "a"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    };
    int num_seg_mutations = sizeof(segment_mutations) / sizeof(segment_mutations[0]);

    /* Replace a random '/' segment */
    char *slash = strchr(uri + 1, '/');
    if (slash) {
        char *next_slash = strchr(slash + 1, '/');
        char *seg_end = next_slash ? next_slash : uri + uri_len;

        /* Remove old segment content, insert mutation */
        const char *mutation = segment_mutations[rand() % num_seg_mutations];
        size_t mut_len = strlen(mutation);
        size_t before = slash + 1 - uri;
        size_t after_len = uri + uri_len - seg_end;

        if (before + mut_len + after_len >= sizeof(uri))
            return 0;

        memmove(uri + before + mut_len, seg_end, after_len + 1);
        memcpy(uri + before, mutation, mut_len);
        uri_len = before + mut_len + after_len;
    }

    /* Rebuild request */
    size_t prefix_len = uri_start;
    size_t rest_start = sp2 - buf;
    size_t rest_len = buf_size - rest_start;
    size_t total = prefix_len + uri_len + rest_len;

    if (total > max_size)
        return 0;

    memcpy(out, buf, prefix_len);
    memcpy(out + prefix_len, uri, uri_len);
    memcpy(out + prefix_len + uri_len, buf + rest_start, rest_len);
    return total;
}

/* -- Strategy 4: Inject encoded/special chars in URI -------------- */

static size_t
inject_special_chars(const uint8_t *buf, size_t buf_size, uint8_t *out, size_t max_size)
{
    /* Build a fresh request with pathological URI */
    static const char *special_uris[] = {
        "/escape/%00%01%02%03%04%05%06%07%08%09%0a%0b%0c%0d%0e%0f",
        "/old/foo%20bar%09baz%0d%0aqux",
        "/upper/%C3%BC%C3%B6%C3%A4", /* UTF-8 umlauts */
        "/search/%E2%80%8B",         /* zero-width space */
        "/user/%252F/%252F/%252F",   /* double-encoded slashes */
        "/nested/%2500%2501%2502",
        "/escape/a b c d e f g h",
        "/old/foo%ff%fe%fd",
        "/chain/test%0d%0aX-Injected: yes",
        "/track/$1%{QUERY_STRING}%1%2%3",
        "/setcookie/val%3B%20domain%3D.evil.com",
    };
    int num_special = sizeof(special_uris) / sizeof(special_uris[0]);

    const char *uri = special_uris[rand() % num_special];

    /* Find headers end to preserve rest of request */
    size_t rle = find_request_line_end(buf, buf_size);
    if (rle == 0) {
        /* Build minimal request from scratch */
        int n = snprintf((char *)out, max_size, "GET %s HTTP/1.1\r\nHost: localhost\r\n\r\n", uri);
        return (n > 0 && (size_t)n < max_size) ? n : 0;
    }

    /* Replace URI in existing request */
    const uint8_t *sp1 = memchr(buf, ' ', rle);
    if (!sp1)
        return 0;

    size_t method_len = sp1 - buf;
    sp1++;

    const uint8_t *sp2 = memchr(sp1, ' ', rle - (sp1 - buf));
    if (!sp2)
        return 0;

    size_t uri_len = strlen(uri);
    size_t rest_start = sp2 - buf;
    size_t rest_len = buf_size - rest_start;
    size_t total = method_len + 1 + uri_len + rest_len;

    if (total > max_size)
        return 0;

    memcpy(out, buf, method_len + 1);
    size_t pos = method_len + 1;
    memcpy(out + pos, uri, uri_len);
    pos += uri_len;
    memcpy(out + pos, buf + rest_start, rest_len);
    return pos + rest_len;
}

/* -- Strategy 5: Very long or deeply nested paths ----------------- */

static size_t inject_long_path(const uint8_t *buf, size_t buf_size, uint8_t *out, size_t max_size)
{
    size_t rle = find_request_line_end(buf, buf_size);
    if (rle == 0)
        return 0;

    const uint8_t *sp1 = memchr(buf, ' ', rle);
    if (!sp1)
        return 0;
    size_t method_len = sp1 - buf;
    sp1++;

    const uint8_t *sp2 = memchr(sp1, ' ', rle - (sp1 - buf));
    if (!sp2)
        return 0;

    /* Build a long path */
    char path[8192];
    int pos = 0;
    int variant = rand() % 4;

    if (variant == 0) {
        /* Deep nesting: /a/b/c/d/.../z */
        int depth = 50 + rand() % 200;
        for (int i = 0; i < depth && pos < (int)sizeof(path) - 4; i++) {
            path[pos++] = '/';
            path[pos++] = 'a' + (i % 26);
        }
    } else if (variant == 1) {
        /* Long single segment: /AAAA...A */
        path[pos++] = '/';
        int len = 1000 + rand() % 4000;
        for (int i = 0; i < len && pos < (int)sizeof(path) - 1; i++)
            path[pos++] = 'A' + (i % 26);
    } else if (variant == 2) {
        /* Many x's for the [N] loop rule */
        int len = 50 + rand() % 500;
        path[pos++] = '/';
        for (int i = 0; i < len && pos < (int)sizeof(path) - 1; i++)
            path[pos++] = 'x';
    } else {
        /* Repeated ../  traversal */
        int count = 20 + rand() % 80;
        for (int i = 0; i < count && pos < (int)sizeof(path) - 4; i++) {
            path[pos++] = '/';
            path[pos++] = '.';
            path[pos++] = '.';
        }
    }
    path[pos] = '\0';

    size_t rest_start = sp2 - buf;
    size_t rest_len = buf_size - rest_start;
    size_t total = method_len + 1 + pos + rest_len;

    if (total > max_size)
        return 0;

    memcpy(out, buf, method_len + 1);
    size_t opos = method_len + 1;
    memcpy(out + opos, path, pos);
    opos += pos;
    memcpy(out + opos, buf + rest_start, rest_len);
    return opos + rest_len;
}

/* -- Strategy 6: Inject multiple headers -------------------------- */

static size_t
inject_multi_headers(const uint8_t *buf, size_t buf_size, uint8_t *out, size_t max_size)
{
    size_t hend = find_headers_end(buf, buf_size);
    if (hend == 0)
        return 0;

    char block[2048];
    int blen = 0;
    int count = 2 + rand() % 4;

    for (int i = 0; i < count && blen < (int)sizeof(block) - 256; i++) {
        int which = rand() % 5;
        int added = 0;

        if (which == 0)
            added = snprintf(
                block + blen, sizeof(block) - blen, "%s", host_payloads[rand() % num_hosts]
            );
        else if (which == 1)
            added =
                snprintf(block + blen, sizeof(block) - blen, "%s", ua_payloads[rand() % num_uas]);
        else if (which == 2)
            added = snprintf(
                block + blen, sizeof(block) - blen, "%s", accept_payloads[rand() % num_accepts]
            );
        else if (which == 3)
            added = snprintf(
                block + blen, sizeof(block) - blen, "%s", xcustom_payloads[rand() % num_xcustoms]
            );
        else
            added = snprintf(block + blen, sizeof(block) - blen, "X-Fuzz-%d: %08x\r\n", i, rand());

        if (added > 0)
            blen += added;
    }

    return insert_header(buf, buf_size, out, max_size, block, blen);
}

/* -- Strategy 7: Swap method -------------------------------------- */

static size_t swap_method(const uint8_t *buf, size_t buf_size, uint8_t *out, size_t max_size)
{
    size_t rle = find_request_line_end(buf, buf_size);
    if (rle == 0)
        return 0;

    const uint8_t *sp1 = memchr(buf, ' ', rle);
    if (!sp1)
        return 0;

    const char *new_method = method_payloads[rand() % num_methods];
    size_t new_mlen = strlen(new_method);
    size_t rest_start = sp1 - buf;
    size_t rest_len = buf_size - rest_start;
    size_t total = new_mlen + rest_len;

    if (total > max_size)
        return 0;

    memcpy(out, new_method, new_mlen);
    memcpy(out + new_mlen, buf + rest_start, rest_len);
    return total;
}

/* -- Strategy 8: Combined mutation -------------------------------- */

static size_t combined_mutation(const uint8_t *buf, size_t buf_size, uint8_t *out, size_t max_size)
{
    /* First swap URI */
    uint8_t stage1[MAX_BUF];
    size_t s1 = swap_uri(buf, buf_size, stage1, sizeof(stage1));
    if (s1 == 0) {
        s1 = buf_size < sizeof(stage1) ? buf_size : sizeof(stage1);
        memcpy(stage1, buf, s1);
    }

    /* Then inject a header */
    size_t result = inject_rewrite_header(stage1, s1, out, max_size);
    return result;
}

/* -- AFL++ API ---------------------------------------------------- */

void *afl_custom_init(afl_state_t *afl, unsigned int seed)
{
    my_mutator_t *data = calloc(1, sizeof(my_mutator_t));
    if (!data)
        return NULL;
    data->afl = afl;
    data->seed = seed;
    srand(seed);
    return data;
}

void afl_custom_deinit(void *data)
{
    free(data);
}

size_t afl_custom_fuzz(
    void *data, uint8_t *buf, size_t buf_size, uint8_t **out_buf, uint8_t *add_buf,
    size_t add_buf_size, size_t max_size
)
{
    (void)data;
    (void)add_buf;
    (void)add_buf_size;

    *out_buf = tmp_buf;

    if (max_size > MAX_BUF)
        max_size = MAX_BUF;

    int strategy = rand() % 100;
    size_t new_size = 0;

    if (strategy < 25) {
        new_size = swap_uri(buf, buf_size, tmp_buf, max_size);
    } else if (strategy < 40) {
        new_size = mutate_query(buf, buf_size, tmp_buf, max_size);
    } else if (strategy < 52) {
        new_size = inject_rewrite_header(buf, buf_size, tmp_buf, max_size);
    } else if (strategy < 62) {
        new_size = mutate_path_segments(buf, buf_size, tmp_buf, max_size);
    } else if (strategy < 72) {
        new_size = inject_special_chars(buf, buf_size, tmp_buf, max_size);
    } else if (strategy < 80) {
        new_size = inject_long_path(buf, buf_size, tmp_buf, max_size);
    } else if (strategy < 88) {
        new_size = inject_multi_headers(buf, buf_size, tmp_buf, max_size);
    } else if (strategy < 94) {
        new_size = swap_method(buf, buf_size, tmp_buf, max_size);
    } else {
        new_size = combined_mutation(buf, buf_size, tmp_buf, max_size);
    }

    /* Fallback: copy original input */
    if (new_size == 0 || new_size > max_size) {
        size_t sz = buf_size < max_size ? buf_size : max_size;
        memcpy(tmp_buf, buf, sz);
        new_size = sz;
    }

    return new_size;
}

size_t afl_custom_fuzz_count(void *data, const uint8_t *buf, size_t buf_size)
{
    (void)data;
    (void)buf;
    (void)buf_size;
    return 9;
}
