/*
 * HTTP Structure-Aware Custom Mutator for AFL++
 *
 * Understands HTTP request structure (request line / headers / body)
 * and applies targeted mutations to each section independently.
 *
 * Strategies:
 * - Swap HTTP methods (GET<->POST<->PUT<->DELETE etc.)
 * - Mutate query string parameters
 * - Corrupt Content-Length values
 * - Add/duplicate/remove headers
 * - Inject long values into random header positions
 *
 * Compile:
 *   clang -shared -fPIC -O3 -o http_mutator.so http_mutator.c
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

typedef struct afl_state {
    void *afl;
} afl_state_t;

typedef struct my_mutator {
    afl_state_t *afl;
    unsigned int seed;
} my_mutator_t;

#define MAX_BUF (1024 * 1024)
static uint8_t tmp_buf[MAX_BUF];

static const char *methods[] = {
    "GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD", "TRACE"
};
static const int num_methods = 8;

static const char *content_lengths[] = {
    "0", "1", "-1", "99999999", "4294967295", "2147483647",
    "2147483648", "18446744073709551615", "aaaa"
};
static const int num_cls = 9;

static const char *interesting_headers[] = {
    "Cookie: session=AAAA; token=BBBB; fuzz=CCCC\r\n",
    "Date: Sat, 29 Oct 1994 19:43:31 GMT\r\n",
    "If-Modified-Since: Sun, 06 Nov 1994 08:49:37 GMT\r\n",
    "Authorization: Basic YWRtaW46cGFzcw==\r\n",
    "Accept-Encoding: gzip, deflate\r\n",
    "Range: bytes=0-65535\r\n",
    "Content-Encoding: gzip\r\n",
    "Transfer-Encoding: chunked\r\n",
    "Connection: keep-alive\r\n",
    "X-Forwarded-For: 127.0.0.1\r\n",
    "If-None-Match: \"deadbeef\"\r\n",
    "Referer: http://localhost/test\r\n",
};
static const int num_interesting = 12;

static const char *query_params[] = {
    "name=test", "id=42", "action=delete", "token=abc123",
    "q=search%20term", "page=-1", "sort=<script>", "debug=true",
    "format=json", "callback=alert(1)", "file=../../../etc/passwd",
    "lang=%00", "type=null", "user=admin' OR 1=1",
};
static const int num_params = 14;

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

/* Find \r\n\r\n boundary between headers and body */
static size_t find_headers_end(const uint8_t *buf, size_t buf_size)
{
    if (buf_size < 4)
        return 0;
    for (size_t i = 0; i <= buf_size - 4; i++) {
        if (buf[i] == '\r' && buf[i + 1] == '\n' &&
            buf[i + 2] == '\r' && buf[i + 3] == '\n') {
            return i;
        }
    }
    return 0;
}

/* Find end of first line (request line) */
static size_t find_request_line_end(const uint8_t *buf, size_t buf_size)
{
    for (size_t i = 0; i < buf_size - 1; i++) {
        if (buf[i] == '\r' && buf[i + 1] == '\n')
            return i;
    }
    return 0;
}

/* Find first space in buffer (method/path separator) */
static size_t find_space(const uint8_t *buf, size_t limit)
{
    for (size_t i = 0; i < limit; i++) {
        if (buf[i] == ' ')
            return i;
    }
    return 0;
}

/* Strategy 1: Swap HTTP method */
static size_t swap_method(const uint8_t *buf, size_t buf_size, uint8_t *out, size_t max_size)
{
    size_t sp = find_space(buf, buf_size < 16 ? buf_size : 16);
    if (sp == 0)
        return 0;

    const char *new_method = methods[rand() % num_methods];
    size_t mlen = strlen(new_method);
    size_t rest = buf_size - sp;

    if (mlen + rest > max_size)
        return 0;

    memcpy(out, new_method, mlen);
    memcpy(out + mlen, buf + sp, rest);
    return mlen + rest;
}

/* Strategy 2: Inject/replace query string */
static size_t mutate_query(const uint8_t *buf, size_t buf_size, uint8_t *out, size_t max_size)
{
    size_t rl_end = find_request_line_end(buf, buf_size);
    if (rl_end == 0)
        return 0;

    /* Find path start (after first space) */
    size_t sp1 = find_space(buf, rl_end);
    if (sp1 == 0)
        return 0;

    /* Find path end (second space) */
    size_t sp2 = find_space(buf + sp1 + 1, rl_end - sp1 - 1);
    if (sp2 == 0)
        return 0;
    sp2 += sp1 + 1;

    /* Find existing '?' in path */
    size_t qmark = 0;
    for (size_t i = sp1 + 1; i < sp2; i++) {
        if (buf[i] == '?') {
            qmark = i;
            break;
        }
    }

    /* Build new query string with 1-4 params */
    char query[512];
    int qlen = 0;
    int nparams = 1 + rand() % 4;
    for (int i = 0; i < nparams; i++) {
        if (i > 0) query[qlen++] = '&';
        const char *p = query_params[rand() % num_params];
        int plen = strlen(p);
        if (qlen + plen >= (int)sizeof(query) - 1)
            break;
        memcpy(query + qlen, p, plen);
        qlen += plen;
    }
    query[qlen] = '\0';

    /* Assemble: method + path_before_query + ? + new_query + rest */
    size_t path_end = qmark ? qmark : sp2;
    size_t prefix_len = path_end;
    size_t suffix_start = sp2;
    size_t suffix_len = buf_size - suffix_start;

    if (prefix_len + 1 + qlen + suffix_len > max_size)
        return 0;

    memcpy(out, buf, prefix_len);
    out[prefix_len] = '?';
    memcpy(out + prefix_len + 1, query, qlen);
    memcpy(out + prefix_len + 1 + qlen, buf + suffix_start, suffix_len);
    return prefix_len + 1 + qlen + suffix_len;
}

/* Strategy 3: Corrupt Content-Length */
static size_t corrupt_content_length(const uint8_t *buf, size_t buf_size,
                                     uint8_t *out, size_t max_size)
{
    /* Find "Content-Length:" in headers */
    const char *needle = "Content-Length:";
    size_t nlen = strlen(needle);
    size_t pos = 0;
    int found = 0;

    for (size_t i = 0; i + nlen < buf_size; i++) {
        if (strncasecmp((const char *)buf + i, needle, nlen) == 0) {
            pos = i + nlen;
            found = 1;
            break;
        }
    }

    if (!found) {
        /* No Content-Length, inject one before headers end */
        size_t hend = find_headers_end(buf, buf_size);
        if (hend == 0)
            return 0;

        const char *val = content_lengths[rand() % num_cls];
        char header[64];
        int hlen = snprintf(header, sizeof(header), "Content-Length: %s\r\n", val);
        if (hlen <= 0)
            return 0;

        /* Insert before \r\n\r\n */
        size_t suffix_len = buf_size - hend;
        if (hend + hlen + suffix_len > max_size)
            return 0;

        memcpy(out, buf, hend);
        memcpy(out + hend, header, hlen);
        memcpy(out + hend + hlen, buf + hend, suffix_len);
        return hend + hlen + suffix_len;
    }

    /* Replace existing value up to \r\n */
    size_t val_end = pos;
    while (val_end < buf_size - 1 && !(buf[val_end] == '\r' && buf[val_end + 1] == '\n'))
        val_end++;

    const char *new_val = content_lengths[rand() % num_cls];
    size_t vlen = strlen(new_val);

    size_t suffix_len = buf_size - val_end;
    if (pos + 1 + vlen + suffix_len > max_size)
        return 0;

    memcpy(out, buf, pos);
    out[pos] = ' ';
    memcpy(out + pos + 1, new_val, vlen);
    memcpy(out + pos + 1 + vlen, buf + val_end, suffix_len);
    return pos + 1 + vlen + suffix_len;
}

/* Strategy 4: Inject interesting header */
static size_t inject_header(const uint8_t *buf, size_t buf_size,
                            uint8_t *out, size_t max_size)
{
    size_t hend = find_headers_end(buf, buf_size);
    if (hend == 0)
        return 0;

    const char *hdr = interesting_headers[rand() % num_interesting];
    size_t hlen = strlen(hdr);
    size_t suffix_len = buf_size - hend;

    if (hend + hlen + suffix_len > max_size)
        return 0;

    memcpy(out, buf, hend);
    memcpy(out + hend, hdr, hlen);
    memcpy(out + hend + hlen, buf + hend, suffix_len);
    return hend + hlen + suffix_len;
}

/* Strategy 5: Duplicate a random existing header */
static size_t duplicate_header(const uint8_t *buf, size_t buf_size,
                               uint8_t *out, size_t max_size)
{
    size_t hend = find_headers_end(buf, buf_size);
    if (hend == 0)
        return 0;

    /* Collect header line starts */
    size_t starts[64];
    size_t ends[64];
    int count = 0;

    size_t rl_end = find_request_line_end(buf, hend);
    if (rl_end == 0)
        return 0;

    size_t i = rl_end + 2; /* skip request line \r\n */
    while (i < hend && count < 64) {
        starts[count] = i;
        /* Find end of this header line */
        size_t j = i;
        while (j < hend - 1 && !(buf[j] == '\r' && buf[j + 1] == '\n'))
            j++;
        ends[count] = j + 2; /* include \r\n */
        count++;
        i = j + 2;
    }

    if (count == 0)
        return 0;

    /* Pick a random header to duplicate */
    int pick = rand() % count;
    size_t hdr_len = ends[pick] - starts[pick];

    if (buf_size + hdr_len > max_size)
        return 0;

    /* Insert duplicate before headers end */
    memcpy(out, buf, hend);
    memcpy(out + hend, buf + starts[pick], hdr_len);
    memcpy(out + hend + hdr_len, buf + hend, buf_size - hend);
    return buf_size + hdr_len;
}

/* Strategy 6: Inject long value into a header */
static size_t inject_long_value(const uint8_t *buf, size_t buf_size,
                                uint8_t *out, size_t max_size)
{
    size_t hend = find_headers_end(buf, buf_size);
    if (hend == 0)
        return 0;

    /* Build a header with a long value */
    int vlen = 128 + rand() % 4096;
    char pattern = 'A' + rand() % 26;

    char hdr_name[32];
    const char *names[] = {"Cookie", "User-Agent", "Referer", "Accept",
                           "Authorization", "X-Fuzz"};
    snprintf(hdr_name, sizeof(hdr_name), "%s", names[rand() % 6]);

    /* name: <pattern * vlen>\r\n */
    size_t hdr_total = strlen(hdr_name) + 2 + vlen + 2;
    size_t suffix_len = buf_size - hend;

    if (hend + hdr_total + suffix_len > max_size)
        return 0;

    memcpy(out, buf, hend);
    size_t pos = hend;
    size_t nlen = strlen(hdr_name);
    memcpy(out + pos, hdr_name, nlen);
    pos += nlen;
    out[pos++] = ':';
    out[pos++] = ' ';
    memset(out + pos, pattern, vlen);
    pos += vlen;
    out[pos++] = '\r';
    out[pos++] = '\n';
    memcpy(out + pos, buf + hend, suffix_len);
    return pos + suffix_len;
}

size_t afl_custom_fuzz(
    void *data, uint8_t *buf, size_t buf_size, uint8_t **out_buf,
    uint8_t *add_buf, size_t add_buf_size, size_t max_size
)
{
    *out_buf = tmp_buf;

    if (max_size > MAX_BUF)
        max_size = MAX_BUF;

    int strategy = rand() % 100;
    size_t new_size = 0;

    if (strategy < 20) {
        new_size = swap_method(buf, buf_size, tmp_buf, max_size);
    } else if (strategy < 40) {
        new_size = mutate_query(buf, buf_size, tmp_buf, max_size);
    } else if (strategy < 55) {
        new_size = corrupt_content_length(buf, buf_size, tmp_buf, max_size);
    } else if (strategy < 70) {
        new_size = inject_header(buf, buf_size, tmp_buf, max_size);
    } else if (strategy < 85) {
        new_size = duplicate_header(buf, buf_size, tmp_buf, max_size);
    } else {
        new_size = inject_long_value(buf, buf_size, tmp_buf, max_size);
    }

    /* Fallback: return input unchanged */
    if (new_size == 0 || new_size > max_size) {
        size_t sz = buf_size < max_size ? buf_size : max_size;
        memcpy(tmp_buf, buf, sz);
        new_size = sz;
    }

    return new_size;
}

size_t afl_custom_fuzz_count(void *data, const uint8_t *buf, size_t buf_size)
{
    return 8;
}
