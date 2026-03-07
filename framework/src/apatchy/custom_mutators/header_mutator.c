/*
 * Header Injection Mutator for AFL++
 *
 * Focuses on HTTP header manipulation to exercise header parsing,
 * cookie handling, date parsing, encoding detection, and other
 * header-driven code paths in mod_lua and Apache core.
 *
 * Strategies:
 * - Inject headers that trigger specific mod_lua code paths
 *   (Cookie, Date, If-Modified-Since, Authorization, Accept-Encoding)
 * - Header folding / continuation lines (obs-fold)
 * - CRLF injection in header values
 * - Very long header values
 * - Duplicate the Host header (triggers different server behavior)
 * - Inject malformed header lines (no colon, empty name, etc.)
 *
 * Compile:
 *   clang -shared -fPIC -O3 -o header_mutator.so header_mutator.c
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

/* Cookie payloads targeting handler.lua's getcookie("session"/"token"/"fuzz") */
static const char *cookie_payloads[] = {
    "session=test",
    "token=YWRtaW46cGFzcw==",
    "fuzz=value",
    "session=AAAA; token=BBBB; fuzz=CCCC",
    "session=; token=; fuzz=",
    "session=%00null; token=%0d%0a; fuzz=%3Cscript%3E",
    "session=" /* empty value */,
    "=noname",
    "session=a]b[c; token={{template}}; fuzz=${jndi:}",
    "session=test; session=override; token=dup; token=dup2",
};
static const int num_cookies = 10;

/* Date payloads targeting r:date_parse_rfc() */
static const char *date_payloads[] = {
    "Sat, 29 Oct 1994 19:43:31 GMT",
    "Sun, 06 Nov 1994 08:49:37 GMT",
    "Monday, 01-Jan-2024 00:00:00 GMT",
    "0",
    "-1",
    "99999999999999",
    "not a date at all",
    "\xff\xff\xff\xff",
    "",
    "Thu, 01 Jan 1970 00:00:00 GMT",
    "Fri, 31 Dec 9999 23:59:59 GMT",
    "Wed, 09 Jun 2021 10:18:14 GMT; extra=garbage",
};
static const int num_dates = 12;

/* Authorization payloads targeting r:basic_auth_pw */
static const char *auth_payloads[] = {
    "Basic YWRtaW46cGFzcw==",       /* admin:pass */
    "Basic dGVzdA==",                /* test (no colon) */
    "Basic ====",                    /* invalid b64 */
    "Basic ",                        /* empty credentials */
    "Bearer eyJhbGciOiJIUzI1NiJ9",  /* JWT-like */
    "Digest username=\"admin\"",
    "NTLM TlRMTVNTUA==",
    "",
    "Basic AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==",
};
static const int num_auths = 9;

/* Malformed header lines */
static const char *malformed_headers[] = {
    "NoColonHere\r\n",
    ": empty-name\r\n",
    "X-Empty:\r\n",
    "X-Space: \r\n",
    "X-Null: \x00value\r\n",
    "X-Tab:\tvalue\r\n",
    "X-Multi: val1\r\n\t continued\r\n",    /* obs-fold */
    "X-Multi: val1\r\n continued\r\n",      /* obs-fold with space */
    " X-Leading-Space: value\r\n",
    "X-CRLF: before\r\nInjected: after\r\n", /* header injection */
};
static const int num_malformed = 10;

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

/* Insert a header string before \r\n\r\n */
static size_t insert_before_body(const uint8_t *buf, size_t buf_size,
                                 uint8_t *out, size_t max_size,
                                 const char *header, size_t hlen)
{
    size_t hend = find_headers_end(buf, buf_size);
    if (hend == 0)
        return 0;

    /* Insert after existing headers (before the blank line) */
    size_t insert_at = hend + 2; /* after the first \r\n of \r\n\r\n */
    size_t suffix_len = buf_size - insert_at + 2; /* +2 to keep final \r\n */

    /* Actually insert right at hend+2 (between the two \r\n pairs) */
    size_t prefix_len = hend + 2;
    size_t rest_len = buf_size - prefix_len;

    if (prefix_len + hlen + rest_len > max_size)
        return 0;

    memcpy(out, buf, prefix_len);
    memcpy(out + prefix_len, header, hlen);
    memcpy(out + prefix_len + hlen, buf + prefix_len, rest_len);
    return prefix_len + hlen + rest_len;
}

/* Strategy 1: Inject Cookie header */
static size_t inject_cookie(const uint8_t *buf, size_t buf_size,
                            uint8_t *out, size_t max_size)
{
    const char *cookie = cookie_payloads[rand() % num_cookies];
    char hdr[512];
    int hlen = snprintf(hdr, sizeof(hdr), "Cookie: %s\r\n", cookie);
    if (hlen <= 0)
        return 0;
    return insert_before_body(buf, buf_size, out, max_size, hdr, hlen);
}

/* Strategy 2: Inject Date or If-Modified-Since */
static size_t inject_date(const uint8_t *buf, size_t buf_size,
                          uint8_t *out, size_t max_size)
{
    const char *date = date_payloads[rand() % num_dates];
    const char *name = (rand() % 2) ? "Date" : "If-Modified-Since";
    char hdr[256];
    int hlen = snprintf(hdr, sizeof(hdr), "%s: %s\r\n", name, date);
    if (hlen <= 0)
        return 0;
    return insert_before_body(buf, buf_size, out, max_size, hdr, hlen);
}

/* Strategy 3: Inject Authorization header */
static size_t inject_auth(const uint8_t *buf, size_t buf_size,
                          uint8_t *out, size_t max_size)
{
    const char *auth = auth_payloads[rand() % num_auths];
    char hdr[256];
    int hlen = snprintf(hdr, sizeof(hdr), "Authorization: %s\r\n", auth);
    if (hlen <= 0)
        return 0;
    return insert_before_body(buf, buf_size, out, max_size, hdr, hlen);
}

/* Strategy 4: Inject malformed header */
static size_t inject_malformed(const uint8_t *buf, size_t buf_size,
                               uint8_t *out, size_t max_size)
{
    const char *hdr = malformed_headers[rand() % num_malformed];
    return insert_before_body(buf, buf_size, out, max_size, hdr, strlen(hdr));
}

/* Strategy 5: Inject very long header value */
static size_t inject_long_header(const uint8_t *buf, size_t buf_size,
                                 uint8_t *out, size_t max_size)
{
    size_t hend = find_headers_end(buf, buf_size);
    if (hend == 0)
        return 0;

    const char *names[] = {"Cookie", "User-Agent", "Accept", "Referer",
                           "Authorization", "If-None-Match", "X-Fuzz"};
    const char *name = names[rand() % 7];
    size_t nlen = strlen(name);

    /* Value length: 256 to 8192 bytes */
    int vlen = 256 + rand() % 7937;

    /* Build: "Name: <pattern>\r\n" */
    size_t hdr_total = nlen + 2 + vlen + 2;
    size_t prefix_len = hend + 2;
    size_t rest_len = buf_size - prefix_len;

    if (prefix_len + hdr_total + rest_len > max_size)
        return 0;

    memcpy(out, buf, prefix_len);
    size_t pos = prefix_len;
    memcpy(out + pos, name, nlen);
    pos += nlen;
    out[pos++] = ':';
    out[pos++] = ' ';

    /* Fill with pattern: mix of printable chars */
    for (int i = 0; i < vlen; i++) {
        int r = rand() % 4;
        if (r == 0)
            out[pos + i] = 'A' + rand() % 26;
        else if (r == 1)
            out[pos + i] = '0' + rand() % 10;
        else if (r == 2)
            out[pos + i] = "=;, \t%&+/"[rand() % 9];
        else
            out[pos + i] = 0x20 + rand() % 95; /* any printable ASCII */
    }
    pos += vlen;
    out[pos++] = '\r';
    out[pos++] = '\n';
    memcpy(out + pos, buf + prefix_len, rest_len);
    return pos + rest_len;
}

/* Strategy 6: Duplicate the Host header with different values */
static size_t duplicate_host(const uint8_t *buf, size_t buf_size,
                             uint8_t *out, size_t max_size)
{
    const char *hosts[] = {
        "Host: localhost\r\n",
        "Host: 127.0.0.1\r\n",
        "Host: evil.com\r\n",
        "Host: localhost:80\r\n",
        "Host: \r\n",
        "Host: localhost\x00evil.com\r\n",
    };
    const char *hdr = hosts[rand() % 6];
    return insert_before_body(buf, buf_size, out, max_size, hdr, strlen(hdr));
}

/* Strategy 7: Inject multiple headers at once */
static size_t inject_multi(const uint8_t *buf, size_t buf_size,
                           uint8_t *out, size_t max_size)
{
    size_t hend = find_headers_end(buf, buf_size);
    if (hend == 0)
        return 0;

    /* Build a block of 2-5 headers */
    char block[2048];
    int blen = 0;
    int count = 2 + rand() % 4;

    for (int i = 0; i < count; i++) {
        int which = rand() % 5;
        int added = 0;
        if (which == 0)
            added = snprintf(block + blen, sizeof(block) - blen,
                             "Cookie: %s\r\n", cookie_payloads[rand() % num_cookies]);
        else if (which == 1)
            added = snprintf(block + blen, sizeof(block) - blen,
                             "Date: %s\r\n", date_payloads[rand() % num_dates]);
        else if (which == 2)
            added = snprintf(block + blen, sizeof(block) - blen,
                             "Authorization: %s\r\n", auth_payloads[rand() % num_auths]);
        else if (which == 3)
            added = snprintf(block + blen, sizeof(block) - blen,
                             "Accept-Encoding: %s\r\n",
                             (const char *[]){"gzip", "deflate", "br", "*", "identity"}[rand() % 5]);
        else
            added = snprintf(block + blen, sizeof(block) - blen,
                             "If-None-Match: \"%08x\"\r\n", rand());

        if (added > 0)
            blen += added;
    }

    return insert_before_body(buf, buf_size, out, max_size, block, blen);
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
        new_size = inject_cookie(buf, buf_size, tmp_buf, max_size);
    } else if (strategy < 35) {
        new_size = inject_date(buf, buf_size, tmp_buf, max_size);
    } else if (strategy < 45) {
        new_size = inject_auth(buf, buf_size, tmp_buf, max_size);
    } else if (strategy < 55) {
        new_size = inject_malformed(buf, buf_size, tmp_buf, max_size);
    } else if (strategy < 70) {
        new_size = inject_long_header(buf, buf_size, tmp_buf, max_size);
    } else if (strategy < 80) {
        new_size = duplicate_host(buf, buf_size, tmp_buf, max_size);
    } else {
        new_size = inject_multi(buf, buf_size, tmp_buf, max_size);
    }

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
