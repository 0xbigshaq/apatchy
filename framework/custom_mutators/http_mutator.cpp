/*
 * HTTP Mutator for AFL++
 *
 * Structure-aware mutations for HTTP requests: method/query/URI
 * manipulation, header injection (cookies, auth, dates, malformed),
 * Content-Length corruption, and long value generation.
 */
// LANG: c++

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

#include "utils/AK.h"

#define MAX_BUF (1024 * 1024)

static const char *methods[] = {
    "GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD", "TRACE",
};
static const int num_methods = sizeof(methods) / sizeof(methods[0]);

static const char *query_params[] = {
    "name=test",
    "id=42",
    "action=delete",
    "token=abc123",
    "q=search%20term",
    "page=-1",
    "sort=<script>",
    "debug=true",
    "format=json",
    "callback=alert(1)",
    "file=../../../etc/passwd",
    "lang=%00",
    "type=null",
    "user=admin' OR 1=1",
};
static const int num_params = sizeof(query_params) / sizeof(query_params[0]);

static const char *cl_values[] = {
    "0",    "1", "-1", "99999999", "4294967295", "2147483647", "2147483648", "18446744073709551615",
    "aaaa",
};
static const int num_cls = sizeof(cl_values) / sizeof(cl_values[0]);

static const char *header_pool[] = {
    "Cookie: session=test\r\n",
    "Cookie: token=YWRtaW46cGFzcw==\r\n",
    "Cookie: fuzz=value\r\n",
    "Cookie: session=AAAA; token=BBBB; fuzz=CCCC\r\n",
    "Cookie: session=; token=; fuzz=\r\n",
    "Cookie: session=%00null; token=%0d%0a; fuzz=%3Cscript%3E\r\n",
    "Cookie: \r\n",
    "Cookie: =noname\r\n",
    "Cookie: session=a]b[c; token={{template}}; fuzz=${jndi:}\r\n",
    "Cookie: session=test; session=override; token=dup; token=dup2\r\n",
    "Date: Sat, 29 Oct 1994 19:43:31 GMT\r\n",
    "Date: 0\r\n",
    "Date: -1\r\n",
    "Date: 99999999999999\r\n",
    "Date: not a date at all\r\n",
    "Date: \r\n",
    "Date: Thu, 01 Jan 1970 00:00:00 GMT\r\n",
    "Date: Fri, 31 Dec 9999 23:59:59 GMT\r\n",
    "If-Modified-Since: Sun, 06 Nov 1994 08:49:37 GMT\r\n",
    "If-Modified-Since: Monday, 01-Jan-2024 00:00:00 GMT\r\n",
    "If-Modified-Since: Wed, 09 Jun 2021 10:18:14 GMT; extra=garbage\r\n",
    "Authorization: Basic YWRtaW46cGFzcw==\r\n",
    "Authorization: Basic dGVzdA==\r\n",
    "Authorization: Basic ====\r\n",
    "Authorization: Basic \r\n",
    "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9\r\n",
    "Authorization: Digest username=\"admin\"\r\n",
    "Authorization: NTLM TlRMTVNTUA==\r\n",
    "Authorization: \r\n",
    "Accept-Encoding: gzip, deflate\r\n",
    "Range: bytes=0-65535\r\n",
    "Content-Encoding: gzip\r\n",
    "Transfer-Encoding: chunked\r\n",
    "Connection: keep-alive\r\n",
    "X-Forwarded-For: 127.0.0.1\r\n",
    "If-None-Match: \"deadbeef\"\r\n",
    "Referer: http://localhost/test\r\n",
    "Host: localhost\r\n",
    "Host: evil.com\r\n",
    "Host: 127.0.0.1\r\n",
    "Host: localhost:8080\r\n",
    "Host: \r\n",
    "Host: localhost\x00evil.com\r\n",
    "NoColonHere\r\n",
    ": empty-name\r\n",
    "X-Empty:\r\n",
    "X-Space: \r\n",
    "X-Null: \x00value\r\n",
    "X-Tab:\tvalue\r\n",
    "X-Multi: val1\r\n\t continued\r\n",
    "X-Multi: val1\r\n continued\r\n",
    " X-Leading-Space: value\r\n",
    "X-CRLF: before\r\nInjected: after\r\n",
};
static const int num_headers = sizeof(header_pool) / sizeof(header_pool[0]);

static const char *long_hdr_names[] = {
    "Cookie", "User-Agent", "Referer", "Accept", "Authorization", "If-None-Match", "X-Fuzz",
};
static const int num_long_names = sizeof(long_hdr_names) / sizeof(long_hdr_names[0]);

struct Mutator {
    void *afl;
    std::vector<uint8_t> buf;
};

extern "C" {
typedef struct afl_state {
    void *afl;
} afl_state_t;
}

static size_t do_swap_method(
    const uint8_t *buf, size_t len, const AK::RequestLine &rl, std::vector<uint8_t> &out, size_t max
)
{
    const char *m = methods[rand() % num_methods];
    size_t mlen = strlen(m);
    size_t rest = len - (rl.uri_start - 1);
    size_t total = mlen + rest;
    if (total > max)
        return 0;
    out.resize(total);
    memcpy(out.data(), m, mlen);
    memcpy(out.data() + mlen, buf + rl.uri_start - 1, rest);
    return total;
}

static size_t do_mutate_query(
    const uint8_t *buf, size_t len, const AK::RequestLine &rl, std::vector<uint8_t> &out, size_t max
)
{
    std::string uri((const char *)buf + rl.uri_start, rl.uri_end - rl.uri_start);
    size_t qpos = uri.find('?');
    std::string path = (qpos != std::string::npos) ? uri.substr(0, qpos) : uri;

    std::string qs;
    int nparams = 1 + rand() % 4;
    for (int i = 0; i < nparams; i++) {
        if (i > 0)
            qs += '&';
        qs += query_params[rand() % num_params];
    }
    std::string new_uri = path + "?" + qs;
    return AK::replace_uri(buf, len, rl, new_uri.c_str(), new_uri.size(), out, max);
}

static size_t do_corrupt_cl(const uint8_t *buf, size_t len, std::vector<uint8_t> &out, size_t max)
{
    char hdr[64];
    int n = snprintf(hdr, sizeof(hdr), "Content-Length: %s\r\n", cl_values[rand() % num_cls]);
    if (n <= 0)
        return 0;
    return AK::inject_header(buf, len, hdr, n, out, max);
}

static size_t do_inject_hdr(const uint8_t *buf, size_t len, std::vector<uint8_t> &out, size_t max)
{
    const char *hdr = header_pool[rand() % num_headers];
    return AK::inject_header(buf, len, hdr, strlen(hdr), out, max);
}

static size_t do_dup_header(const uint8_t *buf, size_t len, std::vector<uint8_t> &out, size_t max)
{
    std::string req((const char *)buf, len);
    size_t hend = AK::find_header_end(buf, len);
    if (hend == 0)
        return 0;

    std::vector<std::string> hdrs;
    size_t pos = req.find("\r\n");
    if (pos == std::string::npos)
        return 0;
    pos += 2;
    while (pos < hend) {
        size_t eol = req.find("\r\n", pos);
        if (eol == std::string::npos || eol >= hend)
            break;
        hdrs.push_back(req.substr(pos, eol - pos + 2));
        pos = eol + 2;
    }
    if (hdrs.empty())
        return 0;

    const std::string &h = hdrs[rand() % hdrs.size()];
    return AK::inject_header(buf, len, h.c_str(), h.size(), out, max);
}

static size_t do_long_header(const uint8_t *buf, size_t len, std::vector<uint8_t> &out, size_t max)
{
    size_t hend = AK::find_header_end(buf, len);
    if (hend == 0)
        return 0;

    const char *name = long_hdr_names[rand() % num_long_names];
    int vlen = 256 + rand() % 7937;

    std::string hdr(name);
    hdr += ": ";
    for (int i = 0; i < vlen; i++) {
        int r = rand() % 4;
        if (r == 0)
            hdr += ('A' + rand() % 26);
        else if (r == 1)
            hdr += ('0' + rand() % 10);
        else if (r == 2)
            hdr += "=;, \t%&+/"[rand() % 9];
        else
            hdr += (char)(0x20 + rand() % 95);
    }
    hdr += "\r\n";
    return AK::inject_header(buf, len, hdr.c_str(), hdr.size(), out, max);
}

static size_t
do_multi_headers(const uint8_t *buf, size_t len, std::vector<uint8_t> &out, size_t max)
{
    std::string block;
    int count = 2 + rand() % 4;
    for (int i = 0; i < count; i++) {
        if (rand() % 5 == 0) {
            char tmp[64];
            snprintf(tmp, sizeof(tmp), "If-None-Match: \"%08x\"\r\n", rand());
            block += tmp;
        } else {
            block += header_pool[rand() % num_headers];
        }
    }
    return AK::inject_header(buf, len, block.c_str(), block.size(), out, max);
}

extern "C" {

void *afl_custom_init(afl_state_t *afl, unsigned int seed)
{
    Mutator *ctx = new (std::nothrow) Mutator();
    if (!ctx)
        return nullptr;
    ctx->afl = afl;
    srand(seed);
    return ctx;
}

void afl_custom_deinit(void *data)
{
    delete static_cast<Mutator *>(data);
}

size_t afl_custom_fuzz(
    void *data, uint8_t *buf, size_t buf_size, uint8_t **out_buf, uint8_t *add_buf,
    size_t add_buf_size, size_t max_size
)
{
    (void)add_buf;
    (void)add_buf_size;
    Mutator *ctx = static_cast<Mutator *>(data);
    if (max_size > MAX_BUF)
        max_size = MAX_BUF;

    AK::RequestLine rl;
    bool has_rl = AK::parse_request_line(buf, buf_size, rl);

    int roll = rand() % 100;
    size_t n = 0;

    if (roll < 15 && has_rl)
        n = do_swap_method(buf, buf_size, rl, ctx->buf, max_size);
    else if (roll < 30 && has_rl)
        n = do_mutate_query(buf, buf_size, rl, ctx->buf, max_size);
    else if (roll < 40)
        n = do_corrupt_cl(buf, buf_size, ctx->buf, max_size);
    else if (roll < 60)
        n = do_inject_hdr(buf, buf_size, ctx->buf, max_size);
    else if (roll < 72)
        n = do_dup_header(buf, buf_size, ctx->buf, max_size);
    else if (roll < 85)
        n = do_long_header(buf, buf_size, ctx->buf, max_size);
    else
        n = do_multi_headers(buf, buf_size, ctx->buf, max_size);

    if (n == 0 || n > max_size) {
        size_t sz = buf_size < max_size ? buf_size : max_size;
        ctx->buf.resize(sz);
        memcpy(ctx->buf.data(), buf, sz);
        n = sz;
    }

    *out_buf = ctx->buf.data();
    return n;
}

size_t afl_custom_fuzz_count(void *data, const uint8_t *buf, size_t buf_size)
{
    (void)data;
    (void)buf;
    (void)buf_size;
    return 8;
}

} // extern "C"
