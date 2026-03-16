/*
 * mod_rewrite Custom Mutator for AFL++
 *
 * Structure-aware mutations targeting mod_rewrite's URL rewriting engine.
 * Crafts HTTP requests that exercise rewrite rules, backreference expansion,
 * variable lookups, RewriteMap functions, and flag processing.
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

static const char *uri_payloads[] = {
    "/a/foo/bar/baz",
    "/a/../../etc/passwd",
    "/a/%2e%2e/%2e%2e/etc/passwd",
    "/a/a%00b",
    "/a",
    "/a/HELLO",
    "/a/AbCdEfGhIjKlMnOpQrStUvWxYz",
    "/a/FOO%2FBAR",
    "/a/hello-world",
    "/a/admin/edit/12345",
    "/a/a%00b/c%0dd/e%0af",
    "/a/AAAAAAAAAAAAAAAA/BBBBBBBBBBBBBBBB/CCCCCCCCCCCCCCCC",
    "/a/test",
    "/a/foo%26bar=baz",
    "/b/clean/page",
    "/b/track/payload$1%{QUERY_STRING}",
    "/b/setcookie/value%3bsecure%3bhttponly",
    "/b/chain/data",
    "/b/download/file.dat",
    "/b/cgi/test.cgi",
    "/b/xxxxxxxxxx",
    "/b/xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    "/b/xxxfoo",
    "/b/catchall/anything",
    "/",
    "",
    "/c/../../../etc/passwd",
    "/a?b#c",
    "/d/%2e%2e/%2e%2e/%2e%2e/%2e%2e/",
    "/d/rewrite/../rewrite/../rewrite",
    "/d/escape/%00%01%02%03%04%05%06%07%08%09%0a%0b%0c%0d%0e%0f",
    "/d/old/foo%20bar%09baz%0d%0aqux",
    "/d/upper/%C3%BC%C3%B6%C3%A4",
    "/d/search/%E2%80%8B",
    "/d/user/%252F/%252F/%252F",
    "/d/nested/%2500%2501%2502",
    "/escape/a b c d e f g h",
    "/old/foo%ff%fe%fd",
    "/chain/test%0d%0aX-Injected: yes",
    "/track/$1%{QUERY_STRING}%1%2%3",
    "/setcookie/val%3B%20domain%3D.evil.com",
};
static const int num_uris = sizeof(uri_payloads) / sizeof(uri_payloads[0]);

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
    "a=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    "%00=%00",
    "id=1%27%20OR%201%3D1",
    "term=<script>alert(1)</script>",
    "x=1&x=2&x=3&x=4&x=5",
};
static const int num_qs = sizeof(qs_payloads) / sizeof(qs_payloads[0]);

static const char *method_payloads[] = {
    "GET",   "POST",  "PUT",     "DELETE",   "HEAD", "OPTIONS",
    "PATCH", "TRACE", "CONNECT", "PROPFIND", "AAAA",
};
static const int num_methods = sizeof(method_payloads) / sizeof(method_payloads[0]);

static const char *host_payloads[] = {
    "Host: localhost\r\n",
    "Host: www.example.com\r\n",
    "Host: pwner.gg\r\n",
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
    "User-Agent: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\r\n",
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

static const char *seg_mutations[] = {
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
    "a",
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
};
static const int num_seg_mutations = sizeof(seg_mutations) / sizeof(seg_mutations[0]);

struct Mutator {
    void *afl;
    std::vector<uint8_t> buf;
};

extern "C" {
typedef struct afl_state {
    void *afl;
} afl_state_t;
}

static const char *pick_header()
{
    int which = rand() % 4;
    if (which == 0)
        return host_payloads[rand() % num_hosts];
    if (which == 1)
        return ua_payloads[rand() % num_uas];
    if (which == 2)
        return accept_payloads[rand() % num_accepts];
    return xcustom_payloads[rand() % num_xcustoms];
}

static size_t do_swap_uri(
    const uint8_t *buf, size_t len, const AK::RequestLine &rl, std::vector<uint8_t> &out, size_t max
)
{
    const char *uri = uri_payloads[rand() % num_uris];
    char tmp[4096];
    size_t uri_len = strlen(uri);

    if (rand() % 3 == 0 && uri_len < sizeof(tmp) - 256) {
        int n = snprintf(tmp, sizeof(tmp), "%s?%s", uri, qs_payloads[rand() % num_qs]);
        if (n > 0) {
            uri = tmp;
            uri_len = n;
        }
    }
    return AK::replace_uri(buf, len, rl, uri, uri_len, out, max);
}

static size_t do_mutate_query(
    const uint8_t *buf, size_t len, const AK::RequestLine &rl, std::vector<uint8_t> &out, size_t max
)
{
    std::string uri((const char *)buf + rl.uri_start, rl.uri_end - rl.uri_start);
    size_t qpos = uri.find('?');
    std::string path = (qpos != std::string::npos) ? uri.substr(0, qpos) : uri;
    std::string new_uri = path + "?" + qs_payloads[rand() % num_qs];
    return AK::replace_uri(buf, len, rl, new_uri.c_str(), new_uri.size(), out, max);
}

static size_t
do_inject_header(const uint8_t *buf, size_t len, std::vector<uint8_t> &out, size_t max)
{
    const char *hdr = pick_header();
    return AK::inject_header(buf, len, hdr, strlen(hdr), out, max);
}

static size_t do_mutate_path(
    const uint8_t *buf, size_t len, const AK::RequestLine &rl, std::vector<uint8_t> &out, size_t max
)
{
    std::string uri((const char *)buf + rl.uri_start, rl.uri_end - rl.uri_start);

    size_t slash = uri.find('/', 1);
    if (slash == std::string::npos)
        return 0;

    size_t next = uri.find('/', slash + 1);
    if (next == std::string::npos)
        next = uri.size();

    uri.replace(slash + 1, next - slash - 1, seg_mutations[rand() % num_seg_mutations]);
    return AK::replace_uri(buf, len, rl, uri.c_str(), uri.size(), out, max);
}

static size_t do_long_path(
    const uint8_t *buf, size_t len, const AK::RequestLine &rl, std::vector<uint8_t> &out, size_t max
)
{
    std::string path;
    int variant = rand() % 4;

    if (variant == 0) {
        int depth = 50 + rand() % 200;
        for (int i = 0; i < depth; i++) {
            path += '/';
            path += ('a' + i % 26);
        }
    } else if (variant == 1) {
        path = "/";
        int n = 1000 + rand() % 4000;
        for (int i = 0; i < n; i++)
            path += ('A' + i % 26);
    } else if (variant == 2) {
        path = "/" + std::string(50 + rand() % 500, 'x');
    } else {
        int count = 20 + rand() % 80;
        for (int i = 0; i < count; i++)
            path += "/..";
    }
    return AK::replace_uri(buf, len, rl, path.c_str(), path.size(), out, max);
}

static size_t
do_multi_headers(const uint8_t *buf, size_t len, std::vector<uint8_t> &out, size_t max)
{
    std::string block;
    int count = 2 + rand() % 4;
    for (int i = 0; i < count; i++) {
        if (rand() % 5 == 0) {
            char tmp[64];
            snprintf(tmp, sizeof(tmp), "X-Fuzz-%d: %08x\r\n", i, rand());
            block += tmp;
        } else {
            block += pick_header();
        }
    }
    return AK::inject_header(buf, len, block.c_str(), block.size(), out, max);
}

static size_t do_swap_method(
    const uint8_t *buf, size_t len, const AK::RequestLine &rl, std::vector<uint8_t> &out, size_t max
)
{
    const char *m = method_payloads[rand() % num_methods];
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

static size_t do_combined(
    const uint8_t *buf, size_t len, const AK::RequestLine &rl, std::vector<uint8_t> &out, size_t max
)
{
    std::vector<uint8_t> tmp;
    size_t n = do_swap_uri(buf, len, rl, tmp, max);
    if (n == 0)
        return 0;

    const char *hdr = pick_header();
    return AK::inject_header(tmp.data(), n, hdr, strlen(hdr), out, max);
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

    if (roll < 25 && has_rl)
        n = do_swap_uri(buf, buf_size, rl, ctx->buf, max_size);
    else if (roll < 40 && has_rl)
        n = do_mutate_query(buf, buf_size, rl, ctx->buf, max_size);
    else if (roll < 52)
        n = do_inject_header(buf, buf_size, ctx->buf, max_size);
    else if (roll < 62 && has_rl)
        n = do_mutate_path(buf, buf_size, rl, ctx->buf, max_size);
    else if (roll < 72 && has_rl)
        n = do_long_path(buf, buf_size, rl, ctx->buf, max_size);
    else if (roll < 82)
        n = do_multi_headers(buf, buf_size, ctx->buf, max_size);
    else if (roll < 92 && has_rl)
        n = do_swap_method(buf, buf_size, rl, ctx->buf, max_size);
    else if (has_rl)
        n = do_combined(buf, buf_size, rl, ctx->buf, max_size);

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
    return 9;
}

} // extern "C"
