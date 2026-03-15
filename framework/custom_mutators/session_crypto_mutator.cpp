/*
 * Session Crypto Mutator for AFL++
 *
 * Path-aware mutator that injects encrypted session cookies matching
 * each route's SessionCookieName and passphrase. Blobs are precomputed
 * at init for each passphrase; the fuzz function parses the request
 * path and injects the correct cookie.
 *
 * Can be chained with other mutators -- AFL++ calls afl_custom_fuzz
 * on each .so independently.
 */
// LDFLAGS: -lcrypto
// LANG: c++

#include <cinttypes>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include <openssl/evp.h>
#include <openssl/rand.h>

#include "utils/AK.h"

#define PASSPHRASE_PRIMARY "fuzzing_test_key_1234567890abcdef"
#define PASSPHRASE_ALT "different_key_for_cross_route_test"

struct RouteInfo {
    const char *path;
    const char *cookie_name;
    int blob_set; // 0 = primary, 1 = alt, -1 = no crypto
};

static const RouteInfo routes[] = {
    {"/a", "session_crypto", 0}, {"/b", "session_plain", -1},  {"/c", "session_ovr", -1},
    {"/d", "session_filter", 0}, {"/e", "session_expiry", -1}, {"/f", "session_auth", -1},
    {"/g", "session_auth", -1},  {"/h", "session_auth", -1},   {"/i", "session2_rfc2965", -1},
    {"/j", "session_dual", -1},  {"/k", "session_strip", -1},  {"/l", "session_empty", -1},
    {"/m", "session_pf", 0},     {"/n", "session_alt", 1},     {"/o", "session_multi", 0},
    {"/p", "session_shared", 0}, {"/q", "session_exec", 0},
};
static const int num_routes = sizeof(routes) / sizeof(routes[0]);

struct MutatorContext {
    void *afl;
    std::vector<std::string> blobs[2]; // [0] = primary, [1] = alt
    std::vector<uint8_t> fuzz_buf;
};

extern "C" {
typedef struct afl_state {
    void *afl;
} afl_state_t;
}

static std::string encrypt_data(
    const char *passphrase, const uint8_t siphash_key[16], const uint8_t *pt, size_t pt_len
)
{
    uint8_t salt[16], iv[16], key[32];
    RAND_bytes(salt, 16);
    RAND_bytes(iv, 16);

    if (!PKCS5_PBKDF2_HMAC_SHA1(passphrase, strlen(passphrase), salt, 16, 4096, 32, key))
        return "";

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        return "";

    std::vector<uint8_t> ct(pt_len + 16);
    int ct_len = 0, final_len = 0;

    bool ok = EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) == 1 &&
              EVP_EncryptUpdate(ctx, ct.data(), &ct_len, pt, (int)pt_len) == 1 &&
              EVP_EncryptFinal_ex(ctx, ct.data() + ct_len, &final_len) == 1;
    EVP_CIPHER_CTX_free(ctx);
    if (!ok)
        return "";
    ct_len += final_len;

    size_t combined = 8 + 16 + 16 + ct_len;
    std::vector<uint8_t> assembled(combined);
    memcpy(assembled.data() + 8, salt, 16);
    memcpy(assembled.data() + 24, iv, 16);
    memcpy(assembled.data() + 40, ct.data(), ct_len);

    if (!AK::siphash24(assembled.data(), assembled.data() + 8, combined - 8, siphash_key))
        return "";

    return AK::base64_encode(assembled.data(), combined);
}

static void compute_siphash_key(const char *passphrase, uint8_t out[16])
{
    unsigned int md_len = 0;
    EVP_MD_CTX *evp_ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(evp_ctx, EVP_md5(), NULL);
    EVP_DigestUpdate(evp_ctx, passphrase, strlen(passphrase));
    EVP_DigestFinal_ex(evp_ctx, out, &md_len);
    EVP_MD_CTX_free(evp_ctx);
}

static void precompute_blobs(const char *passphrase, std::vector<std::string> &out)
{
    uint8_t siphash_key[16];
    compute_siphash_key(passphrase, siphash_key);

    static const char *seeds[] = {
        "user=admin&role=root",
        "user=guest",
        "a=1",
        "user=test&role=user&active=true",
        "session_id=AAAA&csrf=BBBB",
        "x=",
        "",
        "a=1&b=2&c=3&d=4&e=5&f=6&g=7&h=8",
        "lang=en&theme=dark&tz=UTC",
        "token=eyJhbGciOiJIUzI1NiJ9.dGVzdA",
        "path=/admin/../../../etc/passwd",
        "user=%00null%00&role=<script>",
        "encoded=%3Cscript%3Ealert(1)%3C/script%3E",
        "empty_vals=&&&&",
        "dup=a&dup=b&dup=c",
        "fmt=%s%s%s%s%s%n",
    };
    int num_seeds = sizeof(seeds) / sizeof(seeds[0]);

    for (int i = 0; i < num_seeds; i++) {
        std::string blob =
            encrypt_data(passphrase, siphash_key, (const uint8_t *)seeds[i], strlen(seeds[i]));
        if (!blob.empty())
            out.push_back(std::move(blob));
    }
}

extern "C" {

void *afl_custom_init(afl_state_t *afl, unsigned int seed)
{
    MutatorContext *ctx = new (std::nothrow) MutatorContext();
    if (!ctx)
        return nullptr;

    ctx->afl = afl;
    srand(seed);

    precompute_blobs(PASSPHRASE_PRIMARY, ctx->blobs[0]);
    precompute_blobs(PASSPHRASE_ALT, ctx->blobs[1]);

    fprintf(
        stderr, "[session_crypto] precomputed %zu primary + %zu alt blobs\n", ctx->blobs[0].size(),
        ctx->blobs[1].size()
    );

    if (ctx->blobs[0].empty() && ctx->blobs[1].empty()) {
        fprintf(stderr, "[session_crypto] no blobs precomputed, aborting\n");
        delete ctx;
        return nullptr;
    }

    return ctx;
}

void afl_custom_deinit(void *data)
{
    delete static_cast<MutatorContext *>(data);
}

static bool is_cookie_header(const uint8_t *line, size_t len)
{
    if (len >= 8 && strncasecmp((const char *)line, "Cookie: ", 8) == 0)
        return true;
    if (len >= 9 && strncasecmp((const char *)line, "Cookie2: ", 9) == 0)
        return true;
    return false;
}

static size_t strip_cookie_headers(const uint8_t *src, size_t src_len, uint8_t *dst, size_t max_dst)
{
    size_t out = 0;
    size_t pos = 0;

    while (pos < src_len) {
        const uint8_t *eol = (const uint8_t *)memmem(src + pos, src_len - pos, "\r\n", 2);
        size_t line_end = eol ? (size_t)(eol - src) + 2 : src_len;
        size_t line_len = line_end - pos;
        const uint8_t *line = src + pos;

        // skip \r\n prefix to get header name (lines start with \r\n from rest_start)
        const uint8_t *hdr = line;
        size_t hdr_len = line_len;
        if (hdr_len >= 2 && hdr[0] == '\r' && hdr[1] == '\n') {
            hdr += 2;
            hdr_len -= 2;
        }

        if (hdr_len > 0 && is_cookie_header(hdr, hdr_len)) {
            pos = line_end;
            continue;
        }

        if (out + line_len > max_dst)
            break;
        memcpy(dst + out, line, line_len);
        out += line_len;
        pos = line_end;
    }

    return out;
}

size_t afl_custom_fuzz(
    void *data, uint8_t *buf, size_t buf_size, uint8_t **out_buf, uint8_t *add_buf,
    size_t add_buf_size, size_t max_size
)
{
    (void)add_buf;
    (void)add_buf_size;
    MutatorContext *ctx = static_cast<MutatorContext *>(data);

    // find end of first line (\r\n)
    const uint8_t *eol = (const uint8_t *)memmem(buf, buf_size, "\r\n", 2);
    if (!eol) {
        *out_buf = buf;
        return buf_size;
    }
    size_t first_line_end = eol - buf;
    size_t rest_start = first_line_end; // keep from \r\n onward

    // pick a route using entropy from the buffer
    // crypto routes get 50% weight to increase encrypted cookie coverage
    static const int crypto_indices[] = {0, 3, 12, 13, 14, 15, 16}; // /a /d /m /n /o /p /q
    static const int num_crypto = sizeof(crypto_indices) / sizeof(crypto_indices[0]);
    uint32_t idx = 0;
    for (size_t i = 0; i < buf_size && i < 16; i++)
        idx += buf[i];
    const RouteInfo &route =
        (idx % 2 == 0) ? routes[crypto_indices[idx % num_crypto]] : routes[idx % num_routes];

    static uint64_t call_count = 0;
    if (++call_count % 5000 == 0)
        fprintf(
            stderr, "\n[session_crypto] #%" PRIu64 " %s -> %s (%s)\n", call_count, route.path,
            route.cookie_name, route.blob_set >= 0 ? "crypto" : "plain"
        );

    // build request line: "GET /x HTTP/1.1"
    char req_line[20];
    int req_line_len = snprintf(req_line, sizeof(req_line), "GET %s HTTP/1.1", route.path);

    // pick blob for cookie injection (only for crypto routes)
    const std::string *blob = nullptr;
    if (route.blob_set >= 0 && !ctx->blobs[route.blob_set].empty()) {
        uint32_t bidx = buf[0]; // FIXME: this is ugly hack, we need to let AFL decide the payload
                                // and not index into it
        const std::vector<std::string> &bset = ctx->blobs[route.blob_set];
        blob = &bset[bidx % bset.size()];
    }

    const char *cookie_name = route.cookie_name;
    size_t name_len = strlen(cookie_name);
    size_t cookie_len = 0;
    if (blob)
        cookie_len = 10 + name_len + 1 + blob->size();

    // strip cookie headers from the remaining input
    size_t rest_len = buf_size - rest_start;
    std::vector<uint8_t> stripped(rest_len);
    size_t stripped_len =
        strip_cookie_headers(buf + rest_start, rest_len, stripped.data(), rest_len);

    size_t new_size = req_line_len + cookie_len + stripped_len;
    if (new_size > max_size) {
        *out_buf = buf;
        return buf_size;
    }

    ctx->fuzz_buf.resize(new_size);
    size_t cur = 0;

    memcpy(ctx->fuzz_buf.data(), req_line, req_line_len);
    cur = req_line_len;

    if (blob) {
        memcpy(ctx->fuzz_buf.data() + cur, "\r\nCookie: ", 10);
        cur += 10;
        memcpy(ctx->fuzz_buf.data() + cur, cookie_name, name_len);
        cur += name_len;
        ctx->fuzz_buf[cur++] = '=';
        memcpy(ctx->fuzz_buf.data() + cur, blob->data(), blob->size());
        cur += blob->size();
    }

    memcpy(ctx->fuzz_buf.data() + cur, stripped.data(), stripped_len);

    *out_buf = ctx->fuzz_buf.data();
    return new_size;
}

size_t afl_custom_fuzz_count(void *data, const uint8_t *buf, size_t buf_size)
{
    (void)data;
    (void)buf;
    (void)buf_size;
    return 128;
}

} // extern "C"
