/*
 * Session Crypto Mutator for AFL++
 *
 * Path-aware mutator that encrypts AFL's payload for crypto routes
 * and URL-encodes it for plaintext routes. AFL controls the session
 * content; the mutator handles the crypto/encoding wrapper.
 *
 * For crypto routes, the AES key is precomputed at init with a fixed
 * salt so per-call encryption only does AES-CBC + siphash + base64.
 *
 * Can be chained with other mutators via AFL_CUSTOM_MUTATOR_LIBRARY.
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

struct CryptoCtx {
    uint8_t siphash_key[16];
    uint8_t aes_key[32];
    uint8_t salt[16];
    EVP_CIPHER_CTX *evp_ctx;
};

struct MutatorContext {
    void *afl;
    CryptoCtx crypto[2]; // [0] = primary, [1] = alt
    std::vector<uint8_t> fuzz_buf;
    std::vector<uint8_t> ct_buf;
    std::vector<uint8_t> assembled_buf;
    std::string cookie_buf;
};

extern "C" {
typedef struct afl_state {
    void *afl;
} afl_state_t;
}

static bool init_crypto_ctx(CryptoCtx *c, const char *passphrase)
{
    unsigned int md_len = 0;
    EVP_MD_CTX *md = EVP_MD_CTX_new();
    EVP_DigestInit_ex(md, EVP_md5(), NULL);
    EVP_DigestUpdate(md, passphrase, strlen(passphrase));
    EVP_DigestFinal_ex(md, c->siphash_key, &md_len);
    EVP_MD_CTX_free(md);

    memset(c->salt, 0x41, 16);

    if (!PKCS5_PBKDF2_HMAC_SHA1(passphrase, strlen(passphrase), c->salt, 16, 4096, 32, c->aes_key))
        return false;

    c->evp_ctx = EVP_CIPHER_CTX_new();
    return c->evp_ctx != nullptr;
}

// encrypt plaintext using precomputed key (fast, no PBKDF2)
static bool encrypt_payload(
    MutatorContext *m, const CryptoCtx *c, const uint8_t *pt, size_t pt_len
)
{
    static const uint8_t iv[16] = {0};

    m->ct_buf.resize(pt_len + 16);
    int ct_len = 0, final_len = 0;

    EVP_EncryptInit_ex(c->evp_ctx, EVP_aes_256_cbc(), NULL, c->aes_key, iv);
    if (EVP_EncryptUpdate(c->evp_ctx, m->ct_buf.data(), &ct_len, pt, (int)pt_len) != 1 ||
        EVP_EncryptFinal_ex(c->evp_ctx, m->ct_buf.data() + ct_len, &final_len) != 1)
        return false;
    ct_len += final_len;

    size_t combined = 8 + 16 + 16 + ct_len;
    m->assembled_buf.resize(combined);
    memcpy(m->assembled_buf.data() + 8, c->salt, 16);
    memcpy(m->assembled_buf.data() + 24, iv, 16);
    memcpy(m->assembled_buf.data() + 40, m->ct_buf.data(), ct_len);

    if (!AK::siphash24(
            m->assembled_buf.data(), m->assembled_buf.data() + 8, combined - 8, c->siphash_key))
        return false;

    m->cookie_buf = AK::base64_encode(m->assembled_buf.data(), combined);
    return true;
}

// URL-encode AFL's payload as a plaintext session cookie value
static void url_encode_payload(const uint8_t *buf, size_t len, std::string &out)
{
    static const char hex[] = "0123456789ABCDEF";
    out.clear();
    out.reserve(len * 3);
    for (size_t i = 0; i < len; i++) {
        uint8_t c = buf[i];
        if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
            (c >= '0' && c <= '9') || c == '=' || c == '&') {
            out += (char)c;
        } else {
            out += '%';
            out += hex[c >> 4];
            out += hex[c & 0xf];
        }
    }
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

extern "C" {

void *afl_custom_init(afl_state_t *afl, unsigned int seed)
{
    MutatorContext *ctx = new (std::nothrow) MutatorContext();
    if (!ctx)
        return nullptr;

    ctx->afl = afl;
    srand(seed);

    static const char *passphrases[] = {PASSPHRASE_PRIMARY, PASSPHRASE_ALT};
    for (int i = 0; i < 2; i++) {
        if (!init_crypto_ctx(&ctx->crypto[i], passphrases[i])) {
            fprintf(stderr, "[session_crypto] failed to init crypto ctx %d\n", i);
            delete ctx;
            return nullptr;
        }
    }

    fprintf(stderr, "[session_crypto] ready (encrypt-on-the-fly mode)\n");
    return ctx;
}

void afl_custom_deinit(void *data)
{
    MutatorContext *ctx = static_cast<MutatorContext *>(data);
    EVP_CIPHER_CTX_free(ctx->crypto[0].evp_ctx);
    EVP_CIPHER_CTX_free(ctx->crypto[1].evp_ctx);
    delete ctx;
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
    size_t rest_start = first_line_end;

    // pick a route using entropy from the buffer
    static const int crypto_indices[] = {0, 3, 12, 13, 14, 15, 16};
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

    // build request line
    char req_line[20];
    int req_line_len = snprintf(req_line, sizeof(req_line), "GET %s HTTP/1.1", route.path);

    // build cookie value based on route type
    const char *cookie_val = nullptr;
    size_t cookie_val_len = 0;

    if (route.blob_set >= 0) {
        // crypto route: encrypt AFL's payload on the fly
        if (encrypt_payload(ctx, &ctx->crypto[route.blob_set], buf, buf_size)) {
            cookie_val = ctx->cookie_buf.data();
            cookie_val_len = ctx->cookie_buf.size();
        }
    } else {
        // plain route: URL-encode AFL's payload
        url_encode_payload(buf, buf_size, ctx->cookie_buf);
        cookie_val = ctx->cookie_buf.data();
        cookie_val_len = ctx->cookie_buf.size();
    }

    const char *cookie_name = route.cookie_name;
    size_t name_len = strlen(cookie_name);
    size_t cookie_len = 0;
    if (cookie_val)
        cookie_len = 10 + name_len + 1 + cookie_val_len;

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

    if (cookie_val) {
        memcpy(ctx->fuzz_buf.data() + cur, "\r\nCookie: ", 10);
        cur += 10;
        memcpy(ctx->fuzz_buf.data() + cur, cookie_name, name_len);
        cur += name_len;
        ctx->fuzz_buf[cur++] = '=';
        memcpy(ctx->fuzz_buf.data() + cur, cookie_val, cookie_val_len);
        cur += cookie_val_len;
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
