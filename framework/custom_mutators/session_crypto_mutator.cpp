/*
 * Session Crypto Post-Processing Mutator for AFL++
 *
 * Encrypts session cookie values so they pass `mod_session_crypto`'s
 * decryption logic. All crypto happens at init via precomputed buffers;
 * the post-processor only does memcpy.
 *
 * It's better to chain this after other mutators, meaning:
 *   AFL_CUSTOM_MUTATOR_LIBRARY=http_mutator.so:session_crypto_mutator.so
 *
 */
// LDFLAGS: -lcrypto
// LANG: c++

#include <cstdio>
#include <cstring>
#include <cstdint>
#include <string>
#include <vector>

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/params.h>
#include <openssl/core_names.h>

#define DEFAULT_PASSPHRASE "fuzzing_test_key_1234567890abcdef"
#define DEFAULT_COOKIE_NAMES "session_crypto"
#define MAX_BUF (1024 * 1024)

struct MutatorContext {
    void *afl;
    std::string cookie_name;
    std::vector<std::string> blobs;
    std::vector<uint8_t> post_buf;
};

extern "C" {
typedef struct afl_state {
    void *afl;
} afl_state_t;
}

static bool
siphash24_mac(uint8_t out[8], const uint8_t *data, size_t data_len, const uint8_t key[16])
{
    EVP_MAC *mac = EVP_MAC_fetch(NULL, "SIPHASH", NULL);
    if (!mac)
        return false;

    EVP_MAC_CTX *ctx = EVP_MAC_CTX_new(mac);
    EVP_MAC_free(mac);
    if (!ctx)
        return false;

    size_t out_size = 8;
    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_size_t(OSSL_MAC_PARAM_SIZE, &out_size),
        OSSL_PARAM_END,
    };

    size_t final_len = 0;
    bool ok = EVP_MAC_init(ctx, key, 16, params) == 1 && EVP_MAC_update(ctx, data, data_len) == 1 &&
              EVP_MAC_final(ctx, out, &final_len, 8) == 1;

    EVP_MAC_CTX_free(ctx);
    return ok && final_len == 8;
}

static std::string base64_encode(const uint8_t *data, size_t len)
{
    size_t out_len = 4 * ((len + 2) / 3) + 1;
    std::string result(out_len, '\0');
    int written = EVP_EncodeBlock(reinterpret_cast<unsigned char *>(&result[0]), data, (int)len);
    result.resize(written);
    return result;
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

    if (!siphash24_mac(assembled.data(), assembled.data() + 8, combined - 8, siphash_key))
        return "";

    return base64_encode(assembled.data(), combined);
}

static size_t find_header_end(const uint8_t *buf, size_t len)
{
    for (size_t i = 0; i + 3 < len; i++) {
        if (buf[i] == '\r' && buf[i + 1] == '\n' && buf[i + 2] == '\r' && buf[i + 3] == '\n')
            return i;
    }
    return 0;
}

extern "C" {

void *afl_custom_init(afl_state_t *afl, unsigned int seed)
{
    MutatorContext *ctx = new (std::nothrow) MutatorContext();
    if (!ctx)
        return nullptr;

    ctx->afl = afl;
    srand(seed);

    std::string passphrase(DEFAULT_PASSPHRASE);
    ctx->cookie_name = DEFAULT_COOKIE_NAMES;

    uint8_t siphash_key[16];
    unsigned int md_len = 0;
    EVP_MD_CTX *evp_ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(evp_ctx, EVP_md5(), NULL);
    EVP_DigestUpdate(evp_ctx, passphrase.c_str(), passphrase.size());
    EVP_DigestFinal_ex(evp_ctx, siphash_key, &md_len);
    EVP_MD_CTX_free(evp_ctx);

    fprintf(
        stderr, "[session_crypto] passphrase='%s' cookie='%s'\n", passphrase.c_str(),
        ctx->cookie_name.c_str()
    );

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
        std::string blob = encrypt_data(
            passphrase.c_str(), siphash_key, (const uint8_t *)seeds[i], strlen(seeds[i])
        );
        if (!blob.empty())
            ctx->blobs.push_back(std::move(blob));
    }

    fprintf(stderr, "[session_crypto] precomputed %zu/%d blobs\n", ctx->blobs.size(), num_seeds);

    if (ctx->blobs.empty()) {
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

size_t afl_custom_post_process(void *data, uint8_t *buf, size_t buf_size, uint8_t **out_buf)
{
    MutatorContext *ctx = static_cast<MutatorContext *>(data);

    size_t hdr_end = find_header_end(buf, buf_size);
    if (hdr_end == 0) {
        *out_buf = buf;
        return buf_size;
    }

    uint32_t idx = buf[0]; // FIXME: we will need to come up with something smarter than that
    const std::string &blob = ctx->blobs[idx % ctx->blobs.size()];

    const std::string &name = ctx->cookie_name;
    size_t inject_len = 10 + name.size() + 1 + blob.size();
    size_t new_size = hdr_end + inject_len + (buf_size - hdr_end);
    if (new_size > MAX_BUF) {
        *out_buf = buf;
        return buf_size;
    }

    ctx->post_buf.resize(new_size);
    size_t cur = 0;
    memcpy(ctx->post_buf.data(), buf, hdr_end);
    cur = hdr_end;
    memcpy(ctx->post_buf.data() + cur, "\r\nCookie: ", 10);
    cur += 10;
    memcpy(ctx->post_buf.data() + cur, name.c_str(), name.size());
    cur += name.size();
    ctx->post_buf[cur++] = '=';
    memcpy(ctx->post_buf.data() + cur, blob.data(), blob.size());
    cur += blob.size();
    memcpy(ctx->post_buf.data() + cur, buf + hdr_end, buf_size - hdr_end);

    *out_buf = ctx->post_buf.data();
    return new_size;
}

} // extern "C"
