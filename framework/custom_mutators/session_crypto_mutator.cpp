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

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include <openssl/evp.h>
#include <openssl/rand.h>

#include "utils/AK.h"

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

    size_t hdr_end = AK::find_header_end(buf, buf_size);
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
