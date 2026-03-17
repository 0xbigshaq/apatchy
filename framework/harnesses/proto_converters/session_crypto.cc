/*
 * Session crypto converter for the proto harness.
 *
 * Replicates the encryption/encoding logic from session_crypto_mutator.cc
 * so libFuzzer + LPM can fuzz mod_session_crypto with structurally valid
 * encrypted cookies.
 *
 * The SessionRoute enum selects a path + cookie name + crypto mode,
 * matching the AFL mutator's route table exactly.
 */

#include "session_crypto.pb.h"
#include "proto_converters/converters.h"

#include <cstring>
#include <string>
#include <vector>

#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/params.h>

#define PASSPHRASE_PRIMARY "fuzzing_test_key_1234567890abcdef"
#define PASSPHRASE_ALT "different_key_for_cross_route_test"

struct RouteInfo {
    const char *path;
    const char *cookie_name;
    int key_set; // 0 = primary, 1 = alt, -1 = plaintext
};

static const RouteInfo ROUTES[] = {
    {"/a", "session_crypto", 0},
    {"/b", "session_plain", -1},
    {"/c", "session_ovr", -1},
    {"/d", "session_filter", 0},
    {"/e", "session_expiry", -1},
    {"/f", "session_auth", -1},
    {"/g", "session_auth", -1},
    {"/h", "session_auth", -1},
    {"/i", "session2_rfc2965", -1},
    {"/j", "session_dual", -1},
    {"/k", "session_strip", -1},
    {"/l", "session_empty", -1},
    {"/m", "session_pf", 0},
    {"/n", "session_alt", 1},
    {"/o", "session_multi", 0},
    {"/p", "session_shared", 0},
    {"/q", "session_exec", 0},
};

struct CryptoKeys {
    uint8_t siphash_key[16];
    uint8_t aes_key[32];
    uint8_t salt[16];
    bool ready;
};

static CryptoKeys g_keys[2] = {};

static bool derive_keys(CryptoKeys *k, const char *passphrase)
{
    unsigned int md_len = 0;
    EVP_MD_CTX *md = EVP_MD_CTX_new();
    EVP_DigestInit_ex(md, EVP_md5(), NULL);
    EVP_DigestUpdate(md, passphrase, strlen(passphrase));
    EVP_DigestFinal_ex(md, k->siphash_key, &md_len);
    EVP_MD_CTX_free(md);

    memset(k->salt, 0x41, 16);

    if (!PKCS5_PBKDF2_HMAC_SHA1(passphrase, strlen(passphrase), k->salt, 16, 4096, 32, k->aes_key))
        return false;

    k->ready = true;
    return true;
}

static void ensure_keys()
{
    if (!g_keys[0].ready)
        derive_keys(&g_keys[0], PASSPHRASE_PRIMARY);
    if (!g_keys[1].ready)
        derive_keys(&g_keys[1], PASSPHRASE_ALT);
}

static bool siphash24(uint8_t out[8], const uint8_t *data, size_t data_len, const uint8_t key[16])
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

static std::string encrypt_session(const std::string &plaintext, int key_set)
{
    ensure_keys();
    const CryptoKeys *k = &g_keys[key_set];
    static const uint8_t iv[16] = {0};

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        return "";

    std::vector<uint8_t> ct(plaintext.size() + 16);
    int ct_len = 0, final_len = 0;

    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, k->aes_key, iv);
    EVP_EncryptUpdate(ctx, ct.data(), &ct_len, (const uint8_t *)plaintext.data(), (int)plaintext.size());
    EVP_EncryptFinal_ex(ctx, ct.data() + ct_len, &final_len);
    EVP_CIPHER_CTX_free(ctx);
    ct_len += final_len;

    // assemble: [8 MAC][16 salt][16 IV][ciphertext]
    size_t combined = 8 + 16 + 16 + ct_len;
    std::vector<uint8_t> blob(combined);
    memcpy(blob.data() + 8, k->salt, 16);
    memcpy(blob.data() + 24, iv, 16);
    memcpy(blob.data() + 40, ct.data(), ct_len);

    siphash24(blob.data(), blob.data() + 8, combined - 8, k->siphash_key);

    return base64_encode(blob.data(), combined);
}

static std::string url_encode(const std::string &input)
{
    static const char hex[] = "0123456789ABCDEF";
    std::string out;
    out.reserve(input.size() * 3);
    for (unsigned char c : input) {
        if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '=' ||
            c == '&') {
            out += (char)c;
        } else {
            out += '%';
            out += hex[c >> 4];
            out += hex[c & 0xf];
        }
    }
    return out;
}

void ApplySessionCrypto(
    const SessionCookie &cookie, SessionRoute route, std::string &request
)
{
    int idx = static_cast<int>(route);
    if (idx < 0 || idx >= static_cast<int>(sizeof(ROUTES) / sizeof(ROUTES[0])))
        return;

    const RouteInfo &r = ROUTES[idx];

    // Override the URI to match the route
    size_t sp1 = request.find(' ');
    size_t sp2 = request.find(' ', sp1 + 1);
    if (sp1 != std::string::npos && sp2 != std::string::npos)
        request.replace(sp1 + 1, sp2 - sp1 - 1, r.path);

    // Build cookie value
    std::string cookie_value;
    if (cookie.has_raw_override()) {
        cookie_value = base64_encode(
            (const uint8_t *)cookie.raw_override().data(), cookie.raw_override().size());
    } else if (r.key_set >= 0) {
        cookie_value = encrypt_session(cookie.session_data(), r.key_set);
    } else {
        cookie_value = url_encode(cookie.session_data());
    }

    // Inject Cookie header before the final \r\n\r\n
    // Even empty cookie values are valid for fuzzing
    size_t end = request.rfind("\r\n\r\n");
    if (end == std::string::npos)
        return;

    std::string hdr = "Cookie: ";
    hdr += r.cookie_name;
    hdr += "=";
    hdr += cookie_value;
    hdr += "\r\n";
    request.insert(end + 2, hdr);
}
