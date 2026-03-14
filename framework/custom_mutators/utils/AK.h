/*
 * AK (Agnostic Kit) - shared utilities for AFL++ custom mutators
 *
 * Header-only. Include and use: AK::find_header_end(buf, len)
 */
// LANG: c++
#pragma once

#include <cstdint>
#include <cstring>
#include <string>

#include <openssl/evp.h>
#include <openssl/params.h>
#include <openssl/core_names.h>

namespace AK
{

inline size_t find_header_end(const uint8_t *buf, size_t len)
{
    const char *pattern = "\r\n\r\n";
    const void *p = memmem(buf, len, pattern, 4);
    return p ? (size_t)((const uint8_t *)p - buf) : 0;
}

inline size_t find_request_line_end(const uint8_t *buf, size_t len)
{
    const void *p = memmem(buf, len, "\r\n", 2);
    return p ? (size_t)((const uint8_t *)p - buf) : 0;
}

inline size_t find_space(const uint8_t *buf, size_t len)
{
    const void *p = memchr(buf, ' ', len);
    return p ? (size_t)((const uint8_t *)p - buf) : 0;
}

inline bool siphash24(uint8_t out[8], const uint8_t *data, size_t data_len, const uint8_t key[16])
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

inline std::string base64_encode(const uint8_t *data, size_t len)
{
    size_t out_len = 4 * ((len + 2) / 3) + 1;
    std::string result(out_len, '\0');
    int written = EVP_EncodeBlock(reinterpret_cast<unsigned char *>(&result[0]), data, (int)len);
    result.resize(written);
    return result;
}

} // namespace AK
