/*
 * Deflate Config+Input Custom Mutator for AFL++
 *
 * Experimental mutator that fuzzes both mod_deflate configuration and
 * HTTP request payloads simultaneously.  The fuzz input is split into
 * two parts:
 *
 *   [config seed: 12 bytes][HTTP request with gzipped body]
 *
 * The config seed is mapped deterministically to mod_deflate config
 * values (windowSize, memlevel, compressionlevel, bufferSize,
 * inflate_limit, ratio_limit, ratio_burst).  The HTTP request portion
 * is mutated with deflate-aware strategies (corrupt gzip headers,
 * truncate compressed streams, inject decompression bombs, etc.).
 *
 * The harness reads the first 12 bytes, patches mod_deflate's config
 * structs in-memory, and processes the remaining bytes as a normal
 * HTTP request.
 *
 * Compile:
 *   clang -shared -fPIC -O3 -o deflate_config_mutator.so deflate_config_mutator.c
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

/* Config seed is 12 bytes */
#define CONFIG_SEED_SIZE 12

#define MAX_BUF (1024 * 1024)
static uint8_t tmp_buf[MAX_BUF];

/* ----------------------------------------------------------------
 * Lifecycle
 * ---------------------------------------------------------------- */

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

/* ----------------------------------------------------------------
 * Helpers
 * ---------------------------------------------------------------- */

/* Find \r\n\r\n boundary between headers and body */
static size_t find_headers_end(const uint8_t *buf, size_t buf_size)
{
    if (buf_size < 4)
        return 0;
    for (size_t i = 0; i <= buf_size - 4; i++) {
        if (buf[i] == '\r' && buf[i + 1] == '\n' && buf[i + 2] == '\r' && buf[i + 3] == '\n') {
            return i;
        }
    }
    return 0;
}

/* Minimal gzip header (10 bytes) + zlib-compressed empty payload */
static const uint8_t minimal_gzip[] = {
    0x1f, 0x8b, 0x08, 0x00,             /* magic, method, flags */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x03, /* mtime, xfl, OS */
    0x03, 0x00,                         /* compressed empty block */
    0x00, 0x00, 0x00, 0x00,             /* crc32 */
    0x00, 0x00, 0x00, 0x00              /* isize */
};

/* ----------------------------------------------------------------
 * Config seed mutation strategies
 * ---------------------------------------------------------------- */

/* Randomize config seed bytes */
static void mutate_config_seed(uint8_t *seed)
{
    int strategy = rand() % 4;

    switch (strategy) {
    case 0:
        /* Fully random config */
        for (int i = 0; i < CONFIG_SEED_SIZE; i++)
            seed[i] = rand() & 0xff;
        break;

    case 1:
        /* Flip a few bits in existing seed */
        for (int i = 0; i < 1 + rand() % 3; i++) {
            int pos = rand() % CONFIG_SEED_SIZE;
            seed[pos] ^= (1 << (rand() % 8));
        }
        break;

    case 2:
        /* Set extreme values in a few fields */
        {
            int field = rand() % 5;
            switch (field) {
            case 0:
                seed[0] = 0;
                break; /* windowSize = min */
            case 1:
                seed[0] = 0xff;
                break; /* windowSize = max/wrap */
            case 2:
                seed[3] = 0xff;
                seed[4] = 0xff;
                seed[5] = 0xff;
                seed[6] = 0xff;
                break; /* huge bufferSize */
            case 3:
                seed[7] = 0xff;
                seed[8] = 0xff;
                seed[9] = 0xff;
                seed[10] = 0xff;
                break; /* huge inflate_limit */
            case 4:
                seed[11] = 0;
                break; /* ratio_burst = minimal */
            }
        }
        break;

    case 3:
        /* Zero out config (all defaults / zeros) */
        memset(seed, 0, CONFIG_SEED_SIZE);
        break;
    }
}

/* ----------------------------------------------------------------
 * HTTP payload mutation strategies
 * ---------------------------------------------------------------- */

/* Strategy 1: Corrupt gzip magic bytes in the body */
static size_t
corrupt_gzip_header(const uint8_t *http, size_t http_size, uint8_t *out, size_t max_size)
{
    size_t hend = find_headers_end(http, http_size);
    if (hend == 0 || hend + 4 + 10 >= http_size)
        return 0;

    if (http_size > max_size)
        return 0;

    memcpy(out, http, http_size);

    /* Find gzip magic (0x1f 0x8b) in the body and corrupt it */
    size_t body_start = hend + 4;
    for (size_t i = body_start; i < http_size - 1; i++) {
        if (out[i] == 0x1f && out[i + 1] == 0x8b) {
            int corruption = rand() % 4;
            switch (corruption) {
            case 0:
                out[i] = rand() & 0xff;
                break; /* corrupt ID1 */
            case 1:
                out[i + 1] = rand() & 0xff;
                break; /* corrupt ID2 */
            case 2:
                if (i + 2 < http_size)
                    out[i + 2] = rand() & 0xff;
                break; /* corrupt method */
            case 3:
                if (i + 3 < http_size)
                    out[i + 3] = rand() & 0xff;
                break; /* corrupt flags */
            }
            break;
        }
    }
    return http_size;
}

/* Strategy 2: Truncate the compressed body at a random point */
static size_t truncate_body(const uint8_t *http, size_t http_size, uint8_t *out, size_t max_size)
{
    size_t hend = find_headers_end(http, http_size);
    if (hend == 0)
        return 0;

    size_t body_start = hend + 4;
    size_t body_len = http_size - body_start;
    if (body_len < 2)
        return 0;

    /* Truncate body to random length */
    size_t new_body_len = 1 + rand() % body_len;
    size_t total = body_start + new_body_len;
    if (total > max_size)
        return 0;

    memcpy(out, http, total);
    return total;
}

/* Strategy 3: Inject Content-Encoding: gzip header if missing, and
 * append a minimal gzip body */
static size_t
inject_gzip_request(const uint8_t *http, size_t http_size, uint8_t *out, size_t max_size)
{
    size_t hend = find_headers_end(http, http_size);
    if (hend == 0)
        return 0;

    const char *ce_hdr = "Content-Encoding: gzip\r\n";
    size_t ce_len = strlen(ce_hdr);

    /* headers + CE header + \r\n\r\n + gzip body */
    size_t total = hend + ce_len + 4 + sizeof(minimal_gzip);
    if (total > max_size)
        return 0;

    size_t pos = 0;
    memcpy(out + pos, http, hend);
    pos += hend;
    memcpy(out + pos, ce_hdr, ce_len);
    pos += ce_len;
    memcpy(out + pos, "\r\n\r\n", 4);
    pos += 4;
    memcpy(out + pos, minimal_gzip, sizeof(minimal_gzip));
    pos += sizeof(minimal_gzip);

    return pos;
}

/* Strategy 4: Flip random bytes in the compressed body */
static size_t
corrupt_body_bytes(const uint8_t *http, size_t http_size, uint8_t *out, size_t max_size)
{
    size_t hend = find_headers_end(http, http_size);
    if (hend == 0)
        return 0;

    size_t body_start = hend + 4;
    if (body_start >= http_size || http_size > max_size)
        return 0;

    memcpy(out, http, http_size);

    /* Flip 1-8 random bytes in body */
    int flips = 1 + rand() % 8;
    size_t body_len = http_size - body_start;
    for (int i = 0; i < flips && body_len > 0; i++) {
        size_t pos = body_start + (rand() % body_len);
        out[pos] ^= (1 << (rand() % 8));
    }

    return http_size;
}

/* Strategy 5: Create a decompression bomb - small compressed data that
 * expands to a large output, to test ratio limiting */
static size_t inject_bomb(const uint8_t *http, size_t http_size, uint8_t *out, size_t max_size)
{
    size_t hend = find_headers_end(http, http_size);
    if (hend == 0)
        return 0;

    const char *ce_hdr = "Content-Encoding: gzip\r\n";
    size_t ce_len = strlen(ce_hdr);

    /* Build a gzip stream of repeated zeros (compresses very well).
     * Gzip header + deflate block with repeated zero bytes.
     * This is a minimal representation - the actual expansion depends
     * on zlib decompression. */
    uint8_t bomb[64];
    size_t bomb_len = 0;

    /* Gzip header */
    memcpy(bomb, minimal_gzip, 10);
    bomb_len = 10;

    /* A deflate stored block of zeros: BFINAL=1, BTYPE=00 (stored),
     * LEN=32, NLEN=~32, then 32 zero bytes */
    bomb[bomb_len++] = 0x01; /* BFINAL=1, BTYPE=00 */
    bomb[bomb_len++] = 0x20; /* LEN low byte (32) */
    bomb[bomb_len++] = 0x00; /* LEN high byte */
    bomb[bomb_len++] = 0xdf; /* NLEN low byte (~32) */
    bomb[bomb_len++] = 0xff; /* NLEN high byte */
    memset(bomb + bomb_len, 0, 32);
    bomb_len += 32;

    /* CRC32 and size (zeros for simplicity - will trigger CRC error
     * but the interesting part is the ratio check before that) */
    memset(bomb + bomb_len, 0, 8);
    bomb_len += 8;

    size_t total = hend + ce_len + 4 + bomb_len;
    if (total > max_size)
        return 0;

    size_t pos = 0;
    memcpy(out + pos, http, hend);
    pos += hend;
    memcpy(out + pos, ce_hdr, ce_len);
    pos += ce_len;
    memcpy(out + pos, "\r\n\r\n", 4);
    pos += 4;
    memcpy(out + pos, bomb, bomb_len);
    pos += bomb_len;

    return pos;
}

/* Strategy 6: Mutate HTTP method/path while keeping the body */
static size_t
mutate_request_line(const uint8_t *http, size_t http_size, uint8_t *out, size_t max_size)
{
    static const char *methods[] = {"GET", "POST", "PUT", "DELETE", "PATCH"};
    static const int num_methods = 5;

    if (http_size > max_size)
        return 0;

    /* Find first space */
    size_t sp = 0;
    for (size_t i = 0; i < http_size && i < 16; i++) {
        if (http[i] == ' ') {
            sp = i;
            break;
        }
    }
    if (sp == 0)
        return 0;

    const char *method = methods[rand() % num_methods];
    size_t mlen = strlen(method);
    size_t rest = http_size - sp;
    if (mlen + rest > max_size)
        return 0;

    memcpy(out, method, mlen);
    memcpy(out + mlen, http + sp, rest);
    return mlen + rest;
}

/* ----------------------------------------------------------------
 * Main mutation entry point
 * ---------------------------------------------------------------- */

size_t afl_custom_fuzz(
    void *data, uint8_t *buf, size_t buf_size, uint8_t **out_buf, uint8_t *add_buf,
    size_t add_buf_size, size_t max_size
)
{
    *out_buf = tmp_buf;

    if (max_size > MAX_BUF)
        max_size = MAX_BUF;

    /* Ensure input has at least a config seed + minimal HTTP */
    if (buf_size < CONFIG_SEED_SIZE + 16) {
        /* Too small - generate a minimal valid input */
        uint8_t seed[CONFIG_SEED_SIZE];
        for (int i = 0; i < CONFIG_SEED_SIZE; i++)
            seed[i] = rand() & 0xff;

        const char *req = "POST / HTTP/1.0\r\n"
                          "Content-Encoding: gzip\r\n"
                          "\r\n";
        size_t req_len = strlen(req);
        size_t total = CONFIG_SEED_SIZE + req_len + sizeof(minimal_gzip);
        if (total > max_size)
            total = max_size;

        memcpy(tmp_buf, seed, CONFIG_SEED_SIZE);
        size_t pos = CONFIG_SEED_SIZE;
        size_t remaining = total - pos;
        if (remaining > req_len) {
            memcpy(tmp_buf + pos, req, req_len);
            pos += req_len;
            remaining = total - pos;
            if (remaining > sizeof(minimal_gzip))
                remaining = sizeof(minimal_gzip);
            memcpy(tmp_buf + pos, minimal_gzip, remaining);
            pos += remaining;
        } else {
            memcpy(tmp_buf + pos, req, remaining);
            pos += remaining;
        }
        return pos;
    }

    /* Split: config seed | HTTP request */
    uint8_t config_seed[CONFIG_SEED_SIZE];
    memcpy(config_seed, buf, CONFIG_SEED_SIZE);

    const uint8_t *http = buf + CONFIG_SEED_SIZE;
    size_t http_size = buf_size - CONFIG_SEED_SIZE;

    /* Decide whether to mutate config, HTTP, or both */
    int what = rand() % 100;

    if (what < 30) {
        /* Mutate config only */
        mutate_config_seed(config_seed);
        memcpy(tmp_buf, config_seed, CONFIG_SEED_SIZE);
        size_t rest = http_size;
        if (CONFIG_SEED_SIZE + rest > max_size)
            rest = max_size - CONFIG_SEED_SIZE;
        memcpy(tmp_buf + CONFIG_SEED_SIZE, http, rest);
        return CONFIG_SEED_SIZE + rest;
    }

    if (what < 60) {
        /* Mutate HTTP only */
        memcpy(tmp_buf, config_seed, CONFIG_SEED_SIZE);
        size_t http_max = max_size - CONFIG_SEED_SIZE;

        int strategy = rand() % 6;
        size_t new_http_size = 0;

        switch (strategy) {
        case 0:
            new_http_size =
                corrupt_gzip_header(http, http_size, tmp_buf + CONFIG_SEED_SIZE, http_max);
            break;
        case 1:
            new_http_size = truncate_body(http, http_size, tmp_buf + CONFIG_SEED_SIZE, http_max);
            break;
        case 2:
            new_http_size =
                inject_gzip_request(http, http_size, tmp_buf + CONFIG_SEED_SIZE, http_max);
            break;
        case 3:
            new_http_size =
                corrupt_body_bytes(http, http_size, tmp_buf + CONFIG_SEED_SIZE, http_max);
            break;
        case 4:
            new_http_size = inject_bomb(http, http_size, tmp_buf + CONFIG_SEED_SIZE, http_max);
            break;
        case 5:
            new_http_size =
                mutate_request_line(http, http_size, tmp_buf + CONFIG_SEED_SIZE, http_max);
            break;
        }

        if (new_http_size > 0)
            return CONFIG_SEED_SIZE + new_http_size;

        /* Fallback: copy unchanged */
        size_t rest = http_size < http_max ? http_size : http_max;
        memcpy(tmp_buf + CONFIG_SEED_SIZE, http, rest);
        return CONFIG_SEED_SIZE + rest;
    }

    /* Mutate both config and HTTP */
    mutate_config_seed(config_seed);
    memcpy(tmp_buf, config_seed, CONFIG_SEED_SIZE);

    size_t http_max = max_size - CONFIG_SEED_SIZE;
    int strategy = rand() % 6;
    size_t new_http_size = 0;

    switch (strategy) {
    case 0:
        new_http_size = corrupt_gzip_header(http, http_size, tmp_buf + CONFIG_SEED_SIZE, http_max);
        break;
    case 1:
        new_http_size = truncate_body(http, http_size, tmp_buf + CONFIG_SEED_SIZE, http_max);
        break;
    case 2:
        new_http_size = inject_gzip_request(http, http_size, tmp_buf + CONFIG_SEED_SIZE, http_max);
        break;
    case 3:
        new_http_size = corrupt_body_bytes(http, http_size, tmp_buf + CONFIG_SEED_SIZE, http_max);
        break;
    case 4:
        new_http_size = inject_bomb(http, http_size, tmp_buf + CONFIG_SEED_SIZE, http_max);
        break;
    case 5:
        new_http_size = mutate_request_line(http, http_size, tmp_buf + CONFIG_SEED_SIZE, http_max);
        break;
    }

    if (new_http_size > 0)
        return CONFIG_SEED_SIZE + new_http_size;

    /* Fallback */
    size_t rest = http_size < http_max ? http_size : http_max;
    memcpy(tmp_buf + CONFIG_SEED_SIZE, http, rest);
    return CONFIG_SEED_SIZE + rest;
}

size_t afl_custom_fuzz_count(void *data, const uint8_t *buf, size_t buf_size)
{
    return 8;
}
