/*
 * mod_pwn-Specific Custom Mutator for AFL++
 *
 * This mutator targets the intentional vulnerabilities in mod_pwn:
 * - Buffer overflows (stack and heap)
 * - Format strings
 * - Integer overflows
 * - Use-after-free
 * - Double free
 *
 * Compile:
 *   clang -shared -fPIC -O3 -o pwn_mutator.so pwn_mutator.c
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>

typedef struct afl_state {
    void *afl;
} afl_state_t;

typedef struct my_mutator {
    afl_state_t *afl;
    unsigned int seed;
} my_mutator_t;

/* Pwn-specific headers */
static const char *pwn_headers[] = {"X-Pwn-Overflow", "X-Pwn-Heap", "X-Pwn-Format", "X-Pwn-Integer",
                                    "X-Pwn-UAF",      "X-Pwn-Null", "X-Pwn-Double"};
static const int num_pwn_headers = 7;

/* Format string payloads */
static const char *format_strings[] = {"%s",     "%x",       "%n",      "%p",   "%d",
                                       "%s%s%s", "%x%x%x%x", "%n%n%n",  "%1$s", "%10$x",
                                       "%100$n", "%.1000s",  "%.10000x"};
static const int num_formats = 13;

/* Integer overflow values */
static const char *int_values[] = {"0",          "1",           "-1",          "127",
                                   "128",        "255",         "256",         "32767",
                                   "32768",      "65535",       "65536",       "2147483647",
                                   "2147483648", "-2147483648", "-2147483649", "4294967295",
                                   "4294967296"};
static const int num_ints = 17;

/* Overflow patterns */
static const int overflow_sizes[] = {16, 32, 64, 128, 256, 512, 1024, 2048, 4096};
static const int num_sizes = 9;

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

/* Find headers end */
static char *find_headers_end(const uint8_t *buf, size_t buf_size)
{
    if (buf_size < 4)
        return NULL;
    for (size_t i = 0; i <= buf_size - 4; i++) {
        if (buf[i] == '\r' && buf[i + 1] == '\n' && buf[i + 2] == '\r' && buf[i + 3] == '\n') {
            return (char *)&buf[i + 2];
        }
    }
    return NULL;
}

/* Mutation: Inject overflow header */
static size_t inject_overflow(uint8_t *buf, size_t buf_size, uint8_t *out_buf, size_t max_size)
{
    char *headers_end = find_headers_end(buf, buf_size);
    if (!headers_end)
        return 0;

    /* Choose overflow size */
    int size = overflow_sizes[rand() % num_sizes];
    char pattern = 'A' + (rand() % 26);

    /* Build header */
    char header[4096];
    int hdr_len = snprintf(header, sizeof(header), "X-Pwn-Overflow: ");
    if (hdr_len < 0)
        return 0;

    /* Add pattern */
    int pattern_len = size;
    if (hdr_len + pattern_len + 2 > sizeof(header)) {
        pattern_len = sizeof(header) - hdr_len - 3;
    }
    memset(header + hdr_len, pattern, pattern_len);
    hdr_len += pattern_len;

    /* Add CRLF */
    header[hdr_len++] = '\r';
    header[hdr_len++] = '\n';

    /* Assemble */
    size_t prefix_len = headers_end - (char *)buf;
    size_t suffix_len = buf_size - prefix_len;

    if (prefix_len + hdr_len + suffix_len > max_size)
        return 0;

    memcpy(out_buf, buf, prefix_len);
    memcpy(out_buf + prefix_len, header, hdr_len);
    memcpy(out_buf + prefix_len + hdr_len, headers_end, suffix_len);

    return prefix_len + hdr_len + suffix_len;
}

/* Mutation: Inject format string header */
static size_t inject_format(uint8_t *buf, size_t buf_size, uint8_t *out_buf, size_t max_size)
{
    char *headers_end = find_headers_end(buf, buf_size);
    if (!headers_end)
        return 0;

    /* Pick format string */
    const char *fmt = format_strings[rand() % num_formats];

    /* Build header */
    char header[256];
    int len = snprintf(header, sizeof(header), "X-Pwn-Format: %s\r\n", fmt);
    if (len <= 0)
        return 0;

    size_t prefix_len = headers_end - (char *)buf;
    size_t suffix_len = buf_size - prefix_len;

    if (prefix_len + len + suffix_len > max_size)
        return 0;

    memcpy(out_buf, buf, prefix_len);
    memcpy(out_buf + prefix_len, header, len);
    memcpy(out_buf + prefix_len + len, headers_end, suffix_len);

    return prefix_len + len + suffix_len;
}

/* Mutation: Inject integer overflow header */
static size_t inject_integer(uint8_t *buf, size_t buf_size, uint8_t *out_buf, size_t max_size)
{
    char *headers_end = find_headers_end(buf, buf_size);
    if (!headers_end)
        return 0;

    /* Pick integer value */
    const char *val = int_values[rand() % num_ints];

    /* Build header */
    char header[256];
    int len = snprintf(header, sizeof(header), "X-Pwn-Integer: %s\r\n", val);
    if (len <= 0)
        return 0;

    size_t prefix_len = headers_end - (char *)buf;
    size_t suffix_len = buf_size - prefix_len;

    if (prefix_len + len + suffix_len > max_size)
        return 0;

    memcpy(out_buf, buf, prefix_len);
    memcpy(out_buf + prefix_len, header, len);
    memcpy(out_buf + prefix_len + len, headers_end, suffix_len);

    return prefix_len + len + suffix_len;
}

/* Mutation: Inject UAF/Double-free trigger */
static size_t inject_trigger(uint8_t *buf, size_t buf_size, uint8_t *out_buf, size_t max_size)
{
    char *headers_end = find_headers_end(buf, buf_size);
    if (!headers_end)
        return 0;

    /* Pick trigger header */
    const char *hdr = pwn_headers[rand() % num_pwn_headers];

    /* Build header */
    char header[128];
    int len = snprintf(header, sizeof(header), "%s: 1\r\n", hdr);
    if (len <= 0)
        return 0;

    size_t prefix_len = headers_end - (char *)buf;
    size_t suffix_len = buf_size - prefix_len;

    if (prefix_len + len + suffix_len > max_size)
        return 0;

    memcpy(out_buf, buf, prefix_len);
    memcpy(out_buf + prefix_len, header, len);
    memcpy(out_buf + prefix_len + len, headers_end, suffix_len);

    return prefix_len + len + suffix_len;
}

/* Main mutation function */
size_t afl_custom_fuzz(
    void *data, uint8_t *buf, size_t buf_size, uint8_t **out_buf, uint8_t *add_buf,
    size_t add_buf_size, size_t max_size
)
{
    static uint8_t tmp_buf[1024 * 1024];
    *out_buf = tmp_buf;

    /* Choose mutation strategy */
    int strategy = rand() % 100;
    size_t new_size = 0;

    if (strategy < 40) {
        /* 40%: Buffer overflow */
        new_size = inject_overflow(buf, buf_size, tmp_buf, max_size);
    } else if (strategy < 60) {
        /* 20%: Format string */
        new_size = inject_format(buf, buf_size, tmp_buf, max_size);
    } else if (strategy < 80) {
        /* 20%: Integer overflow */
        new_size = inject_integer(buf, buf_size, tmp_buf, max_size);
    } else {
        /* 20%: UAF/Double-free */
        new_size = inject_trigger(buf, buf_size, tmp_buf, max_size);
    }

    if (new_size == 0) {
        memcpy(tmp_buf, buf, buf_size);
        new_size = buf_size;
    }

    return new_size;
}

size_t afl_custom_fuzz_count(void *data, const uint8_t *buf, size_t buf_size)
{
    return 15; /* Try more mutations for pwn */
}
