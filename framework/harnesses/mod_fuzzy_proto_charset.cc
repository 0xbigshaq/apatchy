/*
 * @description: proto harness - mod_charset_lite request-body charset xlate (finish_partial_char heap overflow)
 * @protos: http_request, charset_body
 * @converters: charset
 *
 * Targets modules/filters/mod_charset_lite.c:finish_partial_char().
 *
 * mod_charset_lite sets up a request-body translation filter (XLATEIN) for
 * POST/PUT requests when CharsetSourceEnc != CharsetDefault. On input the iconv
 * "frompage" is CharsetDefault, so configuring CharsetDefault to a multibyte
 * ISO-2022-* charset makes the translation non-single-byte (is_sb == 0) and
 * enables the partial-char straddle path.
 *
 * xlate_in_filter -> xlate_brigade processes the body bucket by bucket. When a
 * bucket ends in an incomplete multibyte char, set_aside_partial_char() saves
 * the tail into the 8-byte ctx->buf (only when saved < 8). On the next bucket
 * finish_partial_char() appends bytes one at a time:
 *
 *     do {
 *         ctx->buf[ctx->saved] = **cur_str;   // <-- no bound check
 *         ++ctx->saved;
 *         ...
 *     } while (rv == APR_INCOMPLETE && *cur_len);
 *
 * With a never-completing escape sequence and a long second bucket, ctx->saved
 * marches past 8 -> heap overflow. The converter emits a chunked body so the
 * first chunk (incomplete escape) and the second chunk (the driver run) land in
 * separate buckets.
 *
 * Build: apatchy link --harness mod_fuzzy_proto_charset
 * Run:   apatchy fuzz --config configs/charset.conf --seed-dir fuzz-seeds/charset
 */
#include "charset_body.pb.h"
#include "proto_converters/converters.h"
#include "proto_harness_common.h"
#include "src/libfuzzer/libfuzzer_macro.h"

DEFINE_PROTO_FUZZER(const CharsetBody &req)
{
    if (!proto_harness_init())
        return;

    std::string raw = BuildCharsetRequest(req);
    fuzz_one_input(raw.data(), raw.size());
}
