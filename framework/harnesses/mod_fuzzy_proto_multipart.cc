/*
 * @description: proto harness - multipart boundary attack fuzzing
 * @protos: http_request, multipart_request
 * @converters: http, multipart
 *
 * Structure-aware libFuzzer harness targeting multipart/form-data parsing.
 * Exercises boundary manipulation, tight spacing (CVE-2021-44790 pattern),
 * Content-Disposition corruption, and fake boundary injection.
 *
 * Build: apatchy link libfuzzer --harness mod_fuzzy_proto_multipart
 * Run:   apatchy fuzz --engine libfuzzer
 */

#include "multipart_request.pb.h"
#include "proto_converters/converters.h"
#include "proto_harness_common.h"
#include "src/libfuzzer/libfuzzer_macro.h"

DEFINE_PROTO_FUZZER(const MultipartRequest &mp)
{
    if (!proto_harness_init())
        return;

    std::string raw = BuildHttpRequest(mp.http());
    ApplyMultipart(mp, raw);
    fuzz_one_input(raw.data(), raw.size());
}
