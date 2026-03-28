/*
 * @description: proto harness - base HTTP2 fuzzing via libprotobuf-mutator
 * @protos: http2_request, http_request
 * @converters: http2
 *
 * Structure-aware libFuzzer harness using the base Http2Request schema.
 * No module-specific transforms -- pure HTTP request fuzzing.
 *
 * Build: apatchy link libfuzzer --harness mod_fuzzy_proto_http2
 * Run:   apatchy fuzz --engine libfuzzer
 */

#include "http2_request.pb.h"
#include "proto_converters/converters.h"
#include "proto_harness_common.h"
#include "src/libfuzzer/libfuzzer_macro.h"

DEFINE_PROTO_FUZZER(const Http2Request &request)
{
    if (!proto_harness_init())
        return;

    std::string raw = BuildHttp2Request(request);
    fuzz_one_input(raw.data(), raw.size());
}
