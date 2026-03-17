/*
 * @description: proto harness - base HTTP fuzzing via libprotobuf-mutator
 *
 * Structure-aware libFuzzer harness using the base HttpRequest schema.
 * No module-specific transforms -- pure HTTP request fuzzing.
 *
 * Build: apatchy link libfuzzer --harness mod_fuzzy_proto
 * Run:   apatchy fuzz --engine libfuzzer
 */

#include "http_request.pb.h"
#include "proto_converters/converters.h"
#include "proto_harness_common.h"
#include "src/libfuzzer/libfuzzer_macro.h"

DEFINE_PROTO_FUZZER(const HttpRequest &request)
{
    if (!proto_harness_init())
        return;

    std::string raw = BuildHttpRequest(request);
    fuzz_one_input(raw.data(), raw.size());
}
