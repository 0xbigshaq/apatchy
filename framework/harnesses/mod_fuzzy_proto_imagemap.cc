/*
 * @description: proto harness - mod_imagemap engine fuzzing
 * @protos: http_request, imagemap
 * @converters: http, imagemap
 *
 * Structure-aware libFuzzer harness targeting mod_imagemap's handler logic,
 * TODO: add config fuzzing too
 *
 * Build: apatchy link libfuzzer --harness mod_fuzzy_proto_imagemap
 * Run:   apatchy fuzz --engine libfuzzer
 */

#include "proto_converters/converters.h"
#include "proto_harness_common.h"
#include "imagemap.pb.h"
#include "src/libfuzzer/libfuzzer_macro.h"

DEFINE_PROTO_FUZZER(const ImageMapReq &req)
{
    if (!proto_harness_init())
        return;

    std::string raw = BuildImageMapReq(req);
    fuzz_one_input(raw.data(), raw.size());
}
