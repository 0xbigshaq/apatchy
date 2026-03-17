/*
 * @description: proto harness - mod_rewrite URL rewriting engine fuzzing
 *
 * Structure-aware libFuzzer harness targeting mod_rewrite's rewrite rules,
 * backreference expansion, variable lookups, and flag processing.
 *
 * Build: apatchy link libfuzzer --harness mod_fuzzy_proto_rewrite
 * Run:   apatchy fuzz --engine libfuzzer
 */

#include "proto_converters/converters.h"
#include "proto_harness_common.h"
#include "rewrite_request.pb.h"
#include "src/libfuzzer/libfuzzer_macro.h"

DEFINE_PROTO_FUZZER(const RewriteRequest &rw)
{
    if (!proto_harness_init())
        return;

    std::string raw = BuildHttpRequest(rw.http());
    ApplyRewrite(rw, raw);
    fuzz_one_input(raw.data(), raw.size());
}
