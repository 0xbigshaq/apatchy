/*
 * @description: proto harness - mod_pwn vulnerability-targeted fuzzing
 * @protos: http_request, pwn_request
 * @converters: http, pwn
 *
 * Structure-aware libFuzzer harness targeting mod_pwn's intentional
 * vulnerabilities: buffer overflows, format strings, integer overflows,
 * use-after-free, double free.
 *
 * Build: apatchy link libfuzzer --harness mod_fuzzy_proto_pwn
 * Run:   apatchy fuzz --engine libfuzzer
 */

#include "proto_converters/converters.h"
#include "proto_harness_common.h"
#include "pwn_request.pb.h"
#include "src/libfuzzer/libfuzzer_macro.h"

DEFINE_PROTO_FUZZER(const PwnRequest &pwn)
{
    if (!proto_harness_init())
        return;

    std::string raw = BuildHttpRequest(pwn.http());
    ApplyPwn(pwn, raw);
    fuzz_one_input(raw.data(), raw.size());
}
