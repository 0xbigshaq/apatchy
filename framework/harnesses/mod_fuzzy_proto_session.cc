/*
 * @description: proto harness - mod_session_crypto fuzzing via libprotobuf-mutator
 *
 * Structure-aware libFuzzer harness for mod_session_crypto.
 * LPM mutates both the HTTP request and session cookie data independently.
 * The converter encrypts/encodes the cookie matching mod_session_crypto's format.
 *
 * Build: apatchy link libfuzzer --harness mod_fuzzy_proto_session
 * Run:   apatchy fuzz --engine libfuzzer --config configs/session_crypto.conf
 */

#include "session_crypto.pb.h"
#include "proto_converters/converters.h"
#include "proto_harness_common.h"
#include "src/libfuzzer/libfuzzer_macro.h"

DEFINE_PROTO_FUZZER(const SessionCryptoRequest &request)
{
    if (!proto_harness_init())
        return;

    std::string raw = BuildHttpRequest(request.http());
    ApplySessionCrypto(request.cookie(), request.route(), raw);
    fuzz_one_input(raw.data(), raw.size());
}
