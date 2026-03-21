/*
 * @description: proto harness - multi-request fuzzing via libprotobuf-mutator
 * @protos: http_request, multi_request
 * @converters: http
 *
 * Structure-aware multi-request harness. Sends an array of HTTP requests
 * in a single fuzzer iteration. Two modes:
 *
 *   keep_alive=false  Each request gets its own connection (separate conn_rec).
 *                     Tests cross-connection state: module globals, cleanup.
 *
 *   keep_alive=true   All requests are concatenated into one buffer and sent
 *                     on a single connection. Apache's keep-alive loop
 *                     processes them sequentially on the same conn_rec.
 *                     Tests request boundary parsing, connection state leaks.
 *
 * Build: apatchy link libfuzzer --harness mod_fuzzy_proto_multi
 * Run:   apatchy fuzz --engine libfuzzer
 */
extern "C" {
#include "fuzz_common.h"
}
#include "multi_request.pb.h"
#include "proto_converters/converters.h"
#include "proto_harness_common.h"
#include "src/libfuzzer/libfuzzer_macro.h"

#define MAX_REQUESTS 16

DEFINE_PROTO_FUZZER(const MultiRequest &multi)
{
    if (!proto_harness_init())
        return;

    int count = multi.requests_size();
    if (count == 0)
        return;
    if (count > MAX_REQUESTS)
        count = MAX_REQUESTS;

    if (multi.keep_alive()) {
        std::string combined;
        for (int i = 0; i < count; i++)
            combined += BuildHttpRequest(multi.requests(i));

        fuzz_one_input(combined.data(), combined.size());
    } else {
        for (int i = 0; i < count; i++) {
            std::string raw = BuildHttpRequest(multi.requests(i));
            fuzz_one_input(raw.data(), raw.size());
        }
    }
}
