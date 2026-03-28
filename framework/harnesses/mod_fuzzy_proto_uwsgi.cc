/*
 * @description: proto harness - uwsgi HTTP fuzzing via libprotobuf-mutator
 * @protos: http_request, uwsgi_req_res
 * @converters: http, uwsgi
 * @extras: fuzz_backend
 *
 * Structure-aware libFuzzer harness using the base HttpRequest schema.
 * No module-specific transforms -- pure HTTP request fuzzing.
 *
 * Build: apatchy link libfuzzer --harness mod_fuzzy_proto
 * Run:   apatchy fuzz --engine libfuzzer
 */
extern "C" {
#include "fuzz_backend.h"
}
#include "proto_converters/converters.h"
#include "proto_harness_common.h"
#include "src/libfuzzer/libfuzzer_macro.h"
#include "uwsgi_req_res.pb.h"

DEFINE_PROTO_FUZZER(const UwsgiRequest &req)
{
    std::string raw_req;
    std::string raw_res;
    if (!proto_harness_init())
        return;

    g_backend_enabled = 1;

    raw_req = BuildUwsgiRequest(req);
    if (req.has_resp())
        raw_res = BuildUwsgiResponse(req.resp());
    else
        raw_res = "HTTP/1.1 200 OK\r\n\r\n";

    g_backend_buf = raw_res.data();
    g_backend_size = raw_res.size();

    fuzz_one_input(raw_req.data(), raw_req.size());
}
