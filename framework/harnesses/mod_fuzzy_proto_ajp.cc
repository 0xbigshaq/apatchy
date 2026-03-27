/*
 * @description: proto harness - AJP request + response fuzzing via libprotobuf-mutator
 * @protos: http_request, ajp_response
 * @converters: http, ajp
 * @ldflags: -Wl,--wrap=ap_proxy_connect_backend
 *
 * Fuzzes both the HTTP-to-AJP request translation and the binary AJP
 * response parsing in mod_proxy_ajp. The HTTP request is sent through
 * the proxy path while the AJP response is injected via a socketpair
 * in fuzz_backend.
 *
 * Build: apatchy link libfuzzer --harness mod_fuzzy_proto_ajp
 * Run:   apatchy fuzz --engine libfuzzer
 */
#include "proto_converters/converters.h"
#include "proto_harness_common.h"
#include "src/libfuzzer/libfuzzer_macro.h"
#include "ajp_response.pb.h"
#include "fuzz_backend.h"

DEFINE_PROTO_FUZZER(const AjpRequest &req)
{
    if (!proto_harness_init())
        return;

    g_backend_enabled = 1;

    std::string raw_req = BuildAjpRequest(req);
    std::string raw_resp;
    if (req.has_raw_resp() && req.raw_resp().size() > 0)
        raw_resp = req.raw_resp();
    else if (req.has_resp())
        raw_resp = BuildAjpResponse(req.resp());
    else
        raw_resp = BuildAjpDefaultResponse();

    g_backend_buf = raw_resp.data();
    g_backend_size = raw_resp.size();
    fuzz_one_input(raw_req.data(), raw_req.size());
}
