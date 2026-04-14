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

#include "imagemap.pb.h"
#include "proto_converters/converters.h"
#include "proto_harness_common.h"
#include "src/libfuzzer/libfuzzer_macro.h"
#include <fstream>

DEFINE_PROTO_FUZZER(const ImageMapReq &req)
{
    if (!proto_harness_init())
        return;

    std::string raw = BuildImageMapReq(req);
    std::string mapfile = BuildMapFile(req);
    if (mapfile.empty() || req.http_req().uri().empty())
        return;
    // std::cout << mapfile << "\n";
    // std::cout << "===----------===\n";
    // std::cout << raw << "\n";
    // write the mapfile contents into `/tmp/htdocs/test.map`(?)
    /*
     * we have two options:F
     * Approach #1. hook the function that returns the contents of the file
        > `apr_file_open()` will return a file descriptor
        > our fuzzer will write to that descriptor
        > every time `ap_cfg_getline()` is called, our fuzzer input
          will be injected into its return value.

     * Approach #2. write to the `test.map` file ourselves
     *
     * for now, we'll take approach #2
    */
    std::ofstream out_file("/tmp/htdocs/test.map");
    if (!out_file) {
        return;
    }
    out_file << mapfile;
    out_file.close();

    fuzz_one_input(raw.data(), raw.size());
}
