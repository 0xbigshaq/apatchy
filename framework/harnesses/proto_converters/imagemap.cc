#include "http_request.pb.h"
#include "imagemap.pb.h"
#include "proto_converters/converters.h"

std::string BuildImageMapReq(const ImageMapReq &req)
{
    std::string result{};
    std::string qs{};
    HttpRequest http_req = req.http_req();

    http_req.set_uri("/test.map");
    if (req.has_coord_x())
        qs += req.coord_x().data();
    if (req.has_coord_y()) {
        qs += ",";
        qs += req.coord_y().data();
    }
    if (!qs.empty()) {
        http_req.set_uri("/test.map?" + qs);
    } else {
        http_req.set_uri("/test.map?empty");
    }

    result = BuildHttpRequest(http_req);
    return result;
}