#include "http_request.pb.h"
#include "imagemap.pb.h"
#include "proto_converters/converters.h"

std::string BuildMapFile(const ImageMapReq &req)
{
    std::string result{};
    if (req.map_directive_value().empty()) {
        return result;
    }
    switch (req.map_directive_key()) {
    case DIRECTIVE_BASE:
        result += "base";
        break;
    case DIRECTIVE_DEFAULT:
        result += "default";
        break;
    case DIRECTIVE_POLY:
        result += "poly";
        break;
    case DIRECTIVE_CIRCLE:
        result += "circle";
        break;
    case DIRECTIVE_RECT:
        result += "rect";
        break;
    case DIRECTIVE_POINT:
        result += "point";
        break;
    }
    result += " ";
    result += req.map_directive_value().data();
    return result;
}

std::string BuildImageMapReq(const ImageMapReq &req)
{
    std::string result{};
    std::string qs{};
    std::string mapfile{};
    HttpRequest http_req = req.http_req();

    // tmp
    // http_req.set_uri("/test.map");
    if (req.has_coord_x())
        qs += req.coord_x().data();
    if (req.has_coord_y()) {
        qs += ",";
        qs += req.coord_y().data();
    }
    if (!qs.empty()) {
        http_req.mutable_uri()->append("?" + qs);
    }

    result = BuildHttpRequest(http_req);
    return result;
}