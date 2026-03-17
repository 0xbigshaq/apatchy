#include "http_request.pb.h"
#include "proto_converters/converters.h"
#include <cstring>

static const char *MethodToString(HttpMethod method)
{
    switch (method) {
    case GET:
        return "GET";
    case POST:
        return "POST";
    case PUT:
        return "PUT";
    case DELETE:
        return "DELETE";
    case HEAD:
        return "HEAD";
    case OPTIONS:
        return "OPTIONS";
    case PATCH:
        return "PATCH";
    case TRACE:
        return "TRACE";
    case CONNECT:
        return "CONNECT";
    case PROPFIND:
        return "PROPFIND";
    case PROXY:
        return "PROXY";
    default:
        return "GET";
    }
}

std::string BuildHttpRequest(const HttpRequest &req)
{
    std::string out;

    const char *method = MethodToString(req.method());
    std::string uri = req.uri();
    if (uri.empty() || uri[0] != '/')
        uri = "/" + uri;

    std::string version = req.has_http_version() ? req.http_version() : "HTTP/1.1";

    out += method;
    out += " ";
    out += uri;
    out += " ";
    out += version;
    out += "\r\n";

    bool has_host = false;
    bool has_content_length = false;

    for (int i = 0; i < req.headers_size(); i++) {
        const Header &hdr = req.headers(i);
        if (hdr.name().empty())
            continue;
        out += hdr.name();
        out += ": ";
        out += hdr.value();
        out += "\r\n";

        if (strcasecmp(hdr.name().c_str(), "host") == 0)
            has_host = true;
        if (strcasecmp(hdr.name().c_str(), "content-length") == 0)
            has_content_length = true;
    }

    if (!has_host)
        out += "Host: localhost\r\n";

    if (req.has_body() && req.body().size() > 0 && !has_content_length) {
        out += "Content-Length: ";
        out += std::to_string(req.body().size());
        out += "\r\n";
    }

    out += "\r\n";

    if (req.has_body())
        out.append(req.body());

    return out;
}
