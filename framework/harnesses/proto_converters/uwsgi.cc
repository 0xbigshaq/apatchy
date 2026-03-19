#include "proto_converters/converters.h"
#include <uwsgi_req_res.pb.h>

static std::string StatusFromCode(ResponseCode rc)
{
    switch (rc) {
    case OK_200:
        return "200 OK";
    case REDIRECT_301:
        return "301 Moved Permanently";
    case REDIRECT_302:
        return "302 Found";
    case CLIENT_ERROR_400:
        return "400 Bad Request";
    case SERVER_ERROR_500:
        return "500 Internal Server Error";
    default:
        return "200 OK";
    }
}

std::string BuildUwsgiResponse(const UwsgiResponse &resp)
{
    std::string result = "";
    result += resp.http_version();
    result += " ";
    result += StatusFromCode(resp.rc());
    result += "\r\n";
    for (auto idx = 0; idx < resp.headers().size(); idx++) {
        Header cur_header = resp.headers(idx);
        result += cur_header.name();
        result += ": ";
        result += cur_header.value();
        result += "\r\n";
    }
    result += "\r\n"; // end of headers
    if (resp.has_body()) {
        result += resp.body();
    }
    return result;
}

static const char *MethodToString(UwsgiHttpMethod method)
{
    switch (method) {
    case UWSGI_GET:
        return "GET";
    case UWSGI_POST:
        return "POST";
    case UWSGI_PUT:
        return "PUT";
    case UWSGI_DELETE:
        return "DELETE";
    case UWSGI_HEAD:
        return "HEAD";
    case UWSGI_OPTIONS:
        return "OPTIONS";
    case UWSGI_PATCH:
        return "PATCH";
    case UWSGI_TRACE:
        return "TRACE";
    case UWSGI_CONNECT:
        return "CONNECT";
    case UWSGI_PROPFIND:
        return "PROPFIND";
    case UWSGI_PROXY:
        return "PROXY";
    default:
        return "GET";
    }
}

std::string BuildUwsgiRequest(const UwsgiRequest &req)
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

    if (req.has_req_body() && req.req_body().size() > 0 && !has_content_length) {
        out += "Content-Length: ";
        out += std::to_string(req.req_body().size());
        out += "\r\n";
    }

    out += "\r\n";

    if (req.has_req_body())
        out.append(req.req_body());

    return out;
}
