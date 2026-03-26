#include "proto_converters/converters.h"
#include <ajp_response.pb.h>

static uint16_t StatusFromCode(AjpResponseCode rc)
{
    switch (rc) {
    case AJP_OK_200:
        return 200;
    case AJP_CREATED_201:
        return 201;
    case AJP_REDIRECT_301:
        return 301;
    case AJP_REDIRECT_302:
        return 302;
    case AJP_NOT_MODIFIED_304:
        return 304;
    case AJP_BAD_REQUEST_400:
        return 400;
    case AJP_UNAUTHORIZED_401:
        return 401;
    case AJP_FORBIDDEN_403:
        return 403;
    case AJP_NOT_FOUND_404:
        return 404;
    case AJP_SERVER_ERROR_500:
        return 500;
    case AJP_BAD_GATEWAY_502:
        return 502;
    case AJP_SERVICE_UNAVAILABLE_503:
        return 503;
    default:
        return 200;
    }
}

static void ajp_append_uint16(std::string &buf, uint16_t val)
{
    buf += (char)((val >> 8) & 0xFF);
    buf += (char)(val & 0xFF);
}

static void ajp_append_uint8(std::string &buf, uint8_t val)
{
    buf += (char)val;
}

static void ajp_append_string(std::string &buf, const std::string &s)
{
    ajp_append_uint16(buf, (uint16_t)s.size());
    buf.append(s);
    buf += '\0';
}

static std::string ajp_wrap_packet(const std::string &payload)
{
    std::string pkt;
    pkt += (char)0x41;
    pkt += (char)0x42;
    ajp_append_uint16(pkt, (uint16_t)payload.size());
    pkt.append(payload);
    return pkt;
}

static uint16_t EncodedHeaderCode(AjpEncodedHeader code)
{
    switch (code) {
    case AJP_HDR_CONTENT_TYPE:
        return 0xA001;
    case AJP_HDR_CONTENT_LANGUAGE:
        return 0xA002;
    case AJP_HDR_CONTENT_LENGTH:
        return 0xA003;
    case AJP_HDR_DATE:
        return 0xA004;
    case AJP_HDR_LAST_MODIFIED:
        return 0xA005;
    case AJP_HDR_LOCATION:
        return 0xA006;
    case AJP_HDR_SET_COOKIE:
        return 0xA007;
    case AJP_HDR_SET_COOKIE2:
        return 0xA008;
    case AJP_HDR_SERVLET_ENGINE:
        return 0xA009;
    case AJP_HDR_STATUS:
        return 0xA00A;
    case AJP_HDR_WWW_AUTHENTICATE:
        return 0xA00B;
    default:
        return 0;
    }
}

std::string BuildAjpResponse(const AjpResponse &resp)
{
    std::string result;

    /* CPONG packet (0x09) - response to CPING probe */
    if (resp.send_cpong()) {
        std::string payload;
        ajp_append_uint8(payload, 0x09);
        result += ajp_wrap_packet(payload);
    }

    /* SEND_HEADERS packet */
    {
        std::string payload;
        const AjpSendHeaders &hdr = resp.send_headers();

        ajp_append_uint8(payload, 0x04); /* CMD_AJP13_SEND_HEADERS */
        ajp_append_uint16(payload, StatusFromCode(hdr.status()));
        ajp_append_string(payload, hdr.status_msg());
        ajp_append_uint16(payload, (uint16_t)hdr.headers_size());

        for (int i = 0; i < hdr.headers_size(); i++) {
            const AjpResponseHeader &h = hdr.headers(i);
            uint16_t code = EncodedHeaderCode(h.code());
            if (code != 0) {
                ajp_append_uint16(payload, code);
            } else {
                std::string name = h.has_raw_name() ? h.raw_name() : "X-Custom";
                ajp_append_string(payload, name);
            }
            ajp_append_string(payload, h.value());
        }

        result += ajp_wrap_packet(payload);
    }

    /* SEND_BODY_CHUNK packets */
    for (int i = 0; i < resp.body_chunks_size(); i++) {
        const AjpBodyChunk &chunk = resp.body_chunks(i);
        const std::string &data = chunk.data();
        if (data.empty())
            continue;

        std::string payload;
        ajp_append_uint8(payload, 0x03); /* CMD_AJP13_SEND_BODY_CHUNK */
        ajp_append_uint16(payload, (uint16_t)data.size());
        payload.append(data);
        payload += '\0'; /* trailing null */

        result += ajp_wrap_packet(payload);
    }

    /* END_RESPONSE packet */
    {
        std::string payload;
        ajp_append_uint8(payload, 0x05); /* CMD_AJP13_END_RESPONSE */
        ajp_append_uint8(payload, resp.reuse() ? 1 : 0);

        result += ajp_wrap_packet(payload);
    }

    return result;
}

static const char *AjpMethodToString(AjpHttpMethod method)
{
    switch (method) {
    case AJP_GET:
        return "GET";
    case AJP_POST:
        return "POST";
    case AJP_PUT:
        return "PUT";
    case AJP_DELETE:
        return "DELETE";
    case AJP_HEAD:
        return "HEAD";
    case AJP_OPTIONS:
        return "OPTIONS";
    default:
        return "GET";
    }
}

std::string BuildAjpDefaultResponse()
{
    std::string result;

    /* SEND_HEADERS: 200 OK, no headers */
    {
        std::string payload;
        ajp_append_uint8(payload, 0x04);
        ajp_append_uint16(payload, 200);
        ajp_append_string(payload, "OK");
        ajp_append_uint16(payload, 0);
        result += ajp_wrap_packet(payload);
    }

    /* END_RESPONSE: reuse=1 */
    {
        std::string payload;
        ajp_append_uint8(payload, 0x05);
        ajp_append_uint8(payload, 1);
        result += ajp_wrap_packet(payload);
    }

    return result;
}

std::string BuildAjpRequest(const AjpRequest &req)
{
    std::string out;

    const char *method = AjpMethodToString(req.method());
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
