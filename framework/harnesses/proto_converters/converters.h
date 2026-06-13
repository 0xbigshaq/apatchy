#pragma once

#include <string>

// Base HTTP conversion: method line, headers, body
class HttpRequest;
std::string BuildHttpRequest(const HttpRequest &req);

// fuzz the entire request cycle
class UwsgiRequest;
class UwsgiResponse;
std::string BuildUwsgiRequest(const UwsgiRequest &req);
std::string BuildUwsgiResponse(const UwsgiResponse &resp);

// Session crypto: encrypt/encode session data, set path, inject Cookie header
class SessionCookie;
enum SessionRoute : int;
void ApplySessionCrypto(const SessionCookie &cookie, SessionRoute route, std::string &request);

// Pwn: inject X-Pwn-* headers for overflow/format/integer/UAF targets
class PwnRequest;
void ApplyPwn(const PwnRequest &pwn, std::string &request);

// Multipart: assemble multipart/form-data body with boundary manipulation
class MultipartRequest;
void ApplyMultipart(const MultipartRequest &mp, std::string &request);

// Rewrite: replace URI with mod_rewrite-targeted payloads
class RewriteRequest;
void ApplyRewrite(const RewriteRequest &rw, std::string &request);

// AJP: build binary AJP response packets and HTTP request
class AjpRequest;
class AjpResponse;
std::string BuildAjpRequest(const AjpRequest &req);
std::string BuildAjpResponse(const AjpResponse &resp);
std::string BuildAjpDefaultResponse();

// HTTP2
class Http2Request;
std::string BuildHttp2Request(const Http2Request &req);

// ImageMap
class ImageMapReq;
std::string BuildImageMapReq(const ImageMapReq &req);
std::string BuildMapFile(const ImageMapReq &req);

// Charset: chunked request body that straddles buckets to drive
// mod_charset_lite's finish_partial_char() partial-char heap overflow
class CharsetBody;
std::string BuildCharsetRequest(const CharsetBody &req);