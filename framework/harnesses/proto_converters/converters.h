#pragma once

#include <string>

class HttpRequest;
class SessionCookie;
class PwnRequest;
class MultipartRequest;
class RewriteRequest;
enum SessionRoute : int;

// Base HTTP conversion: method line, headers, body
std::string BuildHttpRequest(const HttpRequest &req);

// Session crypto: encrypt/encode session data, set path, inject Cookie header
void ApplySessionCrypto(const SessionCookie &cookie, SessionRoute route, std::string &request);

// Pwn: inject X-Pwn-* headers for overflow/format/integer/UAF targets
void ApplyPwn(const PwnRequest &pwn, std::string &request);

// Multipart: assemble multipart/form-data body with boundary manipulation
void ApplyMultipart(const MultipartRequest &mp, std::string &request);

// Rewrite: replace URI with mod_rewrite-targeted payloads
void ApplyRewrite(const RewriteRequest &rw, std::string &request);
