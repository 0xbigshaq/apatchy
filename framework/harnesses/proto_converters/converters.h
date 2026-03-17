#pragma once

#include <string>

class HttpRequest;
class SessionCookie;
enum SessionRoute : int;

// Base HTTP conversion: method line, headers, body
std::string BuildHttpRequest(const HttpRequest &req);

// Session crypto: encrypt/encode session data, set path, inject Cookie header
void ApplySessionCrypto(const SessionCookie &cookie, SessionRoute route, std::string &request);
