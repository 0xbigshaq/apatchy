import sys


def application(environ, start_response):
    method = environ.get("REQUEST_METHOD", "GET")
    path = environ.get("PATH_INFO", "/")
    query = environ.get("QUERY_STRING", "")
    content_type = environ.get("CONTENT_TYPE", "")
    content_length = environ.get("CONTENT_LENGTH", "0")

    # Read request body if present
    body = b""
    try:
        length = int(content_length)
        if length > 0:
            body = environ["wsgi.input"].read(length)
    except (ValueError, KeyError):
        pass

    # Collect HTTP headers from environ
    headers = []
    for key, val in environ.items():
        if key.startswith("HTTP_"):
            headers.append("%s: %s" % (key[5:], val))

    parts = [
        "method=%s" % method,
        "path=%s" % path,
        "query=%s" % query,
        "content_type=%s" % content_type,
        "body_length=%d" % len(body),
        "python=%s" % sys.version,
    ]
    parts.extend(headers)

    output = "\n".join(parts).encode("utf-8")

    status = "200 OK"
    response_headers = [
        ("Content-Type", "text/plain"),
        ("Content-Length", str(len(output))),
    ]
    start_response(status, response_headers)
    return [output]
