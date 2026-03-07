require "string"

function handle(r)
    r.content_type = "text/plain"

    -- Request metadata access
    local method = r.method
    local uri = r.uri
    local unparsed_uri = r.unparsed_uri
    local args_str = r.args or ""
    local hostname = r.hostname or ""
    local the_request = r.the_request or ""
    local protocol = r.protocol or ""

    r:puts("method=" .. method .. "\n")
    r:puts("uri=" .. uri .. "\n")
    r:puts("protocol=" .. protocol .. "\n")

    -- Parse query string (every request)
    local get_args, get_args_table = r:parseargs()
    if get_args then
        for k, v in pairs(get_args) do
            r:puts("arg: " .. tostring(k) .. "=" .. tostring(v) .. "\n")
        end
    end

    -- Parse POST body (urlencoded and multipart)
    if method == "POST" or method == "PUT" or method == "PATCH" then
        local post_args, post_args_table = r:parsebody(8192)
        if post_args then
            for k, v in pairs(post_args) do
                r:puts("body: " .. tostring(k) .. "=" .. tostring(v) .. "\n")
            end
        end
    end

    -- Raw request body (separate code path from parsebody)
    if method == "PUT" then
        local raw = r:requestbody()
        if raw then
            r:puts("rawlen=" .. string.len(raw) .. "\n")
        end
    end

    -- Iterate all request headers
    local hdrs = r.headers_in
    if hdrs then
        for k, v in pairs(hdrs) do
            r:puts("hdr: " .. tostring(k) .. ": " .. tostring(v) .. "\n")
        end
    end

    -- Headers as table (different code path)
    local hdr_table = r:headers_in_table()

    -- Cookie access
    local session_cookie = r:getcookie("session")
    local token_cookie = r:getcookie("token")
    local fuzz_cookie = r:getcookie("fuzz")
    if session_cookie then r:puts("cookie_session=" .. session_cookie .. "\n") end
    if token_cookie then r:puts("cookie_token=" .. token_cookie .. "\n") end

    -- Encoding/decoding utilities on input data
    local sample = args_str
    if string.len(sample) == 0 then sample = "test<>&data" end

    local escaped_html = r:escape_html(sample)
    local escaped_url = r:escape(sample)
    local unescaped = r:unescape(escaped_url)
    r:puts("escaped_html=" .. escaped_html .. "\n")

    -- Base64 encode/decode
    local b64 = r:base64_encode(sample)
    local decoded = r:base64_decode(b64)
    r:puts("b64=" .. b64 .. "\n")

    -- Hashing
    local md5sum = r:md5(sample)
    local sha1sum = r:sha1(sample)
    r:puts("md5=" .. md5sum .. "\n")
    r:puts("sha1=" .. sha1sum .. "\n")

    -- Date parsing from request headers
    local date_hdr = hdrs and hdrs["Date"] or nil
    local ims_hdr = hdrs and hdrs["If-Modified-Since"] or nil
    if date_hdr then
        local ts = r:date_parse_rfc(date_hdr)
        r:puts("parsed_date=" .. tostring(ts) .. "\n")
    end
    if ims_hdr then
        local ts = r:date_parse_rfc(ims_hdr)
        r:puts("parsed_ims=" .. tostring(ts) .. "\n")
    end

    -- Regex matching on URI
    local match = r:regex(uri, "^/([a-z]+)")
    if match then
        r:puts("regex_match=" .. tostring(match[0]) .. "\n")
    end

    -- Glob pattern matching
    local glob_match = r:strcmp_match(uri, "/handler*")
    r:puts("glob=" .. tostring(glob_match) .. "\n")

    -- URL construction
    local full_url = r:construct_url(uri)
    r:puts("url=" .. full_url .. "\n")

    -- Filesystem stat on document root (read-only)
    local info = r:stat("/tmp/htdocs")
    if info then
        r:puts("docroot_type=" .. tostring(info.filetype) .. "\n")
    end

    -- ap_expr evaluation
    local expr_result = r:expr("%{REQUEST_METHOD} == 'GET'")
    r:puts("expr=" .. tostring(expr_result) .. "\n")

    -- ETag generation
    local etag = r:make_etag()
    if etag then r:puts("etag=" .. etag .. "\n") end

    -- Scoreboard access
    local sb_proc = r:scoreboard_process(0)
    if sb_proc then r:puts("sb_proc_pid=" .. tostring(sb_proc.pid) .. "\n") end
    local sb_worker = r:scoreboard_worker(0, 0)

    -- MPM query
    local mpm_result = r:mpm_query(0)
    r:puts("mpm=" .. tostring(mpm_result) .. "\n")

    -- Module introspection
    local modules = r:loaded_modules()
    if modules then
        r:puts("modules=" .. tostring(#modules) .. "\n")
    end

    -- SSL var lookup (nil without SSL, exercises code path)
    local ssl_var = r:ssl_var_lookup("SSL_PROTOCOL")

    -- Set a cookie in response
    r:setcookie({
        key = "fuzz_resp",
        value = md5sum,
        path = "/"
    })

    -- Subprocess env and notes
    r.subprocess_env["FUZZ_METHOD"] = method
    r.notes["fuzz_note"] = uri

    -- Response status based on method
    if method == "GET" or method == "POST" or method == "HEAD" then
        r.status = 200
    elseif method == "PUT" then
        r.status = 201
    elseif method == "DELETE" then
        r.status = 204
    elseif method == "OPTIONS" then
        r.status = 200
        r:puts("OPTIONS OK\n")
    else
        r.status = 405
        r:puts("Unsupported method: " .. method .. "\n")
    end

    r:flush()
    return apache2.OK
end
