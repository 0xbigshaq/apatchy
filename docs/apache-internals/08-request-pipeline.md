# Chapter 8: Request Processing Pipeline

## The Big Picture

When an HTTP request arrives, Apache processes it through a carefully orchestrated pipeline of hooks and filters. Each phase has a specific responsibility -- URI translation, access control, authentication, content generation -- and modules register callbacks at precisely the phases where they need to act.


```{note}
Understanding this pipeline is essential for both module development and fuzzing. For fuzzing, it tells you which code paths your input will exercise: a malformed request line will be caught in phase 3 (request parsing), while a crafted session cookie will flow all the way to the handler phase and into `mod_session_crypto`'s decryption logic.
```


```
┌─────────────────────────────────────────────────────────────────────┐
│                        REQUEST LIFECYCLE                            │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  1. Connection Accepted (MPM)                                       │
│          │                                                          │
│          ▼                                                          │
│  2. Connection Setup (pre_connection hooks)                         │
│          │                                                          │
│          ▼                                                          │
│  3. Read Request Line & Headers                                     │
│          │                                                          │
│          ▼                                                          │
│  4. Request Processing Phases (hooks)                               │
│     ┌─────────────────────────────────────────┐                     │
│     │  post_read_request                      │                     │
│     │  translate_name                         │                     │
│     │  map_to_storage                         │                     │
│     │  header_parser                          │                     │
│     │  access_checker                         │                     │
│     │  check_user_id (authn)                  │                     │
│     │  auth_checker (authz)                   │                     │
│     │  type_checker                           │                     │
│     │  fixups                                 │                     │
│     │  handler                                │                     │
│     └─────────────────────────────────────────┘                     │
│          │                                                          │
│          ▼                                                          │
│  5. Send Response (output filters)                                  │
│          │                                                          │
│          ▼                                                          │
│  6. Log Transaction                                                 │
│          │                                                          │
│          ▼                                                          │
│  7. Cleanup (pool destruction)                                      │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

``````{dropdown} Phase 1: Connection Accepted

The MPM accepts a TCP connection and creates basic structures:

```c
// Inside MPM (simplified)
apr_socket_accept(&client_socket, listen_socket, pool);

// Create connection record
conn_rec *c = ap_run_create_connection(
    pool,           // Connection pool
    server,         // Server record
    client_socket,  // Client socket
    conn_id,        // Unique connection ID
    sbh,            // Scoreboard handle
    bucket_alloc    // Bucket allocator
);
```

The {httpd}`conn_rec` structure is created:

```c
struct conn_rec {
    apr_pool_t *pool;              // Connection pool
    server_rec *base_server;       // Server handling this
    void *conn_config;             // Per-conn module configs

    apr_socket_t *client_socket;   // The actual socket
    const char *client_ip;         // Client IP address
    const char *local_ip;          // Local IP
    apr_port_t client_port;        // Client port

    ap_filter_t *input_filters;    // Input filter chain
    ap_filter_t *output_filters;   // Output filter chain

    long id;                       // Unique connection ID
    int keepalive;                 // Keep-alive status
    signed int double_reverse:2;   // DNS status

    int aborted;                   // Connection aborted?
};
```

``````

``````{dropdown} Phase 2: Connection Setup

Pre-connection hooks run to set up the connection:

```c
// In server/connection.c
int rc = ap_run_pre_connection(c, c->client_socket);
```

This is where:
- SSL/TLS is negotiated (mod_ssl)
- Input/output filters are added
- Connection-level state is initialized

```c
// Example: mod_ssl adds its filters here
static int ssl_hook_pre_connection(conn_rec *c, void *csd)
{
    // Add SSL filters
    ap_add_input_filter("SSL/TLS Input Filter", NULL, NULL, c);
    ap_add_output_filter("SSL/TLS Output Filter", NULL, NULL, c);
    return OK;
}
```

``````

``````{dropdown} Phase 3: Read Request

Apache reads the HTTP request line and headers:

```c
// In server/protocol.c
request_rec *r = ap_read_request(c);
```

This function:
1. Creates a new {httpd}`request_rec` with its own pool
2. Reads the request line: `GET /path HTTP/1.1`
3. Parses method, URI, protocol
4. Reads all headers into `r->headers_in`

```c
// The request_rec structure (key fields)
struct request_rec {
    apr_pool_t *pool;              // Request pool (freed after response)
    conn_rec *connection;          // Parent connection
    server_rec *server;            // Handling server

    // The request
    const char *the_request;       // "GET /path HTTP/1.1"
    char *method;                  // "GET"
    int method_number;             // M_GET
    const char *protocol;          // "HTTP/1.1"
    int proto_num;                 // 1001 (1.1)

    // URI components
    char *uri;                     // "/path"
    char *filename;                // Translated filesystem path
    char *path_info;               // Extra path after script
    char *args;                    // Query string

    // Headers
    apr_table_t *headers_in;       // Request headers
    apr_table_t *headers_out;      // Response headers
    apr_table_t *err_headers_out;  // Error response headers
    apr_table_t *subprocess_env;   // CGI-style environment

    // Response
    int status;                    // HTTP status code
    const char *content_type;      // Response Content-Type
    const char *handler;           // Handler name

    // Authentication
    char *user;                    // Authenticated username
    char *ap_auth_type;            // Auth type used

    // Filters
    ap_filter_t *input_filters;    // Request input filters
    ap_filter_t *output_filters;   // Response output filters

    // Configuration
    void *per_dir_config;          // Merged per-dir configs
    void *request_config;          // Per-request module data
};
```

``````

``````{dropdown} Phase 4: Request Processing

The heart of Apache -- a series of hooks process the request in a fixed order. The orchestrating function is `ap_process_request_internal()` in `server/request.c`. It calls each hook in sequence, and any hook returning an error code short-circuits the entire pipeline:

```c
// server/request.c: ap_process_request_internal()

// 1. Post-read-request - First look at request
if ((access_status = ap_run_post_read_request(r))) {
    return access_status;
}

// 2. Translate URI to filename/handler
if ((access_status = ap_run_translate_name(r))) {
    return access_status;
}

// 3. Map to storage (hook into <Directory> etc.)
if ((access_status = ap_run_map_to_storage(r))) {
    return access_status;
}

// 4. Walk <Directory> sections, merge configs
if ((access_status = ap_directory_walk(r))) {
    return access_status;
}
if ((access_status = ap_file_walk(r))) {
    return access_status;
}

// 5. Header parsing (post-walk)
if ((access_status = ap_run_header_parser(r))) {
    return access_status;
}

// === SECURITY HOOKS START HERE ===

// 6. Access check (IP-based)
switch (ap_run_access_checker(r)) {
    case OK:      break;
    case DECLINED: break;
    default:      return access_status;
}

// 7. Authentication (who are you?)
switch (ap_run_check_user_id(r)) {
    case OK:      break;
    case DECLINED: break;
    default:      return access_status;
}

// 8. Authorization (are you allowed?)
switch (ap_run_auth_checker(r)) {
    case OK:      break;
    case DECLINED: break;
    default:      return access_status;
}

// === SECURITY HOOKS END ===

// 9. MIME type checking
if ((access_status = ap_run_type_checker(r))) {
    return access_status;
}

// 10. Fixups (last chance modifications)
if ((access_status = ap_run_fixups(r))) {
    return access_status;
}
```

### Detailed Phase Breakdown

#### Post-Read-Request

First hook after headers are parsed. Used for:
- Early request inspection
- Setting up request state
- Rejecting obviously bad requests

```c
static int my_post_read(request_rec *r)
{
    // Log the raw request
    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                  "Request: %s", r->the_request);

    // Check for suspicious patterns
    if (strstr(r->uri, "..")) {
        return HTTP_BAD_REQUEST;
    }

    return DECLINED;  // Continue processing
}
```

#### Translate Name

Map URI to filename or handler:

```c
static int my_translate(request_rec *r)
{
    // Handle /api/* requests
    if (strncmp(r->uri, "/api/", 5) == 0) {
        r->handler = "api-handler";
        r->filename = apr_pstrdup(r->pool, "/dev/null");
        return OK;  // We handled it
    }

    // Let other translators try
    return DECLINED;
}
```

Standard translators:
- **mod_alias**: `Alias`, `Redirect`, `ScriptAlias`
- **mod_rewrite**: `RewriteRule`
- **mod_proxy**: Forward to backend
- **core**: Map to DocumentRoot

#### Map to Storage

Connect request to filesystem or virtual storage:

```c
static int my_map_to_storage(request_rec *r)
{
    // Handle virtual paths
    if (strncmp(r->uri, "/virtual/", 9) == 0) {
        // Don't look for file on disk
        return OK;
    }
    return DECLINED;
}
```

#### Directory Walk

Between `map_to_storage` and the security hooks, Apache performs a **directory walk** (`ap_directory_walk()` in `server/request.c`). This is where the per-directory configuration merge happens -- Apache walks each component of the translated filesystem path, matching `<Directory>` and `<Location>` sections and merging their configurations into `r->per_dir_config`. See [Chapter 4: Configuration](04-configuration.md) for how the merge works.

The walk also processes `.htaccess` files if `AllowOverride` permits it:
1. Check if path exists on disk
2. Match `<Directory>`, `<Location>`, `<Files>` sections
3. Merge per-directory configs (base → vhost → directory → .htaccess)
4. Set `r->per_dir_config` with the final merged result

```c
// This happens automatically in core (server/request.c)
// The result is r->per_dir_config being set
// with merged configuration for this specific path
```

#### Access Checker

IP/host-based access control (runs before authentication):

```c
static int my_access_checker(request_rec *r)
{
    // Block known bad IPs
    if (strcmp(r->useragent_ip, "1.2.3.4") == 0) {
        ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r,
                      "Blocked IP: %s", r->useragent_ip);
        return HTTP_FORBIDDEN;
    }
    return DECLINED;
}
```

Modern approach uses `mod_authz_host`:
```apache
<Location /admin>
    Require ip 192.168.1.0/24
</Location>
```

#### Check User ID (Authentication)

Determine who the user is:

```c
static int my_authn(request_rec *r)
{
    const char *auth = apr_table_get(r->headers_in, "Authorization");
    if (!auth) {
        // No auth provided - let other modules try
        return DECLINED;
    }

    if (strncmp(auth, "Bearer ", 7) == 0) {
        const char *token = auth + 7;
        const char *user = validate_token(token);
        if (user) {
            r->user = apr_pstrdup(r->pool, user);
            r->ap_auth_type = "Bearer";
            return OK;
        }
        return HTTP_UNAUTHORIZED;
    }

    return DECLINED;
}
```

#### Auth Checker (Authorization)

Check if authenticated user is allowed:

```c
static int my_authz(request_rec *r)
{
    if (!r->user) {
        // No user - can't authorize
        return DECLINED;
    }

    // Check if user has required role
    if (user_has_role(r->user, "admin")) {
        return OK;
    }

    return HTTP_FORBIDDEN;
}
```

Modern approach uses `mod_authz_core`:
```apache
<Location /admin>
    Require role admin
</Location>
```

#### Type Checker

Determine content type and set handler:

```c
static int my_type_checker(request_rec *r)
{
    if (r->filename && ends_with(r->filename, ".custom")) {
        r->content_type = "application/x-custom";
        r->handler = "custom-handler";
        return OK;
    }
    return DECLINED;
}
```

#### Fixups

Last chance to modify request before handler runs:

```c
static int my_fixup(request_rec *r)
{
    // Add custom header
    apr_table_set(r->headers_out, "X-Request-ID",
                  generate_request_id(r));

    // Modify environment
    apr_table_set(r->subprocess_env, "MY_VAR", "value");

    return DECLINED;  // Let others run too
}
```

``````

``````{dropdown} Phase 5: Invoke Handler

The handler generates the response content:

```c
// In server/config.c: ap_invoke_handler()
int result = ap_run_handler(r);

if (result == DECLINED && r->handler) {
    ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r,
                  "No handler found for '%s'", r->handler);
    result = HTTP_INTERNAL_SERVER_ERROR;
}
```

Handler types:
1. **Content handlers**: mod_cgi, mod_php, custom modules
2. **Proxy handlers**: Forward to backend
3. **Static file handlers**: Core's default_handler

```c
static int my_handler(request_rec *r)
{
    // Only handle requests for us
    if (!r->handler || strcmp(r->handler, "my-handler") != 0) {
        return DECLINED;
    }

    // Set response headers
    ap_set_content_type(r, "text/html");
    apr_table_set(r->headers_out, "X-Powered-By", "MyModule");

    // Generate content
    ap_rputs("<html><body>", r);
    ap_rprintf(r, "<h1>Hello, %s!</h1>", r->user ? r->user : "Guest");
    ap_rputs("</body></html>", r);

    return OK;
}
```

``````

``````{dropdown} Phase 6: Send Response

Response flows through output filter chain:

```c
// Handler output goes through filters:
// Handler → Content Filters → Protocol Filters → SSL → Network

// The core HTTP filter adds:
// - Status line
// - Headers
// - Chunked encoding (if needed)
```

Key output filters:
- **CORE_OUTPUT**: Actually writes to socket
- **HTTP_HEADER**: Adds HTTP response headers
- **CONTENT_LENGTH**: Sets Content-Length if possible
- **CHUNK**: Applies chunked transfer encoding
- **DEFLATE**: Compresses content (mod_deflate)
- **SSL_OUT**: Encrypts for TLS (mod_ssl)

``````

``````{dropdown} Phase 7: Log Transaction

After response is sent:

```c
// In server/request.c: ap_process_request()
ap_run_log_transaction(r);
```

Logging hooks record:
- Request URI and method
- Response status
- Bytes sent
- Time taken
- Client info

```c
static int my_logger(request_rec *r)
{
    apr_time_t elapsed = apr_time_now() - r->request_time;

    ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r,
                  "%s %s -> %d (%lu bytes, %lu us)",
                  r->method, r->uri, r->status,
                  r->bytes_sent, (unsigned long)elapsed);

    return OK;
}
```

``````

``````{dropdown} Phase 8: Cleanup

After logging, the request pool is destroyed:

```c
// In server/request.c
apr_pool_destroy(r->pool);
// All request allocations freed
// All cleanup callbacks run
```

For keep-alive connections, the loop repeats from Phase 3.

``````

## Internal Redirects

Apache can redirect internally without a new HTTP round-trip. This creates a new {httpd}`request_rec` that re-runs the pipeline from phase 4, but reuses the same connection and avoids sending a 3xx response to the client. `ErrorDocument` directives use this mechanism -- a 404 error on `/missing-page` internally redirects to `/error/404.html`:

```c
// In a handler or hook:
ap_internal_redirect("/new/path", r);

// Or with modified request:
request_rec *new_r = ap_sub_req_lookup_uri("/new/path", r, NULL);
ap_run_sub_req(new_r);
ap_destroy_sub_req(new_r);
```

Internal redirects create a new {httpd}`request_rec` but reuse the connection.

## Subrequests

Subrequests are "virtual" requests that run the pipeline for a different URI within the context of the current request. Unlike internal redirects (which replace the current request), subrequests run alongside it. The subrequest gets its own {httpd}`request_rec` with a pool that's a child of the parent request's pool:

```c
// Lookup what would handle a URI
request_rec *sub = ap_sub_req_lookup_uri("/includes/header.html",
                                          r, r->output_filters);
if (sub->status == HTTP_OK) {
    // Run the subrequest
    ap_run_sub_req(sub);
}
ap_destroy_sub_req(sub);
```

Used by:
- `mod_include` (SSI)
- `mod_negotiation`
- `mod_dir`

## Error Handling

When an error occurs:

```c
// Return HTTP error from any hook/handler
return HTTP_FORBIDDEN;  // 403

// Or set r->status and return OK
r->status = HTTP_NOT_FOUND;
ap_send_error_response(r, 0);
return OK;
```

Apache then:
1. Sets error status
2. Looks for `ErrorDocument`
3. Generates error response
4. Runs log hooks

## Summary

The request pipeline is Apache's orchestration of:

1. **Connection setup** - MPM accepts, hooks initialize
2. **Request parsing** - HTTP line and headers
3. **URI processing** - Translate and map to handler
4. **Security checks** - Access, authentication, authorization
5. **Content generation** - Handler produces response
6. **Response delivery** - Filters transform and send
7. **Logging** - Record the transaction
8. **Cleanup** - Free resources

Key insights for fuzzing:
- **Entry point**: The harness calls {httpd}`ap_process_connection` directly, bypassing the MPM's accept loop. This enters the pipeline at phase 2 (connection setup)
- **Input source**: The core input filter is replaced with one that reads from the fuzzer's memory buffer instead of a socket
- **Output sink**: The core output filter is replaced with one that discards data (or writes to `/dev/null`)
- **All phases are hook-driven**: Every module callback registered via `ap_hook_*()` runs exactly as it would in production
- **Pool-scoped allocations**: After each request, {httpd}`apr_pool_destroy` frees everything, which is when ASan (with `--enable-pool-debug=yes`) checks for memory errors
- **Internal redirects and subrequests** can be triggered by fuzzer input (e.g., a request to a path with an `ErrorDocument` directive), exercising additional code paths beyond the initial request
