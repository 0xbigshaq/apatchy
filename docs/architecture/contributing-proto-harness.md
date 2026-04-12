# Contributing a Proto Harness

This guide walks through creating a new proto harness from scratch. By the end, you will have a working structure-aware fuzzing target for an Apache module. For background on the harness internals and filter architecture, see [Harness Design](harness-design.md). For the fuzzing engine and LPM integration, see [Fuzzing Engines](fuzzing-engines.md).

## Prerequisites

- A working `apatchy` build environment (Apache compiled with `--enable-mods-static=all`)
- LibFuzzer and libprotobuf-mutator installed (see [Building and Linking](building-linking.md))
- Familiarity with the Apache module you want to fuzz -- which hooks it registers, what input it processes, and what config directives it needs

## Overview

A proto harness has four components:

```
proto schema (.proto)  -->  converter (.cc)  -->  harness (.cc)  -->  Apache config (.conf)
       |                        |                      |
  defines the             converts proto          calls the converter
  mutation space          to raw HTTP/binary       and feeds result to
                                                   fuzz_one_input()
```

Each component lives in its own directory:

| Component | Directory | Naming convention |
|-----------|-----------|-------------------|
| Proto schema | `protos/` | `<feature>.proto` |
| Converter | `harnesses/proto_converters/` | `<feature>.cc` |
| Harness | `harnesses/` | `mod_fuzzy_proto_<feature>.cc` |
| Apache config | `configs/` | `<feature>.conf` |
| Seed corpus | `fuzz-seeds/<feature>/` | Binary protobuf or `.textproto` files |

## Step 1: Define the Proto Schema

Create a `.proto` file in `protos/` that describes the input space for your target module. This is where you define what LPM can mutate.

Most harnesses import the base `http_request.proto` and add module-specific fields on top. For example, if you were fuzzing a caching module:

```protobuf
// protos/cache_request.proto
syntax = "proto2";

import "http_request.proto";

enum CacheControl {
  NO_CACHE = 0;
  NO_STORE = 1;
  MAX_AGE = 2;
  PUBLIC = 3;
  PRIVATE = 4;
}

message CacheRequest {
  required HttpRequest http = 1;
  optional CacheControl control = 2;
  optional int32 max_age = 3;
  optional string etag = 4;
}
```

**Design tips:**

- Use `required` for fields the module always needs (like the HTTP request itself)
- Use `optional` for fields that trigger different code paths when present vs. absent
- Use `enum` to constrain values to meaningful choices (LPM will cycle through all variants)
- Use `repeated` for variable-length lists (headers, query params, etc.)
- Keep the schema focused on what the *module* cares about -- do not model the entire HTTP spec

The base `HttpRequest` message already covers method, URI, HTTP version, headers, and body. You only need to add fields for module-specific input that is not part of a normal HTTP request (encrypted cookies, binary protocol frames, multipart boundaries, etc.).

## Step 2: Write the Converter

Create a converter in `harnesses/proto_converters/` that translates your protobuf message into whatever raw input the module expects.

**If your module processes standard HTTP requests** (just with specific headers or URI patterns), you might not need a custom converter at all -- use `BuildHttpRequest()` directly and apply your module-specific transforms on the resulting string.

**If your module processes a binary protocol or needs complex encoding**, write a dedicated `Build*()` function:

```cpp
// harnesses/proto_converters/cache.cc
#include "converters.h"
#include "cache_request.pb.h"

static const char *CacheControlToString(CacheControl cc)
{
    switch (cc) {
    case NO_CACHE:  return "no-cache";
    case NO_STORE:  return "no-store";
    case MAX_AGE:   return "max-age";
    case PUBLIC:    return "public";
    case PRIVATE:   return "private";
    default:        return "no-cache";
    }
}

void ApplyCache(const CacheRequest &req, std::string &request)
{
    std::string val = CacheControlToString(req.control());
    if (req.control() == MAX_AGE && req.has_max_age())
        val += "=" + std::to_string(req.max_age());

    // Inject Cache-Control header before the blank line
    size_t pos = request.find("\r\n\r\n");
    if (pos != std::string::npos) {
        std::string hdr = "Cache-Control: " + val + "\r\n";
        if (req.has_etag())
            hdr += "If-None-Match: " + req.etag() + "\r\n";
        request.insert(pos + 2, hdr);
    }
}
```

Then declare the function in `converters.h`:

```cpp
class CacheRequest;
void ApplyCache(const CacheRequest &req, std::string &request);
```

**Converter patterns:**

There are two common patterns depending on what your module needs:

1. **Apply-style** (`void Apply*(const Proto &, std::string &request)`) -- modifies an existing HTTP request string by injecting headers, rewriting the URI, or appending encoded data. Used when the module processes standard HTTP with extra data (session cookies, rewrite rules, multipart bodies).

2. **Build-style** (`std::string Build*(const Proto &)`) -- constructs a complete raw input from scratch. Used when the module speaks a non-HTTP protocol (AJP binary frames, HTTP/2, uWSGI).

## Step 3: Write the Harness

Create the harness `.cc` file in `harnesses/`. This is the entry point that ties everything together.

```cpp
/*
 * @description: proto harness - mod_cache fuzzing via libprotobuf-mutator
 * @protos: http_request, cache_request
 * @converters: http, cache
 *
 * Structure-aware libFuzzer harness for mod_cache.
 * LPM mutates both the HTTP request and cache control fields independently.
 *
 * Build: apatchy link libfuzzer --harness mod_fuzzy_proto_cache
 * Run:   apatchy fuzz --engine libfuzzer --config configs/cache.conf
 */

#include "proto_converters/converters.h"
#include "proto_harness_common.h"
#include "cache_request.pb.h"
#include "src/libfuzzer/libfuzzer_macro.h"

DEFINE_PROTO_FUZZER(const CacheRequest &request)
{
    if (!proto_harness_init())
        return;

    std::string raw = BuildHttpRequest(request.http());
    ApplyCache(request, raw);
    fuzz_one_input(raw.data(), raw.size());
}
```

### Metadata tags

The comment header contains metadata tags that the build system parses to determine what to compile and link. These are required:

| Tag | Required | Description |
|-----|----------|-------------|
| `@description:` | Yes | One-line description, shown by `apatchy harness list` |
| `@protos:` | Yes | Comma-separated list of `.proto` file names (without extension) |
| `@converters:` | Yes | Comma-separated list of converter files from `proto_converters/` (without extension) |
| `@extras:` | No | Additional C source files to compile and link (without `.c` extension) |
| `@ldflags:` | No | Extra linker flags (e.g. `-Wl,--wrap=some_function`) |

### Required includes

Every proto harness needs these four includes:

```cpp
#include "proto_converters/converters.h"   // converter function declarations
#include "proto_harness_common.h"          // proto_harness_init()
#include "<your_proto>.pb.h"               // generated protobuf header
#include "src/libfuzzer/libfuzzer_macro.h" // DEFINE_PROTO_FUZZER macro
```

### Entry point structure

The `DEFINE_PROTO_FUZZER` body always follows the same pattern:

1. Call `proto_harness_init()` -- initializes Apache once per process (config parsing, module hooks, memory pools). Returns `false` on failure.
2. Convert the protobuf to raw input using your converter.
3. Call `fuzz_one_input(data, size)` to run the input through Apache's full request pipeline.

### Fuzzing proxy modules

If your target is a proxy module (mod_proxy_uwsgi, mod_proxy_ajp, etc.), you need to mock the backend server response. Add `fuzz_backend` to `@extras:` and set up the backend buffer before calling `fuzz_one_input()`:

```cpp
/*
 * @extras: fuzz_backend
 * @ldflags: -Wl,--wrap=ap_proxy_connect_backend
 */

extern "C" {
#include "fuzz_backend.h"
}

DEFINE_PROTO_FUZZER(const MyProxyRequest &req)
{
    if (!proto_harness_init())
        return;

    g_backend_enabled = 1;

    std::string response = BuildMyResponse(req.resp());
    g_backend_buf = response.data();
    g_backend_size = response.size();

    std::string raw = BuildHttpRequest(req.http());
    fuzz_one_input(raw.data(), raw.size());
}
```

The `--wrap=ap_proxy_connect_backend` linker flag redirects Apache's backend connection function to the mock in `fuzz_backend.c`, which serves `g_backend_buf` through a socketpair instead of connecting to a real upstream.

## Step 4: Write the Apache Config

Create a config in `configs/` that enables and configures the module you want to fuzz. The config should exercise as many code paths as possible.

Start with this base and add module-specific directives:

```apache
# configs/cache.conf
ServerName localhost:80
HttpProtocolOptions Unsafe
DocumentRoot "/tmp/htdocs"
ErrorLog "/dev/stdout"
LogLevel emerg
TypesConfig conf/mime.types

<Directory "/">
    Require all granted
</Directory>

LimitRequestFieldSize 100000
LimitRequestLine 100000
```

Key directives to keep:

- **`HttpProtocolOptions Unsafe`** -- relaxes strict HTTP parsing so fuzz inputs reach module code instead of being rejected by the protocol parser
- **`Require all granted`** -- disables auth checks so requests reach your module
- **`LogLevel emerg`** -- minimizes logging overhead during fuzzing
- **`LimitRequestFieldSize`/`LimitRequestLine`** -- allows large fuzz inputs through

Then add your module's config. Use multiple `<Location>` blocks to hit different code paths:

```apache
CacheEnable disk /a
CacheRoot "/tmp/cache"
CacheDefaultExpire 300

<Location "/b">
    CacheDisable on
</Location>
```

## Step 5: Add Seed Corpus

Create a directory in `fuzz-seeds/` for your harness seeds:

```
fuzz-seeds/<feature>/
```

LPM accepts seeds in text protobuf format (`.textproto`), which is human-readable:

```protobuf
# fuzz-seeds/cache/basic.textproto
http {
  method: GET
  uri: "/a/index.html"
  headers { name: "Host" value: "localhost" }
}
control: MAX_AGE
max_age: 300
etag: "abc123"
```

You only need a few valid seeds -- LPM handles mutation from there. Focus seeds on:

- A minimal valid request that reaches your module
- One seed per major code path or `<Location>` block in your config
- Edge cases specific to your module (empty values, boundary conditions)

## Step 6: Build and Run

Build the harness:

```bash
apatchy link libfuzzer --harness mod_fuzzy_proto_<feature>
```

Run the fuzzer:

```bash
FUZZ_CONF=configs/<feature>.conf apatchy fuzz --engine libfuzzer --corpus fuzz-seeds/<feature>/
```

Verify it starts without crashing and is finding new coverage. If Apache fails to initialize, check the config -- missing modules or bad directives are the most common cause.

## Checklist

Before submitting:

- [ ] Proto schema in `protos/` -- imports `http_request.proto` if applicable
- [ ] Converter in `harnesses/proto_converters/` -- declared in `converters.h`
- [ ] Harness `.cc` in `harnesses/` -- correct `@protos`, `@converters`, `@extras`, `@ldflags` tags
- [ ] Apache config in `configs/` -- module enabled, multiple routes for coverage
- [ ] Seed corpus in `fuzz-seeds/` -- at least one valid seed per route
- [ ] Builds with `apatchy link libfuzzer --harness <name>`
- [ ] Runs without initialization errors
- [ ] Reaches target module code (check with a coverage build)

## Reference: Existing Harnesses

| Harness | Module | Key technique |
|---------|--------|---------------|
| `mod_fuzzy_proto` | Core HTTP | Base case -- just `BuildHttpRequest()` |
| `mod_fuzzy_proto_session` | mod_session_crypto | `ApplySessionCrypto()` injects encrypted cookies |
| `mod_fuzzy_proto_multipart` | mod_mime | `ApplyMultipart()` builds multipart/form-data bodies |
| `mod_fuzzy_proto_rewrite` | mod_rewrite | `ApplyRewrite()` replaces URI with rewrite-targeted patterns |
| `mod_fuzzy_proto_uwsgi` | mod_proxy_uwsgi | Backend mocking via `fuzz_backend` + `--wrap` |
| `mod_fuzzy_proto_ajp` | mod_proxy_ajp | Binary AJP protocol + backend mocking |

Read these for patterns to follow when building your own harness.
