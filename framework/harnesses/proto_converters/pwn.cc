#include "proto_converters/converters.h"
#include "pwn_request.pb.h"
#include <cstring>
#include <string>

static const char *format_strings[] = {"%s",     "%x",       "%n",      "%p",   "%d",
                                       "%s%s%s", "%x%x%x%x", "%n%n%n",  "%1$s", "%10$x",
                                       "%100$n", "%.1000s",  "%.10000x"};

static const char *int_values[] = {"0",          "1",           "-1",          "127",
                                   "128",        "255",         "256",         "32767",
                                   "32768",      "65535",       "65536",       "2147483647",
                                   "2147483648", "-2147483648", "-2147483649", "4294967295",
                                   "4294967296"};

static const int overflow_sizes[] = {16, 32, 64, 128, 256, 512, 1024, 2048, 4096};

static const char *pwn_header_names[] = {"X-Pwn-Overflow", "X-Pwn-Heap", "X-Pwn-Format",
                                         "X-Pwn-Integer",  "X-Pwn-UAF",  "X-Pwn-Null",
                                         "X-Pwn-Double"};

void ApplyPwn(const PwnRequest &pwn, std::string &request)
{
    std::string header;

    switch (pwn.strategy()) {
    case PWN_OVERFLOW: {
        int idx = pwn.overflow_size_idx() % 9;
        int size = overflow_sizes[idx];
        char ch = 'A' + (pwn.overflow_char() % 26);
        header = "X-Pwn-Overflow: ";
        header.append(size, ch);
        break;
    }
    case PWN_FORMAT: {
        int idx = pwn.format_payload() % 13;
        header = "X-Pwn-Format: ";
        header += format_strings[idx];
        break;
    }
    case PWN_INTEGER: {
        int idx = pwn.int_payload() % 17;
        header = "X-Pwn-Integer: ";
        header += int_values[idx];
        break;
    }
    default: {
        int idx = pwn.strategy() % 7;
        header = pwn_header_names[idx];
        header += ": 1";
        break;
    }
    }

    header += "\r\n";

    size_t hend = request.find("\r\n\r\n");
    if (hend == std::string::npos)
        return;
    request.insert(hend + 2, header);
}