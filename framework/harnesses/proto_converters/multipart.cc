#include "multipart_request.pb.h"
#include "proto_converters/converters.h"
#include <cstring>
#include <string>

static const char *boundary_strings[] = {"a",    "ab",   "x", "--",  "boundary", "fuzzboundary",
                                         "AAAA", "----", "0", "\r\n"};

static const char *disposition_strings[] = {
    "form-data",
    "attachment",
    "inline",
    "",
    "form-data; name=\"test\"; filename=\"x.txt\"",
    "form-data; name=\"a\"",
};

void ApplyMultipart(const MultipartRequest &mp, std::string &request)
{
    int bidx = mp.boundary() % 10;
    const char *boundary = boundary_strings[bidx];

    std::string body;

    if (mp.parts_size() == 0) {
        body += "--";
        body += boundary;
        body += "\r\n\r\n\r\n--";
        body += boundary;
        body += "--\r\n";
    } else {
        for (int i = 0; i < mp.parts_size(); i++) {
            const MultipartPart &part = mp.parts(i);
            body += "--";
            for (uint32_t d = 0; d < part.extra_dashes(); d++)
                body += '-';
            body += boundary;
            body += "\r\n";

            int didx = part.disposition() % 6;
            const char *disp = disposition_strings[didx];
            if (disp[0] != '\0') {
                body += "Content-Disposition: ";
                body += disp;
                if (part.has_field_name() && !part.field_name().empty()) {
                    body += "; name=\"";
                    body += part.field_name();
                    body += "\"";
                }
                body += "\r\n";
            }

            if (mp.tight_spacing()) {
                body += "\r\n";
            } else {
                body += "\r\n";
            }

            if (part.has_body())
                body.append(reinterpret_cast<const char *>(part.body().data()), part.body().size());

            if (part.inject_fake_boundary()) {
                body += "\r\n--";
                body += boundary;
                body += "\r\n";
            }

            body += "\r\n";
        }
        body += "--";
        body += boundary;
        body += "--\r\n";
    }

    std::string ct_header = "Content-Type: multipart/form-data; boundary=";
    ct_header += boundary;
    ct_header += "\r\n";

    std::string cl_header = "Content-Length: ";
    cl_header += std::to_string(body.size());
    cl_header += "\r\n";

    size_t hend = request.find("\r\n\r\n");
    if (hend == std::string::npos)
        return;

    request.insert(hend + 2, ct_header + cl_header);

    hend = request.find("\r\n\r\n");
    if (hend == std::string::npos)
        return;
    request.replace(hend + 4, std::string::npos, body);
}