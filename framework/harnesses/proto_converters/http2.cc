
#include "http2_request.pb.h"
#include "proto_converters/converters.h"
#include <cstring>

static const char H2_PREFACE[] = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
static const size_t H2_PREFACE_LEN = sizeof(H2_PREFACE) - 1;

static void WriteU8(std::string &out, uint8_t v)
{
    out += (char)v;
}

static void WriteU16(std::string &out, uint16_t v)
{
    out += (char)((v >> 8) & 0xff);
    out += (char)(v & 0xff);
}

static void WriteU32(std::string &out, uint32_t v)
{
    out += (char)((v >> 24) & 0xff);
    out += (char)((v >> 16) & 0xff);
    out += (char)((v >> 8) & 0xff);
    out += (char)(v & 0xff);
}

static void
WriteFrameHeader(std::string &out, uint32_t length, uint8_t type, uint8_t flags, uint32_t stream_id)
{
    out += (char)((length >> 16) & 0xff);
    out += (char)((length >> 8) & 0xff);
    out += (char)(length & 0xff);
    out += (char)type;
    out += (char)flags;
    out += (char)((stream_id >> 24) & 0x7f);
    out += (char)((stream_id >> 16) & 0xff);
    out += (char)((stream_id >> 8) & 0xff);
    out += (char)(stream_id & 0xff);
}

static void
WriteHpackHeaders(std::string &out, const google::protobuf::RepeatedPtrField<Header> &headers)
{
    for (int i = 0; i < headers.size(); i++) {
        const Header &hdr = headers.Get(i);
        if (hdr.name().empty())
            continue;
        WriteU8(out, 0x00);
        WriteU8(out, (uint8_t)(hdr.name().size() & 0x7f));
        out.append(hdr.name());
        WriteU8(out, (uint8_t)(hdr.value().size() & 0x7f));
        out.append(hdr.value());
    }
}

static std::string BuildSettingsPayload(const H2SettingsFrame &sf)
{
    std::string payload;
    for (int i = 0; i < sf.settings_size(); i++) {
        const H2Setting &s = sf.settings(i);
        uint16_t id = 0;
        switch (s.id()) {
        case HEADER_TABLE_SIZE:
            id = 0x1;
            break;
        case ENABLE_PUSH:
            id = 0x2;
            break;
        case MAX_CONCURRENT_STREAMS:
            id = 0x3;
            break;
        case INITIAL_WINDOW_SIZE:
            id = 0x4;
            break;
        case MAX_FRAME_SIZE:
            id = 0x5;
            break;
        case MAX_HEADER_LIST_SIZE:
            id = 0x6;
            break;
        }
        WriteU16(payload, id);
        WriteU32(payload, s.value());
    }
    return payload;
}

static void WriteFrame(std::string &out, const H2Frame &f)
{
    uint32_t stream_id = f.has_stream_id() ? f.stream_id() : 0;

    if (f.has_settings()) {
        const H2SettingsFrame &sf = f.settings();
        uint8_t flags = sf.ack() ? 0x01 : 0x00;
        if (sf.ack()) {
            WriteFrameHeader(out, 0, 0x04, flags, 0);
        } else {
            std::string payload = BuildSettingsPayload(sf);
            WriteFrameHeader(out, payload.size(), 0x04, flags, 0);
            out.append(payload);
        }
    } else if (f.has_data()) {
        const H2DataFrame &df = f.data();
        uint8_t flags = df.end_stream() ? 0x01 : 0x00;
        WriteFrameHeader(out, df.data().size(), 0x00, flags, stream_id);
        out.append(df.data());
    } else if (f.has_headers()) {
        const H2HeadersFrame &hf = f.headers();
        std::string payload;
        uint8_t flags = 0x04; // END_HEADERS
        if (hf.end_stream())
            flags |= 0x01;
        if (hf.has_priority_dep()) {
            flags |= 0x20;
            uint32_t dep = hf.priority_dep();
            WriteU32(payload, dep);
            uint8_t weight = hf.has_priority_weight() ? (hf.priority_weight() & 0xff) : 16;
            WriteU8(payload, weight);
        }
        WriteHpackHeaders(payload, hf.headers());
        WriteFrameHeader(out, payload.size(), 0x01, flags, stream_id);
        out.append(payload);
    } else if (f.has_window_update()) {
        const H2WindowUpdateFrame &wf = f.window_update();
        std::string payload;
        WriteU32(payload, wf.increment() & 0x7fffffff);
        WriteFrameHeader(out, payload.size(), 0x08, 0x00, stream_id);
        out.append(payload);
    } else if (f.has_rst_stream()) {
        const H2RstStreamFrame &rf = f.rst_stream();
        std::string payload;
        WriteU32(payload, rf.error_code());
        WriteFrameHeader(out, payload.size(), 0x03, 0x00, stream_id);
        out.append(payload);
    } else if (f.has_goaway()) {
        const H2GoawayFrame &gf = f.goaway();
        std::string payload;
        WriteU32(payload, gf.last_stream_id());
        WriteU32(payload, gf.error_code());
        if (gf.has_debug_data())
            payload.append(gf.debug_data());
        WriteFrameHeader(out, payload.size(), 0x07, 0x00, 0);
        out.append(payload);
    } else if (f.has_ping()) {
        const H2PingFrame &pf = f.ping();
        uint8_t flags = pf.ack() ? 0x01 : 0x00;
        char payload[8] = {0};
        if (pf.has_data()) {
            size_t len = pf.data().size() < 8 ? pf.data().size() : 8;
            memcpy(payload, pf.data().data(), len);
        }
        WriteFrameHeader(out, 8, 0x06, flags, 0);
        out.append(payload, 8);
    } else if (f.has_priority()) {
        const H2PriorityFrame &pf = f.priority();
        std::string payload;
        uint32_t dep = pf.dep_stream_id();
        if (pf.exclusive())
            dep |= 0x80000000;
        WriteU32(payload, dep);
        uint8_t weight = pf.has_weight() ? (pf.weight() & 0xff) : 16;
        WriteU8(payload, weight);
        WriteFrameHeader(out, payload.size(), 0x02, 0x00, stream_id);
        out.append(payload);
    } else if (f.has_continuation()) {
        const H2ContinuationFrame &cf = f.continuation();
        std::string payload;
        uint8_t flags = cf.end_headers() ? 0x04 : 0x00;
        WriteHpackHeaders(payload, cf.headers());
        WriteFrameHeader(out, payload.size(), 0x09, flags, stream_id);
        out.append(payload);
    }
}

std::string BuildHttp2Request(const Http2Request &req)
{
    std::string out;

    if (req.has_raw_preface()) {
        out.append(req.raw_preface());
    } else {
        out.append(H2_PREFACE, H2_PREFACE_LEN);
    }

    for (int i = 0; i < req.frames_size(); i++) {
        WriteFrame(out, req.frames(i));
    }

    return out;
}
