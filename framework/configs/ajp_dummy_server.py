import socket
import struct

METHODS = {2: "GET", 3: "HEAD", 4: "POST", 5: "PUT", 6: "DELETE", 8: "OPTIONS"}


def parse_ajp_request(data):
    """Extract method and URI from AJP FORWARD_REQUEST payload."""
    if len(data) < 4:
        return "???", "???"
    method = METHODS.get(data[1], f"M{data[1]}")
    # skip prefix_code(1) + method(1), read protocol string, then URI
    off = 2
    # protocol string (length-prefixed)
    if off + 2 > len(data):
        return method, "???"
    plen = (data[off] << 8) | data[off + 1]
    off += 2 + plen + 1  # skip length + string + null
    # URI string
    if off + 2 > len(data):
        return method, "???"
    ulen = (data[off] << 8) | data[off + 1]
    off += 2
    if off + ulen > len(data):
        return method, "???"
    uri = data[off : off + ulen].decode("utf-8", errors="replace")
    return method, uri


count = 0

s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", 8009))
s.listen(128)
print("[+] ajp dummy server listening on 127.0.0.1:8009")
while True:
    c, _ = s.accept()
    try:
        hdr = c.recv(4)
        if len(hdr) == 4:
            size = struct.unpack(">H", hdr[2:4])[0]
            data = b""
            remaining = size
            while remaining > 0:
                chunk = c.recv(min(remaining, 8192))
                if not chunk:
                    break
                data += chunk
                remaining -= len(chunk)
            count += 1
            method, uri = parse_ajp_request(data)
            is_post = len(data) > 1 and data[1] == 0x04
            print(f"[{count}] {method} {uri}", flush=True)
            pass
    except Exception as e:
        print(f"[!] error: {e}", flush=True)
    c.close()
