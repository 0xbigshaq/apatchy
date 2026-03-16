"""CVE-2020-11984 - Integer truncation in mod_proxy_uwsgi packet size.

The uwsgi binary protocol uses a 16-bit packet size field (apr_uint16_t).
When HTTP headers exceed 64KB, uwsgi_send_headers truncates the size:

* Line 192: ``vallen = strlen(env[j].val)`` truncates header value
  lengths from size_t to uint16, zeroing values >= 64KB.
* Line 199: ``pktsize = headerlen - 4`` truncates the total packet
  size, so the uwsgi header declares a smaller packet than what is
  actually sent.

The buffer is allocated and sent with the correct (large) size, so
there is no memory corruption on the Apache side.  The overflow
happens on the uwsgi backend which trusts the 16-bit size field and
reads past it into uninitialized memory.

Trigger: send a request with a header value longer than 64KB through
a uwsgi proxy.  Detected by --truncsan (implicit-unsigned-integer-truncation).
"""

from pathlib import Path

from apatchy.bugs.base import Bug
from apatchy.utils.logger import get_logger

logger = get_logger(__name__)

HEADER_SIZE = 65536


class CVE_2020_11984(Bug):
    """Integer truncation in mod_proxy_uwsgi packet size."""

    def setup(self) -> None:  # noqa
        htdocs = Path("/tmp/htdocs")
        htdocs.mkdir(exist_ok=True)

    def generate_seeds(self) -> None:  # noqa
        seeds_dir = self.seeds_dir
        seeds_dir.mkdir(exist_ok=True)

        seed_path = seeds_dir / "large_header.txt"
        if seed_path.exists():
            logger.info(f"{seed_path} already exists, skipping")
            return

        header_val = "A" * HEADER_SIZE
        request = (
            f"GET / HTTP/1.1\r\n"  #
            f"Host: localhost\r\n"  #
            f"X-Big: {header_val}\r\n"  #
            f"Connection: close\r\n"  #
            f"\r\n"
        ).encode()

        seed_path.write_bytes(request)
        logger.info(f"wrote {seed_path}")
