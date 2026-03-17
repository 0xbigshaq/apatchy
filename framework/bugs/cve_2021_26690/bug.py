"""CVE-2021-26690 - NULL pointer dereference in mod_session.

A cookie value of "=" causes session_identity_decode to pass a NULL
pointer to apr_strtok.  The identity decoder splits on "&" to extract
key=value pairs, but when the entire cookie value is just "=",
apr_strtok receives NULL and dereferences it.
"""

from pathlib import Path

from apatchy.bugs.base import Bug
from apatchy.utils.logger import get_logger

logger = get_logger(__name__)


class CVE_2021_26690(Bug):
    """NULL pointer dereference in mod_session session_identity_decode."""

    def setup(self) -> None:  # noqa: D102
        htdocs = Path("/tmp/htdocs")
        htdocs.mkdir(exist_ok=True)

    def generate_seeds(self) -> None:  # noqa: D102
        seeds_dir = self.seeds_dir
        seeds_dir.mkdir(exist_ok=True)
        logger.info("Generating seeds...")
        self._null_deref_identity_decode(seeds_dir)
        logger.info("Seeds generated.")

    def _null_deref_identity_decode(self, seeds_dir: Path) -> None:
        """Proto seed that triggers NULL deref in session_identity_decode.

        Route /k has SessionCookieRemove On. A cookie value of "="
        produces a NULL token from the "&" split, which apr_strtok
        dereferences.
        """
        seed = seeds_dir / "null_deref.textproto"
        if seed.exists():
            logger.info("null_deref.textproto already exists, skipping")
            return

        src = self.bug_dir / "null_deref.textproto"
        seed.write_text(src.read_text())
