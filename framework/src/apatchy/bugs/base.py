"""Base class for 1day bug reproductions.

Contributors subclass :class:`Bug` and override methods as needed.
The base class provides sensible defaults so that the simplest
contribution is just a ``bug.toml`` + ``httpd.conf`` - no Python required.
"""

import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

from apatchy.utils.logger import get_logger

logger = get_logger(__name__)


class Bug:
    """Base class for 1day bug reproductions.

    Parameters
    ----------
    bug_dir : Path
        Absolute path to the bug's directory (e.g. ``bugs/cve_2022_23943/``).
    manifest : dict
        Parsed contents of ``bug.toml``.
    """

    def __init__(self, bug_dir: Path, manifest: Dict[str, Any]) -> None:
        self.bug_dir = bug_dir
        self.manifest = manifest

    @property
    def cve_id(self) -> str:
        """The CVE identifier from the manifest."""
        return self.manifest["bug"]["id"]

    @property
    def description(self) -> str:
        """Short description of the bug."""
        return self.manifest["bug"].get("description", "")

    @property
    def version(self) -> str:
        """Last affected Apache HTTPD version."""
        return self.manifest["bug"]["version"]

    @property
    def modules(self) -> List[str]:
        """Apache modules involved in the bug."""
        return self.manifest["bug"].get("modules", [])

    @property
    def bug_type(self) -> str:
        """Bug classification (e.g. heap-buffer-overflow, integer-overflow)."""
        return self.manifest["bug"].get("type", "unknown")

    @property
    def references(self) -> List[str]:
        """External reference URLs."""
        return self.manifest["bug"].get("references", [])

    @property
    def httpd_config(self) -> Path:
        """Path to the httpd.conf for this bug."""
        return self.bug_dir / "httpd.conf"

    @property
    def seeds_dir(self) -> Path:
        """Directory containing seed inputs."""
        return self.bug_dir / "seeds"

    @property
    def sanitizers(self) -> List[str]:
        """Recommended sanitizers from the manifest."""
        return self.manifest.get("build", {}).get("sanitizers", ["asan"])

    @property
    def triage_timeout(self) -> int:
        """Recommended triage timeout in seconds."""
        return self.manifest.get("reproduce", {}).get("timeout", 30)

    @property
    def suppress_file(self) -> Optional[str]:
        """Resolved path to the UBSan suppression file.

        Looks in the bug directory first, then ``configs/``.
        Returns ``None`` if not specified or not found.
        """
        name = self.manifest.get("reproduce", {}).get("suppress")
        if not name:
            return None

        # Bug-local suppression file takes priority
        local = self.bug_dir / name
        if local.exists():
            return str(local)

        # Fall back to configs/ directory
        configs = self.bug_dir.parent.parent / "configs" / name
        if configs.exists():
            return str(configs)

        return name

    def setup(self) -> None:
        """Extra setup beyond the standard download/configure/make.

        Override for bugs that need special preparation (e.g. creating
        files in DocumentRoot, generating certificates). Called after
        Apache is built and harnesses are linked.
        """

    def generate_seeds(self) -> None:
        """Generate seed inputs for this bug.

        Override to create seeds programmatically.  The default
        implementation runs ``gen_seed.py`` if it exists in the bug
        directory.
        """
        gen_script = self.bug_dir / "gen_seed.py"
        if gen_script.exists():
            logger.info(f"Running seed generator: {gen_script.name}")
            subprocess.run([sys.executable, str(gen_script)], check=True, cwd=str(self.bug_dir))
        else:
            logger.info("No seed generator found, skipping")

    def reproduce(self, harness_path: Path, **kwargs: Any) -> None:
        """Reproduce the bug by triaging all seeds.

        Override for custom reproduction logic (e.g. multi-step
        sequences, specific seed ordering).  The default delegates
        to :class:`~apatchy.managers.report_manager.ReportManager`.

        Parameters
        ----------
        harness_path : Path
            Path to the compiled harness binary.
        **kwargs
            Extra arguments forwarded to the triage call.
        """
        # Default implementation is handled by BugManager which calls
        # ReportManager.triage_crash() for each seed file.
        pass

    def configure_flags(self) -> List[str]:
        """Extra Apache configure flags needed for this bug.

        Override if the bug needs flags beyond the defaults (e.g.
        ``--with-crypto`` for session_crypto bugs).
        """
        return self.manifest.get("build", {}).get("configure_flags", [])

    def fuzz_env(self) -> Dict[str, str]:
        """Extra environment variables for fuzzing this bug.

        Override to set custom env vars (e.g. ``AFL_PRELOAD``,
        custom dictionary paths).
        """
        return {}

    def clean(self) -> None:
        """Clean up generated artifacts for this bug.

        Override to remove bug-specific files (e.g. files created in
        ``/tmp``, generated configs).  The default implementation
        removes the ``seeds/`` directory if it exists.
        """
        import shutil

        if self.seeds_dir.exists():
            shutil.rmtree(self.seeds_dir)
            logger.info(f"Removed {self.seeds_dir}")
