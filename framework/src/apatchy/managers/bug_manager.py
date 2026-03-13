import importlib.util
import inspect
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

from apatchy.bugs.base import Bug
from apatchy.config import Config
from apatchy.utils.logger import get_logger

logger = get_logger(__name__)

# Python 3.11+ ships tomllib; older versions need the tomli backport.
try:
    import tomllib
except ModuleNotFoundError:
    import tomli as tomllib  # type: ignore[no-redef]


class BugManager:
    """Discover, load, and orchestrate 1day bug reproductions.

    ``BugManager`` manages the full lifecycle of known (1day) Apache HTTPD bugs:
    listing what is available, setting up a reproduction environment, and running
    the actual triage. Each bug lives in its own subdirectory under ``bugs/`` and
    is described by a ``bug.toml`` manifest. An optional ``bug.py`` can subclass
    :class:`~apatchy.bugs.base.Bug` to add custom setup, seed generation, or
    reproduction logic.

    A typical bug directory looks like::

        bugs/
          cve_xxxx_yyyyy/
            bug.toml        # manifest (id, version, modules, sanitizers, ...)
            bug.py          # optional Bug subclass with custom logic
            httpd.conf      # Apache config that triggers the bug
            gen_seed.py     # optional seed generator script
            seeds/          # generated seed inputs (created by setup)

    The setup flow performed by :meth:`setup` is:

    1. Download the vulnerable Apache version if not already present.
    2. Configure and build Apache with the sanitizers listed in the manifest.
    3. Link the fuzzing harnesses (AFL++ and standalone).
    4. Run any bug-specific setup (e.g. creating files in DocumentRoot).
    5. Generate seed inputs.

    Args:
        bugs_dir: Root directory containing bug subdirectories. Defaults to
            ``<WORK_DIR>/bugs/``.
        verbose: Forward verbose flag to build operations.

    Example:
        .. code-block:: python

            from apatchy.managers.bug_manager import BugManager

            bm = BugManager()

            # List all available bugs
            for bug in bm.list_bugs():
                print(f"{bug['id']}  {bug['description']}")

            # Set up a bug (download, build, seed)
            bm.setup("CVE-2022-23943")

            # Reproduce it by triaging the generated seeds
            bm.reproduce("CVE-2022-23943")
    """

    def __init__(self, bugs_dir: Optional[Path] = None, verbose: bool = False) -> None:
        self.bugs_dir = bugs_dir or Config.WORK_DIR / "bugs"
        self.verbose = verbose

    def list_bugs(self) -> List[Dict[str, Any]]:
        """Return metadata for every bug that has a ``bug.toml``.

        Returns
        -------
        list[dict]
            Each dict contains keys from the ``[bug]`` table plus
            the directory path.
        """
        results: List[Dict[str, Any]] = []
        if not self.bugs_dir.exists():
            return results

        for toml_path in sorted(self.bugs_dir.glob("*/bug.toml")):
            manifest = self._load_manifest(toml_path)
            if manifest is None:
                continue
            bug_section = manifest.get("bug", {})
            results.append(
                {
                    "id": bug_section.get("id", toml_path.parent.name),
                    "description": bug_section.get("description", ""),
                    "modules": bug_section.get("modules", []),
                    "version": bug_section.get("version", ""),
                    "type": bug_section.get("type", ""),
                    "dir": str(toml_path.parent),
                }
            )
        return results

    def get_bug_instance(self, cve_id: str) -> Bug:
        """Load and return a :class:`Bug` instance for the given CVE.

        Parameters
        ----------
        cve_id : str
            CVE identifier.  Accepted formats: ``CVE-2022-23943``,
            ``cve-2022-23943``, or ``cve_2022_23943``.

        Raises
        ------
        FileNotFoundError
            If no matching bug directory or ``bug.toml`` is found.
        """
        bug_dir = self._resolve_bug_dir(cve_id)
        toml_path = bug_dir / "bug.toml"
        if not toml_path.exists():
            raise FileNotFoundError(f"No bug.toml found in {bug_dir}")

        manifest = self._load_manifest(toml_path)
        if manifest is None:
            raise FileNotFoundError(f"Failed to parse {toml_path}")

        # Try loading contributor's bug.py, fall back to base Bug class
        bug_py = bug_dir / "bug.py"
        if bug_py.exists():
            bug_cls = self._load_bug_class(bug_py)
            if bug_cls is not None:
                return bug_cls(bug_dir, manifest)

        return Bug(bug_dir, manifest)

    def setup(self, cve_id: str) -> None:
        """Full setup for a bug: download, configure, build, link, seeds.

        Parameters
        ----------
        cve_id : str
            CVE identifier.
        """
        bug = self.get_bug_instance(cve_id)
        version = bug.version

        logger.info(f"Setting up {bug.cve_id} (Apache {version})")

        # Download
        from apatchy.core.downloader import Downloader

        downloader = Downloader()
        httpd_dir = Config.get_apache_dir(version)
        if not httpd_dir.exists():
            logger.info(f"Downloading Apache {version}...")
            downloader.download_apache(version)
        else:
            logger.info(f"Apache {version} already downloaded")

        # Configure
        from apatchy.managers.build_manager import BuildManager
        from apatchy.managers.config_manager import ConfigManager

        sanitizer_flags = {s: True for s in bug.sanitizers}
        config_manager = ConfigManager(
            build_mode="fuzz",
            asan=sanitizer_flags.get("asan", False),
            ubsan=sanitizer_flags.get("ubsan", False),
            intsan=sanitizer_flags.get("intsan", False),
            truncsan=sanitizer_flags.get("truncsan", False),
        )
        build_manager = BuildManager(httpd_dir, config_manager, verbose=self.verbose)

        logger.info("Configuring Apache...")
        build_manager.configure_httpd(extra_flags=bug.configure_flags())

        # Make
        logger.info("Building Apache...")
        build_manager.compile_httpd()

        # Link harnesses (always relink to match the version we just built)
        harness_name = bug.harness
        for engine in ("afl", "standalone"):
            logger.info(f"Linking {engine} harness...")
            build_manager.build_harness(mode=engine, harness_name=harness_name)

        # Bug-specific setup
        logger.info("Running bug-specific setup...")
        bug.setup()

        # Generate seeds
        logger.info("Generating seeds...")
        bug.generate_seeds()

        logger.info(f"{bug.cve_id} setup complete")
        logger.info(f"  Config: {bug.httpd_config}")
        logger.info(f"  Fuzz:   apatchy fuzz --config {bug.httpd_config}")

    def reproduce(self, cve_id: str) -> None:
        """Reproduce a bug by triaging its seeds.

        Parameters
        ----------
        cve_id : str
            CVE identifier.
        """
        bug = self.get_bug_instance(cve_id)

        if not bug.seeds_dir.exists() or not any(bug.seeds_dir.iterdir()):
            logger.info("No seeds found, generating...")
            bug.generate_seeds()

        # Find harness
        harness_path = self._find_harness()
        if harness_path is None:
            logger.error("No harness binary found. Run 'apatchy bug setup %s' first.", cve_id)
            return

        # TODO(#27): detect harness version via `fuzz_harness --version`
        # and warn if it doesn't match bug.version

        # Check for custom reproduce()
        if type(bug).reproduce is not Bug.reproduce:
            logger.info(f"Running custom reproduce() for {bug.cve_id}")
            bug.reproduce(harness_path)
            return

        # Default: triage each seed file
        if not bug.seeds_dir.exists():
            logger.error(f"No seeds directory at {bug.seeds_dir}")
            return

        seed_files = sorted(f for f in bug.seeds_dir.iterdir() if f.is_file())
        if not seed_files:
            logger.error(f"No seed files found in {bug.seeds_dir}")
            return

        httpd_root = self._get_active_httpd(bug.version)
        if httpd_root is None:
            return

        from apatchy.managers.config_manager import ConfigManager
        from apatchy.managers.report_manager import ReportManager

        config_manager = ConfigManager(config_name=str(bug.httpd_config))
        report_manager = ReportManager(httpd_root, config_manager)

        logger.info(f"Triaging {len(seed_files)} seed(s) for {bug.cve_id}")
        for seed_file in seed_files:
            logger.info(f"  Triaging {seed_file.name}...")
            report_manager.triage_crash(
                str(seed_file),
                harness_path,
                suppress=bug.suppress_file,
                timeout=bug.triage_timeout,
            )

    def _resolve_bug_dir(self, cve_id: str) -> Path:
        """Resolve a CVE ID to a bug directory path.

        Accepts ``CVE-2022-23943``, ``cve-2022-23943``, or
        ``cve_2022_23943``.
        """
        # Normalise to underscore form
        normalised = cve_id.lower().replace("-", "_")
        bug_dir = self.bugs_dir / normalised
        if bug_dir.exists():
            return bug_dir

        # Try with dashes
        dashed = cve_id.lower()
        bug_dir = self.bugs_dir / dashed
        if bug_dir.exists():
            return bug_dir

        # Scan all directories for a matching [bug].id
        for toml_path in self.bugs_dir.glob("*/bug.toml"):
            manifest = self._load_manifest(toml_path)
            if manifest and manifest.get("bug", {}).get("id", "").upper() == cve_id.upper():
                return toml_path.parent

        raise FileNotFoundError(
            f"Bug directory not found for '{cve_id}'. Run 'apatchy bug list' to see available bugs."
        )

    @staticmethod
    def _load_manifest(toml_path: Path) -> Optional[Dict[str, Any]]:
        """Parse a ``bug.toml`` file."""
        try:
            with open(toml_path, "rb") as f:
                return tomllib.load(f)
        except Exception:
            logger.warning(f"Failed to parse {toml_path}")
            return None

    @staticmethod
    def _load_bug_class(bug_py: Path) -> Optional[type]:
        """Dynamically load a :class:`Bug` subclass from ``bug.py``."""
        spec = importlib.util.spec_from_file_location("_bug_module", bug_py)
        if spec is None or spec.loader is None:
            return None

        module = importlib.util.module_from_spec(spec)
        sys.modules["_bug_module"] = module
        try:
            spec.loader.exec_module(module)
        except Exception:
            logger.warning(f"Failed to load {bug_py}", exc_info=True)
            return None
        finally:
            sys.modules.pop("_bug_module", None)

        # Find the first Bug subclass (not Bug itself)
        for _name, obj in inspect.getmembers(module, inspect.isclass):
            if issubclass(obj, Bug) and obj is not Bug:
                return obj

        return None

    @staticmethod
    def _find_harness() -> Optional[Path]:
        """Find a harness binary for triage."""
        for name in ("fuzz_harness_standalone", "fuzz_harness_afl"):
            candidate = Config.WORK_DIR / name
            if candidate.exists():
                return candidate
        return None

    @staticmethod
    def _get_active_httpd(version: str) -> Optional[Path]:
        """Find the httpd source directory for a version."""
        target = Config.get_apache_dir(version)
        if target.exists():
            return target
        # Try finding any httpd-*
        dirs = [d for d in Config.WORK_DIR.glob("httpd-*") if not d.name.endswith(("-cov", "-standalone"))]
        if len(dirs) == 1:
            return dirs[0]
        logger.error(f"httpd-{version} not found. Run 'apatchy bug setup' first.")
        return None
