"""Toolchain dependency checking, AFL++ setup, and LLVM detection.

:class:`ToolchainManager` inspects the local system for required build
tools, libraries, and fuzzing infrastructure.  It can also clone and
build AFL++ and download matching LLVM packages automatically.
"""

import os
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional

from apatchy.config import Config
from apatchy.core import toolchain_config
from apatchy.core.process_runner import ProcessRunner
from apatchy.utils.logger import get_logger

logger = get_logger(__name__)


@dataclass
class DepStatus:
    """Result of a single dependency check (used by :meth:`ToolchainManager.check`)."""

    name: str
    category: str
    found: bool
    version: str = ""
    path: str = ""
    install_hint: str = ""


class ToolchainManager:
    """Manages toolchain dependencies: checking, AFL++ setup, LLVM detection."""

    def __init__(self, verbose: bool = False) -> None:
        self.toolchain_dir = Config.TOOLCHAIN_DIR
        self.aflpp_dir = self.toolchain_dir / "aflplusplus"
        self.runner = ProcessRunner(verbose=verbose)


    def check(self) -> List[DepStatus]:
        """Return structured status for all dependencies."""
        deps: List[DepStatus] = []

        # Build tools
        deps.append(self._check_binary("clang", "Build", "apt install clang"))
        deps.append(self._check_binary("make", "Build", "apt install make"))
        deps.append(self._check_binary("pkg-config", "Build", "apt install pkg-config"))
        deps.append(self._check_binary("autoconf", "Build", "apt install autoconf"))
        deps.append(self._check_binary("libtool", "Build", "apt install libtool"))

        # Fuzzing tools
        deps.append(self._check_binary("afl-fuzz", "Fuzzing", "apatchy setup afl"))
        deps.append(self._check_binary("afl-clang-fast", "Fuzzing", "apatchy setup afl"))

        # Coverage tools (version-matched to clang)
        clang_ver = self._detect_clang_major_version()
        if clang_ver:
            deps.append(
                self._check_binary(
                    f"llvm-profdata-{clang_ver}",
                    "Coverage",
                    f"apt install llvm-{clang_ver}",
                    fallback="llvm-profdata",
                )
            )
            deps.append(
                self._check_binary(
                    f"llvm-cov-{clang_ver}",
                    "Coverage",
                    f"apt install llvm-{clang_ver}",
                    fallback="llvm-cov",
                )
            )
        else:
            deps.append(self._check_binary("llvm-profdata", "Coverage", "apt install llvm"))
            deps.append(self._check_binary("llvm-cov", "Coverage", "apt install llvm"))

        # System libraries
        deps.append(
            self._check_pkg_or_config(
                "libpcre2-dev",
                "Libraries",
                "pcre2-config",
                "libpcre2",
                "apt install libpcre2-dev",
            )
        )
        deps.append(
            self._check_pkg_or_config(
                "zlib1g-dev",
                "Libraries",
                None,
                "zlib",
                "apt install zlib1g-dev",
            )
        )
        deps.append(
            self._check_pkg_or_config(
                "libxml2-dev",
                "Libraries",
                "xml2-config",
                "libxml-2.0",
                "apt install libxml2-dev",
            )
        )
        deps.append(
            self._check_header_or_pkg(
                "libexpat1-dev",
                "Libraries",
                "expat.h",
                "expat",
                "apt install libexpat1-dev",
            )
        )
        deps.append(
            self._check_header_or_pkg(
                "uuid-dev",
                "Libraries",
                "uuid/uuid.h",
                "uuid",
                "apt install uuid-dev",
            )
        )
        deps.append(
            self._check_pkg_or_config(
                "libssl-dev",
                "Libraries",
                None,
                "openssl",
                "apt install libssl-dev",
            )
        )

        # Persist discovered paths to toolchain.config
        self._write_deps_to_config(deps)

        return deps


    def setup_afl(self) -> None:
        """Clone and build AFL++ into toolchain/aflplusplus/."""
        afl_fuzz = self.aflpp_dir / "afl-fuzz"
        if afl_fuzz.exists():
            logger.info(f"AFL++ already built at {self.aflpp_dir}")
            self._write_afl_paths()
            return

        # Check prereqs
        for prog in ("git", "clang", "make"):
            if not shutil.which(prog):
                logger.error(f"Missing required tool: {prog}")
                return

        self.toolchain_dir.mkdir(parents=True, exist_ok=True)

        # Clone
        if not self.aflpp_dir.exists():
            self.runner.run_build(
                ["git", "clone", Config.AFLPP_REPO_URL, str(self.aflpp_dir)],
                label="Cloning AFL++",
            )
        else:
            logger.info("AFL++ source already present, building...")

        # Build
        nproc = os.cpu_count() or 1
        self.runner.run_build(
            ["make", f"-j{nproc}", "source-only"],
            label="Building AFL++",
            cwd=self.aflpp_dir,
        )

        if afl_fuzz.exists():
            logger.info(f"AFL++ built successfully at {self.aflpp_dir}")
            self._write_afl_paths()
        else:
            logger.error("Build completed but afl-fuzz binary not found.")


    def setup_llvm(self, standalone: bool = False) -> None:
        """Detect clang version, download missing LLVM tools to toolchain/.

        Args:
            standalone: Download ALL tools into toolchain/ even if system
                        copies already exist.
        """
        clang_ver = self._detect_clang_major_version()
        if not clang_ver:
            logger.error("clang not found in PATH. Install clang first:")
            logger.error("  sudo apt install clang")
            return

        logger.info(f"Detected clang major version: {clang_ver}")

        tool_names = [
            f"llvm-profdata-{clang_ver}",
            f"llvm-cov-{clang_ver}",
            f"lld-{clang_ver}",
        ]

        llvm_dir = self.toolchain_dir / f"llvm-{clang_ver}"

        if standalone:
            # In standalone mode, check only the local toolchain directory
            logger.info("Standalone mode: targeting local toolchain directory")
            targets = []
            for name in tool_names:
                local = self._find_local_llvm_binary(llvm_dir, name)
                if local:
                    logger.info(f"  Found (local): {name} -> {local}")
                else:
                    targets.append(name)
                    sys_path = shutil.which(name)
                    if sys_path:
                        logger.info(f"  System: {name} -> {sys_path} (will download local copy)")
                    else:
                        logger.warning(f"  Missing: {name}")

            if not targets:
                logger.info("All LLVM tools already in toolchain directory.")
                # Ensure config points to local copies
                local_paths = {n: self._find_local_llvm_binary(llvm_dir, n) for n in tool_names}
                local_paths = {n: p for n, p in local_paths.items() if p}
                if local_paths:
                    toolchain_config.force_update_section("coverage", local_paths)
                return

            downloaded = self._download_llvm_packages(clang_ver, targets)
            if downloaded:
                # Merge with any already-local tools for a complete config write
                all_local = {}
                for name in tool_names:
                    if name in downloaded:
                        all_local[name] = downloaded[name]
                    else:
                        local = self._find_local_llvm_binary(llvm_dir, name)
                        if local:
                            all_local[name] = local
                toolchain_config.force_update_section("coverage", all_local)
                for name, path in downloaded.items():
                    logger.info(f"  Installed: {name} -> {path}")
                if len(all_local) == len(tool_names):
                    logger.info("All LLVM tools present (standalone).")
                    return

            # Fallback if download failed
            logger.error("Download failed. Try manually:")
            logger.info(f"  sudo apt install llvm-{clang_ver} lld-{clang_ver}")
            return

        # --- Normal (non-standalone) mode ---

        # Check toolchain.config first, then PATH
        tools: Dict[str, Optional[str]] = {}
        for name in tool_names:
            tools[name] = toolchain_config.resolve_tool(name)

        missing = [n for n, p in tools.items() if not p]
        found = {n: p for n, p in tools.items() if p}

        for name, path in found.items():
            logger.info(f"  Found: {name} -> {path}")

        if found:
            toolchain_config.force_update_section("coverage", found)

        if not missing:
            logger.info("All LLVM tools present.")
            return

        for name in missing:
            logger.warning(f"  Missing: {name}")

        # Offer to download missing tools locally
        answer = input(f"\nDownload missing tools to {llvm_dir}? [y/N] ")
        if answer.strip().lower() == "y":
            downloaded = self._download_llvm_packages(clang_ver, missing)
            if downloaded:
                toolchain_config.force_update_section("coverage", downloaded)
                for name, path in downloaded.items():
                    logger.info(f"  Installed: {name} -> {path}")
                still_missing = [n for n in missing if n not in downloaded]
                if not still_missing:
                    logger.info("All LLVM tools present.")
                    return
                missing = still_missing

        # Manual instructions for anything still missing
        logger.info("")
        logger.info("Install manually with:")
        logger.info(f"  sudo apt install llvm-{clang_ver} lld-{clang_ver}")
        logger.info("")
        logger.info("If the package is not available, add the LLVM apt repo:")
        logger.info("  https://apt.llvm.org/")
        logger.info(f"  wget https://apt.llvm.org/llvm.sh && chmod +x llvm.sh && sudo ./llvm.sh {clang_ver}")


    def _detect_clang_major_version(self) -> Optional[str]:
        """Detect the major version of clang in PATH."""
        clang = shutil.which("clang")
        if not clang:
            return None
        return self._get_binary_version(clang, major_only=True)

    def _check_binary(
        self,
        name: str,
        category: str,
        install_hint: str,
        fallback: Optional[str] = None,
    ) -> DepStatus:
        """Check if a binary exists - config override, then PATH."""
        # Check toolchain.config first (respects user overrides)
        path = toolchain_config.resolve_tool(name)
        if not path and fallback:
            path = toolchain_config.resolve_tool(fallback)
            if path:
                name = f"{name} (via {fallback})"
        if path:
            version = self._get_binary_version(path) or ""
            return DepStatus(name, category, True, version, path)
        return DepStatus(name, category, False, install_hint=install_hint)

    def _check_pkg_or_config(
        self,
        name: str,
        category: str,
        config_binary: Optional[str],
        pkg_name: str,
        install_hint: str,
    ) -> DepStatus:
        """Check for a library via its config binary or pkg-config."""
        # Try config binary first (e.g. pcre2-config, xml2-config)
        if config_binary:
            path = shutil.which(config_binary)
            if path:
                version = self._get_binary_version(path, flag="--version") or ""
                return DepStatus(name, category, True, version, path)

        # Try pkg-config
        if shutil.which("pkg-config"):
            result = subprocess.run(
                ["pkg-config", "--modversion", pkg_name],
                capture_output=True,
                text=True,
            )
            if result.returncode == 0:
                version = result.stdout.strip()
                return DepStatus(name, category, True, version, f"pkg-config:{pkg_name}")

        return DepStatus(name, category, False, install_hint=install_hint)

    def _check_header_or_pkg(
        self,
        name: str,
        category: str,
        header: str,
        pkg_name: str,
        install_hint: str,
    ) -> DepStatus:
        """Check for a library via header file or pkg-config."""
        # Try pkg-config first
        if shutil.which("pkg-config"):
            result = subprocess.run(
                ["pkg-config", "--modversion", pkg_name],
                capture_output=True,
                text=True,
            )
            if result.returncode == 0:
                version = result.stdout.strip()
                return DepStatus(name, category, True, version, f"pkg-config:{pkg_name}")

        # Check standard include paths for header
        for inc_dir in ("/usr/include", "/usr/local/include"):
            if Path(inc_dir, header).exists():
                return DepStatus(name, category, True, path=str(Path(inc_dir, header)))

        return DepStatus(name, category, False, install_hint=install_hint)


    def _find_local_llvm_binary(self, llvm_dir: Path, name: str) -> Optional[str]:
        """Check if a tool already exists in the local toolchain/llvm-{ver}/ directory."""
        for search_dir in (
            llvm_dir / "usr" / "bin",
            llvm_dir / "usr" / "lib" / llvm_dir.name / "bin",
        ):
            p = search_dir / name
            if p.exists():
                return str(p)
        return None

    def _download_llvm_packages(self, clang_ver: str, missing: List[str]) -> Dict[str, str]:
        """Download missing LLVM .deb packages and extract to toolchain/llvm-{ver}/."""
        llvm_dir = self.toolchain_dir / f"llvm-{clang_ver}"
        llvm_dir.mkdir(parents=True, exist_ok=True)

        # Deduplicate: map tool names to apt package names
        pkg_names = list(set(f"lld-{clang_ver}" if t.startswith("lld") else f"llvm-{clang_ver}" for t in missing))

        with tempfile.TemporaryDirectory() as tmpdir:
            for pkg in pkg_names:
                logger.info(f"Downloading {pkg}...")
                result = subprocess.run(
                    ["apt-get", "download", pkg],
                    cwd=tmpdir,
                    capture_output=True,
                    text=True,
                )
                if result.returncode != 0:
                    stderr = result.stderr.strip()
                    logger.error(f"apt-get download failed for {pkg}: {stderr}")
                    return {}

                # Extract the .deb into the llvm directory
                debs = list(Path(tmpdir).glob(f"{pkg}*.deb"))
                if not debs:
                    logger.error(f"No .deb found for {pkg}")
                    return {}

                for deb in debs:
                    logger.info(f"Extracting {deb.name}...")
                    result = subprocess.run(
                        ["dpkg-deb", "-x", str(deb), str(llvm_dir)],
                        capture_output=True,
                        text=True,
                    )
                    if result.returncode != 0:
                        logger.error(f"dpkg-deb failed: {result.stderr.strip()}")
                        return {}

        # Find extracted binaries
        found: Dict[str, str] = {}
        search_dirs = [
            llvm_dir / "usr" / "bin",
            llvm_dir / "usr" / "lib" / f"llvm-{clang_ver}" / "bin",
        ]
        for tool in missing:
            for search_dir in search_dirs:
                p = search_dir / tool
                if p.exists():
                    found[tool] = str(p)
                    break

        if found:
            logger.info(f"LLVM tools saved to {llvm_dir}")
        unfound = [t for t in missing if t not in found]
        for t in unfound:
            logger.warning(f"  Binary not found after extraction: {t}")

        return found


    def _write_afl_paths(self) -> None:
        """Write AFL++ binary paths to toolchain.config [fuzzing] section."""
        entries = {}
        for binary in ("afl-fuzz", "afl-clang-fast", "afl-clang-lto", "afl-gcc", "afl-showmap", "afl-cmin", "afl-tmin"):
            p = self.aflpp_dir / binary
            if p.exists():
                entries[binary] = str(p)
        if entries:
            toolchain_config.force_update_section("fuzzing", entries)
            logger.info(f"AFL++ paths saved to {Config.TOOLCHAIN_CONFIG}")

    def _write_deps_to_config(self, deps: List[DepStatus]) -> None:
        """Persist check() results to toolchain.config, grouped by section."""
        category_to_section = {
            "Build": "build",
            "Fuzzing": "fuzzing",
            "Coverage": "coverage",
            "Libraries": "libraries",
        }
        groups: dict = {}
        for dep in deps:
            if not dep.found or not dep.path:
                continue
            section = category_to_section.get(dep.category)
            if not section:
                continue
            key = self._normalize_key(dep.name)
            groups.setdefault(section, {})[key] = dep.path

        for section, entries in groups.items():
            toolchain_config.update_section(section, entries)

    @staticmethod
    def _normalize_key(name: str) -> str:
        """Strip fallback suffixes like ' (via llvm-profdata)' for clean INI keys."""
        idx = name.find(" (via ")
        if idx != -1:
            return name[:idx]
        return name

    @staticmethod
    def _get_binary_version(
        binary_path: str,
        flag: str = "--version",
        major_only: bool = False,
    ) -> Optional[str]:
        """Extract version string from a binary's --version output."""
        try:
            result = subprocess.run(
                [binary_path, flag],
                capture_output=True,
                text=True,
                timeout=5,
            )
            output = result.stdout + result.stderr
            match = re.search(r"(\d+\.\d+[\.\d]*)", output)
            if match:
                version = match.group(1)
                if major_only:
                    return version.split(".")[0]
                return version
        except (subprocess.TimeoutExpired, OSError):
            pass
        return None
