import subprocess
import tempfile
from pathlib import Path
from typing import Dict, List, Optional

from apatchy.core import toolchain_config
from apatchy.core.toolchain.base import DepStatus, ToolchainTool
from apatchy.core.toolchain.simple import BinaryTool, get_binary_version
from apatchy.utils.logger import get_logger

logger = get_logger(__name__)


class LlvmTool(ToolchainTool):  # noqa: D101
    name = "llvm"

    def detect(self) -> Optional[str]:  # noqa: D102
        candidates = [f"clang-{v}" for v in range(20, 10, -1)] + ["clang"]
        for name in candidates:
            path = toolchain_config.resolve_tool(name)
            if path:
                ver = get_binary_version(path, major_only=True)
                if ver:
                    return ver
        return None

    def check(self) -> List[DepStatus]:  # noqa: D102
        deps = []
        clang_ver = self.detect()
        if clang_ver:
            deps.append(
                BinaryTool(
                    f"llvm-profdata-{clang_ver}",
                    "Coverage",
                    f"apatchy setup llvm --llvm-version {clang_ver}",
                    self.toolchain_dir,
                    self.verbose,
                    fallback="llvm-profdata",
                    version_args=["merge", "--version"],
                ).check()[0]
            )
            deps.append(
                BinaryTool(
                    f"llvm-cov-{clang_ver}",
                    "Coverage",
                    f"apatchy setup llvm --llvm-version {clang_ver}",
                    self.toolchain_dir,
                    self.verbose,
                    fallback="llvm-cov",
                ).check()[0]
            )
        else:
            deps.append(
                BinaryTool(
                    "llvm-profdata",
                    "Coverage",
                    "apatchy setup llvm --llvm-version 18",
                    self.toolchain_dir,
                    self.verbose,
                    version_args=["merge", "--version"],
                ).check()[0]
            )
            deps.append(
                BinaryTool(
                    "llvm-cov", "Coverage", "apatchy setup llvm --llvm-version 18", self.toolchain_dir, self.verbose
                ).check()[0]
            )
        return deps

    def setup(self, force: bool = False, **kwargs) -> None:  # noqa: D102
        llvm_version = kwargs.get("llvm_version")
        clang_ver = llvm_version or self.detect()
        if not clang_ver:
            logger.error("clang not found. Specify --llvm-version:")
            logger.error("  apatchy setup --force llvm --llvm-version 18")
            return

        if not force and self.detect():
            logger.info(f"LLVM {clang_ver} already installed, registering paths...")
            self._register_binaries(clang_ver)
            return

        logger.info(f"Installing LLVM {clang_ver} via apt.llvm.org installer...")
        if self._run_llvm_installer(clang_ver):
            self._register_binaries(clang_ver)

    def _run_llvm_installer(self, clang_ver: str) -> bool:
        with tempfile.TemporaryDirectory() as tmpdir:
            script = Path(tmpdir) / "llvm.sh"
            result = subprocess.run(
                ["wget", "-qO", str(script), "https://apt.llvm.org/llvm.sh"],
                capture_output=True,
                text=True,
            )
            if result.returncode != 0:
                logger.error(f"Failed to download LLVM installer: {result.stderr.strip()}")
                return False
            script.chmod(0o755)
            result = subprocess.run(
                ["sudo", str(script), clang_ver, "all"],
                text=True,
            )
            if result.returncode != 0:
                logger.error("LLVM installer failed")
                return False
        return True

    def _register_binaries(self, clang_ver: str) -> None:
        bin_dir = Path(f"/usr/lib/llvm-{clang_ver}/bin")
        if not bin_dir.is_dir():
            logger.warning(f"LLVM bin dir not found: {bin_dir}")
            return

        build_entries: Dict[str, str] = {}
        coverage_entries: Dict[str, str] = {}

        for p in sorted(bin_dir.iterdir()):
            if not p.is_file():
                continue
            name = p.name
            path = str(p)
            if name.startswith("clang"):
                build_entries[name] = path
                unversioned = name.removesuffix(f"-{clang_ver}")
                if unversioned != name:
                    build_entries[unversioned] = path
            else:
                coverage_entries[name] = path

        if build_entries:
            toolchain_config.force_update_section("build", build_entries)
            logger.info(f"Registered {len(build_entries)} build tool(s) from {bin_dir}")
        if coverage_entries:
            toolchain_config.force_update_section("coverage", coverage_entries)
            logger.info(f"Registered {len(coverage_entries)} LLVM tool(s) from {bin_dir}")
