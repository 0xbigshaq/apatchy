import os
import subprocess
from pathlib import Path
from typing import List, Optional

from apatchy.config import Config
from apatchy.core import toolchain_config
from apatchy.core.process_runner import ProcessRunner
from apatchy.core.toolchain.base import DepStatus, ToolchainTool
from apatchy.core.toolchain.simple import BinaryTool, get_binary_version
from apatchy.utils.logger import get_logger

logger = get_logger(__name__)


class AflTool(ToolchainTool):
    name = "afl"

    def __init__(self, toolchain_dir: Path, verbose: bool = False) -> None:
        super().__init__(toolchain_dir, verbose)
        self._aflpp_dir = toolchain_dir / "aflplusplus"
        self._runner = ProcessRunner(verbose=verbose)

    def detect(self) -> Optional[str]:
        path = toolchain_config.resolve_tool("afl-fuzz")
        if path:
            return get_binary_version(path) or "unknown"
        return None

    def check(self) -> List[DepStatus]:
        return (
            BinaryTool("afl-fuzz", "Fuzzing", "apatchy setup afl", self.toolchain_dir, self.verbose).check()
            + BinaryTool("afl-clang-fast", "Fuzzing", "apatchy setup afl", self.toolchain_dir, self.verbose).check()
        )

    def setup(self, force: bool = False, **kwargs) -> None:
        afl_fuzz = self._aflpp_dir / "afl-fuzz"
        if afl_fuzz.exists() and not force:
            logger.info(f"AFL++ already built at {self._aflpp_dir}")
            self._write_paths()
            return

        for prog in ("git", "clang", "make"):
            if not toolchain_config.resolve_tool(prog):
                logger.error(f"Missing required tool: {prog}")
                return

        self.toolchain_dir.mkdir(parents=True, exist_ok=True)

        if not self._aflpp_dir.exists():
            self._runner.run_build(
                ["git", "clone", Config.AFLPP_REPO_URL, str(self._aflpp_dir)],
                label="Cloning AFL++",
            )
        elif force:
            logger.info("Force mode: cleaning previous AFL++ build...")
            subprocess.run(["make", "clean"], cwd=self._aflpp_dir, capture_output=True)
        else:
            logger.info("AFL++ source already present, building...")

        nproc = os.cpu_count() or 1
        build_env = os.environ.copy()
        clang_path = toolchain_config.resolve_tool("clang")
        clangpp_path = toolchain_config.resolve_tool("clang++")
        if clang_path:
            build_env["CC"] = clang_path
        if clangpp_path:
            build_env["CXX"] = clangpp_path

        llvm_config_path = toolchain_config.resolve_tool("llvm-config")
        if not llvm_config_path and clang_path:
            candidates = sorted(Path(clang_path).parent.glob("llvm-config*"))
            if candidates:
                llvm_config_path = str(candidates[0])
        if llvm_config_path:
            build_env["LLVM_CONFIG"] = llvm_config_path

        self._runner.run_build(
            ["make", f"-j{nproc}", "source-only"],
            label="Building AFL++",
            cwd=self._aflpp_dir,
            env=build_env,
        )

        if afl_fuzz.exists():
            logger.info(f"AFL++ built successfully at {self._aflpp_dir}")
            self._write_paths()
        else:
            logger.error("Build completed but afl-fuzz binary not found.")

    def _write_paths(self) -> None:
        entries = {}
        for binary in ("afl-fuzz", "afl-clang-fast", "afl-clang-lto", "afl-gcc", "afl-showmap", "afl-cmin", "afl-tmin"):
            p = self._aflpp_dir / binary
            if p.exists():
                entries[binary] = str(p)
        if entries:
            toolchain_config.force_update_section("fuzzing", entries)
            logger.info(f"AFL++ paths saved to {Config.TOOLCHAIN_CONFIG}")
