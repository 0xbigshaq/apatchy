import os
import subprocess
from pathlib import Path
from typing import List, Optional

from apatchy.core import toolchain_config
from apatchy.core.process_runner import ProcessRunner
from apatchy.core.toolchain.base import DepStatus, ToolchainTool
from apatchy.core.toolchain.simple import get_binary_version
from apatchy.utils.logger import get_logger

logger = get_logger(__name__)

LPM_REPO_URL = "https://github.com/google/libprotobuf-mutator.git"

# Standard system paths where LPM headers/libs may be installed
_SYSTEM_INCLUDE_DIRS = ("/usr/include", "/usr/local/include")
_SYSTEM_LIB_DIRS = ("/usr/lib", "/usr/lib/x86_64-linux-gnu", "/usr/local/lib")


class LpmTool(ToolchainTool):
    """Clone and build libprotobuf-mutator for structure-aware libFuzzer fuzzing."""

    name = "lpm"

    def __init__(self, toolchain_dir: Path, verbose: bool = False) -> None:
        super().__init__(toolchain_dir, verbose)
        self._lpm_dir = toolchain_dir / "libprotobuf-mutator"
        self._runner = ProcessRunner(verbose=verbose)

    def check(self) -> List[DepStatus]:  # noqa: D102
        results: List[DepStatus] = []

        # protoc
        protoc = toolchain_config.resolve_tool("protoc")
        if protoc:
            version = get_binary_version(protoc) or ""
            results.append(DepStatus("protoc", "Fuzzing", True, version, protoc))
        else:
            results.append(DepStatus("protoc", "Fuzzing", False, install_hint="apt install protobuf-compiler"))

        # libprotobuf
        pb_found = self._check_pkg("protobuf")
        if pb_found:
            results.append(DepStatus("libprotobuf-dev", "Fuzzing", True, pb_found, "pkg-config:protobuf"))
        else:
            results.append(DepStatus("libprotobuf-dev", "Fuzzing", False, install_hint="apt install libprotobuf-dev"))

        # libprotobuf-mutator
        lpm_path = self._find_lpm()
        if lpm_path:
            results.append(DepStatus("libprotobuf-mutator", "Fuzzing", True, path=str(lpm_path)))
        else:
            results.append(DepStatus("libprotobuf-mutator", "Fuzzing", False, install_hint="apatchy setup lpm"))

        return results

    def setup(self, force: bool = False, **kwargs) -> None:  # noqa: D102
        build_dir = self._lpm_dir / "build"
        marker = build_dir / "src" / "libprotobuf-mutator.a"

        if marker.exists() and not force:
            logger.info(f"libprotobuf-mutator already built at {self._lpm_dir}")
            self._write_paths()
            return

        for prog in ("cmake", "protoc"):
            if not toolchain_config.resolve_tool(prog):
                logger.error(f"Missing required tool: {prog}")
                return

        # Prefer ninja but fall back to make
        ninja = toolchain_config.resolve_tool("ninja")
        generator = "Ninja" if ninja else "Unix Makefiles"

        self.toolchain_dir.mkdir(parents=True, exist_ok=True)

        if not self._lpm_dir.exists():
            self._runner.run_build(
                ["git", "clone", LPM_REPO_URL, str(self._lpm_dir)],
                label="Cloning libprotobuf-mutator",
            )
        elif force:
            logger.info("Force mode: cleaning previous LPM build...")
            if build_dir.exists():
                import shutil

                shutil.rmtree(build_dir)

        build_dir.mkdir(exist_ok=True)

        nproc = os.cpu_count() or 1

        self._runner.run_build(
            [
                "cmake",
                f"-G{generator}",
                "-DCMAKE_BUILD_TYPE=Release",
                "-DLIB_PROTO_MUTATOR_TESTING=OFF",
                "-DLIB_PROTO_MUTATOR_DOWNLOAD_PROTOBUF=OFF",
                "..",
            ],
            label="Configuring LPM",
            cwd=build_dir,
        )

        build_cmd = ["ninja", f"-j{nproc}"] if ninja else ["make", f"-j{nproc}"]
        self._runner.run_build(
            build_cmd,
            label="Building LPM",
            cwd=build_dir,
        )

        if marker.exists():
            logger.info(f"libprotobuf-mutator built at {self._lpm_dir}")
            self._write_paths()
        else:
            logger.error("Build completed but libprotobuf-mutator.a not found.")

    def _write_paths(self) -> None:
        build_dir = self._lpm_dir / "build"
        entries = {
            "lpm-root": str(self._lpm_dir),
            "lpm-build": str(build_dir),
        }
        toolchain_config.force_update_section("fuzzing", entries)
        logger.info("LPM paths saved to toolchain.config")

    def _find_lpm(self) -> Optional[Path]:
        """Find LPM installation: toolchain build first, then system paths."""
        # Toolchain-local build
        local_lib = self._lpm_dir / "build" / "src" / "libprotobuf-mutator.a"
        if local_lib.exists():
            return self._lpm_dir

        # System paths
        for lib_dir in _SYSTEM_LIB_DIRS:
            for name in ("libprotobuf-mutator.a", "libprotobuf-mutator.so"):
                if Path(lib_dir, name).exists():
                    return Path(lib_dir)

        return None

    @staticmethod
    def _check_pkg(pkg_name: str) -> str:
        """Check if a pkg-config package is available, return version or empty string."""
        try:
            result = subprocess.run(
                ["pkg-config", "--modversion", pkg_name],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode == 0:
                return result.stdout.strip()
        except (subprocess.TimeoutExpired, OSError):
            pass
        return ""
