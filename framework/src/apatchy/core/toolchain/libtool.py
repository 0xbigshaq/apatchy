import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import List, Optional

from apatchy.core import toolchain_config
from apatchy.core.toolchain.base import DepStatus, ToolchainTool
from apatchy.core.toolchain.simple import get_binary_version
from apatchy.utils.logger import get_logger

logger = get_logger(__name__)


class LibtoolTool(ToolchainTool):  # noqa: D101
    name = "libtool"

    def detect(self) -> Optional[str]:  # noqa: D102
        path = toolchain_config.resolve_tool("libtool")
        if path:
            return get_binary_version(path) or "unknown"
        return None

    def check(self) -> List[DepStatus]:  # noqa: D102
        path = toolchain_config.resolve_tool("libtool")
        if path:
            version = get_binary_version(path) or ""
            return [DepStatus("libtool", "Build", True, version, path)]
        return [DepStatus("libtool", "Build", False, install_hint="apatchy setup libtool")]

    def setup(self, force: bool = False, **kwargs) -> None:  # noqa: D102
        dest = self.toolchain_dir / "libtool"
        binary = dest / "usr" / "bin" / "libtool"

        if binary.exists():
            logger.info(f"libtool already at {binary}")
            toolchain_config.force_update_section("build", {"libtool": str(binary)})
            return

        if not force:
            system = shutil.which("libtool")
            if system:
                logger.info(f"libtool found at {system}, skipping download")
                toolchain_config.force_update_section("build", {"libtool": system})
                return

        dest.mkdir(parents=True, exist_ok=True)

        with tempfile.TemporaryDirectory() as tmpdir:
            for pkg in ("libtool", "libtool-bin"):
                logger.info(f"Downloading {pkg}...")
                result = subprocess.run(
                    ["apt-get", "download", pkg],
                    cwd=tmpdir,
                    capture_output=True,
                    text=True,
                )
                if result.returncode != 0:
                    logger.error(f"apt-get download failed for {pkg}: {result.stderr.strip()}")
                    return

            for deb in sorted(Path(tmpdir).glob("libtool*.deb")):
                logger.info(f"Extracting {deb.name}...")
                result = subprocess.run(
                    ["dpkg-deb", "-x", str(deb), str(dest)],
                    capture_output=True,
                    text=True,
                )
                if result.returncode != 0:
                    logger.error(f"dpkg-deb failed: {result.stderr.strip()}")
                    return

        if binary.exists():
            toolchain_config.force_update_section("build", {"libtool": str(binary)})
            logger.info(f"libtool saved to {binary}")
        else:
            logger.error("libtool binary not found after extraction")
