import re
import shutil
import subprocess
from pathlib import Path
from typing import List, Optional

from apatchy.core import toolchain_config
from apatchy.core.toolchain.base import DepStatus, ToolchainTool


def get_binary_version(binary_path: str, flag: str = "--version", major_only: bool = False) -> Optional[str]:
    try:
        result = subprocess.run([binary_path, flag], capture_output=True, text=True, timeout=5)
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


def get_binary_version_from_args(binary_path: str, args: List[str]) -> Optional[str]:
    try:
        result = subprocess.run([binary_path, *args], capture_output=True, text=True, timeout=5)
        output = result.stdout + result.stderr
        match = re.search(r"(\d+\.\d+[\.\d]*)", output)
        if match:
            return match.group(1)
    except (subprocess.TimeoutExpired, OSError):
        pass
    return None


class BinaryTool(ToolchainTool):  # noqa: D101
    def __init__(
        self,
        name: str,
        category: str,
        install_hint: str,
        toolchain_dir: Path,
        verbose: bool = False,
        fallback: Optional[str] = None,
        version_args: Optional[List[str]] = None,
        exists_only: bool = False,
    ) -> None:
        super().__init__(toolchain_dir, verbose)
        self.name = name
        self.category = category
        self.install_hint = install_hint
        self._fallback = fallback
        self._version_args = version_args
        self._exists_only = exists_only

    def detect(self) -> Optional[str]:  # noqa: D102
        path = toolchain_config.resolve_tool(self.name)
        if not path and self._fallback:
            path = toolchain_config.resolve_tool(self._fallback)
        if path:
            return get_binary_version(path) or "unknown"
        return None

    def check(self) -> List[DepStatus]:  # noqa: D102
        path = toolchain_config.resolve_tool(self.name)
        display_name = self.name
        if not path and self._fallback:
            path = toolchain_config.resolve_tool(self._fallback)
            if path:
                display_name = f"{self.name} (via {self._fallback})"
        if path:
            if self._exists_only:
                return [DepStatus(display_name, self.category, True, path=path)]
            version = (
                get_binary_version_from_args(path, self._version_args)
                if self._version_args
                else get_binary_version(path)
            ) or ""
            return [DepStatus(display_name, self.category, True, version, path)]
        return [DepStatus(display_name, self.category, False, install_hint=self.install_hint)]


class PkgOrConfigTool(ToolchainTool):  # noqa: D101
    def __init__(
        self,
        name: str,
        category: str,
        install_hint: str,
        toolchain_dir: Path,
        config_binary: Optional[str],
        pkg_name: str,
        verbose: bool = False,
    ) -> None:
        super().__init__(toolchain_dir, verbose)
        self.name = name
        self.category = category
        self.install_hint = install_hint
        self._config_binary = config_binary
        self._pkg_name = pkg_name

    def check(self) -> List[DepStatus]:  # noqa: D102
        if self._config_binary:
            path = shutil.which(self._config_binary)
            if path:
                version = get_binary_version(path, flag="--version") or ""
                return [DepStatus(self.name, self.category, True, version, path)]
        if shutil.which("pkg-config"):
            result = subprocess.run(
                ["pkg-config", "--modversion", self._pkg_name],
                capture_output=True,
                text=True,
            )
            if result.returncode == 0:
                version = result.stdout.strip()
                return [DepStatus(self.name, self.category, True, version, f"pkg-config:{self._pkg_name}")]
        return [DepStatus(self.name, self.category, False, install_hint=self.install_hint)]


class HeaderOrPkgTool(ToolchainTool):  # noqa: D101
    def __init__(
        self,
        name: str,
        category: str,
        install_hint: str,
        toolchain_dir: Path,
        header: str,
        pkg_name: str,
        verbose: bool = False,
    ) -> None:
        super().__init__(toolchain_dir, verbose)
        self.name = name
        self.category = category
        self.install_hint = install_hint
        self._header = header
        self._pkg_name = pkg_name

    def check(self) -> List[DepStatus]:  # noqa: D102
        if shutil.which("pkg-config"):
            result = subprocess.run(
                ["pkg-config", "--modversion", self._pkg_name],
                capture_output=True,
                text=True,
            )
            if result.returncode == 0:
                version = result.stdout.strip()
                return [DepStatus(self.name, self.category, True, version, f"pkg-config:{self._pkg_name}")]
        for inc_dir in ("/usr/include", "/usr/local/include"):
            if Path(inc_dir, self._header).exists():
                return [DepStatus(self.name, self.category, True, path=str(Path(inc_dir, self._header)))]
        return [DepStatus(self.name, self.category, False, install_hint=self.install_hint)]
