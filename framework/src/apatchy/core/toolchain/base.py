from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional


@dataclass
class DepStatus:  # noqa: D101
    name: str
    category: str
    found: bool
    version: str = ""
    path: str = ""
    install_hint: str = ""


class ToolchainTool(ABC):
    """Base class for all toolchain tools. Subclasses must implement check()."""

    name: str

    def __init__(self, toolchain_dir: Path, verbose: bool = False) -> None:
        self.toolchain_dir = toolchain_dir
        self.verbose = verbose

    def detect(self) -> Optional[str]:
        """Return the installed version string, or None if not found."""
        return None

    @abstractmethod
    def check(self) -> List[DepStatus]:
        """Return the full status of all sub-tools. Used by `apatchy setup check`."""
        ...

    def setup(self, force: bool = False, **kwargs) -> None:
        """Install or configure the tool. Override in subclasses that support it."""
        from apatchy.utils.logger import get_logger

        get_logger(__name__).warning(f"No automatic setup available for {self.name}")
