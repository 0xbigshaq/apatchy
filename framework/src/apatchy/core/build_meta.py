"""Persistent build metadata for the root and branch trees.

``BuildMeta`` captures everything about how a tree was configured and
compiled: sanitizer choices, compiler flags, config hash, and httpd
version.  It is serialized to ``.apatchy_build.json`` inside each tree
so that branches can inherit sanitizer state from the root and CLI
commands like ``apatchy info`` can display the build configuration.
"""

import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Optional

_FILENAME = ".apatchy_build.json"


@dataclass
class BuildMeta:
    """Persistent build metadata for a tree (root or branch)."""

    tree: str  # "vanilla" | "lf" | "cov"
    cc: str = "clang"
    cflags: str = ""
    ldflags: str = ""
    asan: bool = False
    ubsan: bool = False
    ubsan_ignorelist: Optional[str] = None
    intsan: bool = False
    truncsan: bool = False
    httpd_version: str = ""
    config_hash: str = ""

    def save(self, tree_root: Path) -> Path:
        """Write metadata to ``.apatchy_build.json`` inside *tree_root*."""
        path = tree_root / _FILENAME
        path.write_text(json.dumps(asdict(self), indent=2) + "\n")
        return path

    @classmethod
    def load(cls, tree_root: Path) -> "BuildMeta":
        """Load metadata from *tree_root*, raising if absent."""
        path = tree_root / _FILENAME
        if not path.exists():
            raise FileNotFoundError(f"No build metadata found at {path}")
        data = json.loads(path.read_text())
        known = {f.name for f in cls.__dataclass_fields__.values()}
        filtered = {k: v for k, v in data.items() if k in known}
        return cls(**filtered)

    @classmethod
    def exists(cls, tree_root: Path) -> bool:
        """Return True if *tree_root* contains a metadata file."""
        return (tree_root / _FILENAME).is_file()
