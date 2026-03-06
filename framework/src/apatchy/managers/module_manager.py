"""Build external Apache modules as shared objects (``.so`` DSOs).

:class:`ModuleManager` compiles C source files from the bundled
``external_modules/`` directory with the same sanitizer flags as the
main Apache build, producing ``.so`` files that Apache can ``LoadModule``
at runtime.
"""

import shutil
import subprocess
from pathlib import Path
from typing import List, Optional

from apatchy.config import Config
from apatchy.core import toolchain_config
from apatchy.utils.logger import get_logger

logger = get_logger(__name__)


class ModuleManager:
    """Builds external Apache modules as DSOs (.so) for runtime loading."""

    def __init__(self, httpd_root: Path) -> None:
        self.httpd_root = httpd_root
        self.work_dir = Config.WORK_DIR
        self.modules_out = self.work_dir / "modules"

    def list_modules(self) -> List[dict]:
        """List available external module sources."""
        modules = []
        for src in sorted(Config.EXTERNAL_MODULES_DIR.glob("*.c")):
            name = src.stem  # e.g. "mod_pwn"
            built_so = self.modules_out / f"{name}.so"
            modules.append(
                {
                    "name": name,
                    "source": str(src),
                    "built": str(built_so) if built_so.exists() else "",
                }
            )
        return modules

    def build_module(self, name: Optional[str] = None, cc: Optional[str] = None) -> None:
        """Build one or all external modules as shared objects."""
        if name:
            src = Config.EXTERNAL_MODULES_DIR / f"{name}.c"
            if not src.exists():
                # Try without mod_ prefix
                src = Config.EXTERNAL_MODULES_DIR / f"mod_{name}.c"
            if not src.exists():
                logger.error(f"Module source not found: {name}")
                logger.info("Available modules:")
                for m in self.list_modules():
                    logger.info(f"  {m['name']}")
                return
            self._build_one(src, cc=cc)
        else:
            sources = list(Config.EXTERNAL_MODULES_DIR.glob("*.c"))
            if not sources:
                logger.error("No external module sources found.")
                return
            for src in sources:
                self._build_one(src, cc=cc)

    def _get_sanitizer_flags(self) -> List[str]:
        """Extract -fsanitize= flags from the Apache build's config_vars.mk."""
        config_vars = self.httpd_root / "build" / "config_vars.mk"
        flags = []
        if not config_vars.exists():
            return flags
        for line in config_vars.read_text().splitlines():
            key, _, value = line.partition("=")
            if key.strip() in ("CFLAGS", "LDFLAGS"):
                for token in value.split():
                    if token.startswith("-fsanitize=") and token not in flags:
                        flags.append(token)
        return flags

    def _build_one(self, src: Path, cc: Optional[str] = None) -> None:
        """Compile a single .c file into a .so DSO."""
        name = src.stem  # e.g. "mod_pwn"
        self.modules_out.mkdir(exist_ok=True)
        output = self.modules_out / f"{name}.so"

        if cc is None:
            # Default: use afl-clang-fast for instrumented builds, fall back to clang/gcc.
            # Prefer toolchain config paths over system PATH.
            cc = (
                toolchain_config.resolve_tool("afl-clang-fast")
                or toolchain_config.resolve_tool("clang")
                or shutil.which("gcc")
            )
        else:
            cc = toolchain_config.resolve_tool(cc) or shutil.which(cc) or cc

        if not cc:
            logger.error("No C compiler found (afl-clang-fast, clang, or gcc)")
            return

        includes = [
            f"-I{self.httpd_root}/include",
            f"-I{self.httpd_root}/srclib/apr/include",
            f"-I{self.httpd_root}/srclib/apr-util/include",
            f"-I{self.httpd_root}/os/unix",
            f"-I{self.httpd_root}/server",
        ]

        # Add module subdirectories as includes
        modules_dir = self.httpd_root / "modules"
        if modules_dir.exists():
            for p in modules_dir.iterdir():
                if p.is_dir():
                    includes.append(f"-I{p}")

        # Propagate sanitizer flags from the Apache build so external
        # modules are instrumented the same way as the harness.
        sanitizer_flags = self._get_sanitizer_flags()

        cmd = [
            cc,
            "-fPIC",
            "-shared",
            "-g",
            "-O0",
            *sanitizer_flags,
            "-o",
            str(output),
            str(src),
            *includes,
        ]

        logger.info(f"Building {name}.so with {Path(cc).name} ...")
        try:
            subprocess.run(cmd, check=True)
            logger.info(f"Built: {output}")
        except subprocess.CalledProcessError:
            logger.error(f"Failed to build {name}.so")
