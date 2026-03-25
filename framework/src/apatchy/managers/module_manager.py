import subprocess
from pathlib import Path
from typing import List, Optional

from apatchy.config import Config
from apatchy.core import toolchain_config
from apatchy.utils.logger import get_logger

logger = get_logger(__name__)


class ModuleManager:
    """Build external Apache modules as shared objects (``.so``) for runtime loading.

    ``ModuleManager`` compiles custom C modules (e.g. ``mod_pwn.c``) into
    position-independent shared objects that Apache can load via
    ``LoadModule`` at runtime. Module sources live in the external modules
    directory and are compiled against the Apache build tree's headers.

    The compiler defaults to ``clang``, falling back to ``gcc`` if
    unavailable. A custom compiler can be specified via the ``cc`` argument.

    Sanitizer flags (``-fsanitize=...``) are automatically extracted from
    the Apache build's ``config_vars.mk`` and propagated to the module
    build, so modules are instrumented identically to the main binary.

    Built ``.so`` files are placed in ``<WORK_DIR>/modules/`` and can be
    referenced from an httpd config via ``LoadModule``.

    Args:
        httpd_root: Path to the Apache HTTPD source directory whose headers
            and build config are used for compilation.

    CLI usage:

    .. code-block:: bash

        # Build all external modules
        apatchy module build

        # Build a specific module
        apatchy module build mod_pwn

        # Build with a specific compiler
        apatchy module build mod_pwn --cc clang

        # List available modules and their build status
        apatchy module list

    Example:
        .. code-block:: python

            from pathlib import Path
            from apatchy.managers.module_manager import ModuleManager

            mm = ModuleManager(Path("httpd-2.4.58"))

            # Build all modules with default compiler
            mm.build_module()

            # Build a specific module
            mm.build_module(name="mod_pwn")

            # List what is available
            for m in mm.list_modules():
                print(f"{m['name']}  {m['built'] or '(not built)'}")
    """

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
        for d in sorted(Config.EXTERNAL_MODULES_DIR.iterdir()):
            if d.is_dir() and (d / "build.sh").exists():
                name = d.name
                built_so = self.modules_out / f"{name}.so"
                modules.append(
                    {
                        "name": name,
                        "source": str(d),
                        "built": str(built_so) if built_so.exists() else "",
                    }
                )
        return modules

    def build_module(self, name: Optional[str] = None, cc: Optional[str] = None) -> None:
        """Build one or all external modules as shared objects."""
        if name:
            src = Config.EXTERNAL_MODULES_DIR / f"{name}.c"
            if not src.exists():
                src = Config.EXTERNAL_MODULES_DIR / f"mod_{name}.c"
            if src.exists():
                self._build_one(src, cc=cc)
                return

            d = Config.EXTERNAL_MODULES_DIR / name
            if not d.is_dir():
                d = Config.EXTERNAL_MODULES_DIR / f"mod_{name}"
            if d.is_dir() and (d / "build.sh").exists():
                self._build_directory(d, cc=cc)
                return

            logger.error(f"Module source not found: {name}")
            logger.info("Available modules:")
            for m in self.list_modules():
                logger.info(f"  {m['name']}")
        else:
            found = False
            for src in sorted(Config.EXTERNAL_MODULES_DIR.glob("*.c")):
                self._build_one(src, cc=cc)
                found = True
            for d in sorted(Config.EXTERNAL_MODULES_DIR.iterdir()):
                if d.is_dir() and (d / "build.sh").exists():
                    self._build_directory(d, cc=cc)
                    found = True
            if not found:
                logger.error("No external module sources found.")

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
                    if token.startswith(("-fsanitize", "-fno-sanitize")) and token not in flags:
                        flags.append(token)
        return flags

    def _build_one(self, src: Path, cc: Optional[str] = None) -> None:
        """Compile a single .c file into a .so DSO."""
        name = src.stem  # e.g. "mod_pwn"
        self.modules_out.mkdir(exist_ok=True)
        output = self.modules_out / f"{name}.so"

        if cc is None:
            cc = toolchain_config.resolve_tool("clang") or toolchain_config.resolve_tool("gcc")
        else:
            cc = toolchain_config.resolve_tool(cc) or cc

        if not cc:
            logger.error("No C compiler found (clang or gcc)")
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

    def _build_directory(self, module_dir: Path, cc: Optional[str] = None) -> None:
        """Build a directory-based module by invoking its build.sh script."""
        name = module_dir.name
        self.modules_out.mkdir(exist_ok=True)
        output = self.modules_out / f"{name}.so"

        if cc is None:
            cc = toolchain_config.resolve_tool("clang") or toolchain_config.resolve_tool("gcc")
        else:
            cc = toolchain_config.resolve_tool(cc) or cc

        if not cc:
            logger.error("No C compiler found (clang or gcc)")
            return

        sanitizer_flags = self._get_sanitizer_flags()

        env = {
            **subprocess.os.environ,
            "HTTPD_ROOT": str(self.httpd_root),
            "CC": cc,
            "SANITIZER_FLAGS": " ".join(sanitizer_flags),
            "OUTPUT_DIR": str(self.modules_out),
            "MODULE_DIR": str(module_dir),
        }

        build_script = module_dir / "build.sh"
        logger.info(f"Building {name}.so via build.sh ...")
        try:
            subprocess.run(
                ["bash", str(build_script)],
                check=True,
                env=env,
                cwd=module_dir,
            )
        except subprocess.CalledProcessError:
            logger.error(f"build.sh failed for {name}")
            return

        if output.exists():
            logger.info(f"Built: {output}")
        else:
            logger.error(f"build.sh completed but {name}.so was not produced")
