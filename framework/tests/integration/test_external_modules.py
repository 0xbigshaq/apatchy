"""Integration tests for external module (DSO) builds."""

from pathlib import Path

import pytest

from apatchy.config import Config
from apatchy.managers.module_manager import ModuleManager


def test_list_modules(httpd: Path) -> None:
    """list_modules() returns at least one module."""
    mm = ModuleManager(httpd)
    modules = mm.list_modules()
    assert len(modules) > 0
    assert modules[0]["name"] == "mod_pwn"


def test_build_single_module(httpd: Path, build_dir: Path, mp: pytest.MonkeyPatch) -> None:
    """Build mod_pwn as a shared object."""
    mp.chdir(build_dir)

    mm = ModuleManager(httpd)
    mm.work_dir = build_dir
    mm.modules_out = build_dir / "modules"

    mm.build_module("mod_pwn", cc="clang")

    so_file = mm.modules_out / "mod_pwn.so"
    assert so_file.exists(), "mod_pwn.so not produced"
    assert so_file.stat().st_size > 0


def test_build_all_modules(httpd: Path, build_dir: Path, mp: pytest.MonkeyPatch) -> None:
    """Build all external modules (name=None)."""
    mp.chdir(build_dir)

    mm = ModuleManager(httpd)
    mm.work_dir = build_dir
    mm.modules_out = build_dir / "modules"

    mm.build_module(name=None, cc="clang")

    # Every .c in external_modules/ should have a corresponding .so
    sources = list(Config.EXTERNAL_MODULES_DIR.glob("*.c"))
    for src in sources:
        so_file = mm.modules_out / f"{src.stem}.so"
        assert so_file.exists(), f"{src.stem}.so not built"


def test_sanitizer_flags_extracted(httpd: Path) -> None:
    """_get_sanitizer_flags reads real config_vars.mk."""
    mm = ModuleManager(httpd)
    flags = mm._get_sanitizer_flags()

    # The configured_apache fixture uses --asan, so we expect sanitizer flags
    assert isinstance(flags, list)
    # At minimum, ASan should be present (from our fixture's configure)
    san_str = " ".join(flags)
    assert "-fsanitize=address" in san_str, f"Expected ASan in flags, got: {flags}"
