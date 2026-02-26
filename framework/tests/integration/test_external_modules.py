"""Integration tests for external module (DSO) builds."""

import shutil

import pytest

from apatchy.config import Config
from apatchy.managers.module_manager import ModuleManager


def test_list_modules(compiled_apache):
    """list_modules() returns at least one module."""
    mm = ModuleManager(compiled_apache)
    modules = mm.list_modules()
    assert len(modules) > 0
    assert modules[0]["name"] == "mod_pwn"


def test_build_single_module(compiled_apache, harness_build_dir, monkeypatch):
    """Build mod_pwn as a shared object."""
    monkeypatch.chdir(harness_build_dir)

    mm = ModuleManager(compiled_apache)
    mm.work_dir = harness_build_dir
    mm.modules_out = harness_build_dir / "modules"

    # Use clang directly (don't require afl-clang-fast for this test)
    mm.build_module("mod_pwn", cc="clang")

    so_file = mm.modules_out / "mod_pwn.so"
    assert so_file.exists(), "mod_pwn.so not produced"
    assert so_file.stat().st_size > 0


@pytest.mark.skipif(
    not shutil.which("afl-clang-fast"),
    reason="afl-clang-fast not found",
)
def test_build_module_with_afl(compiled_apache, harness_build_dir, monkeypatch):
    """Build mod_pwn with afl-clang-fast for instrumented fuzzing."""
    monkeypatch.chdir(harness_build_dir)

    mm = ModuleManager(compiled_apache)
    mm.work_dir = harness_build_dir
    mm.modules_out = harness_build_dir / "modules"

    mm.build_module("mod_pwn", cc="afl-clang-fast")

    so_file = mm.modules_out / "mod_pwn.so"
    assert so_file.exists()


def test_build_all_modules(compiled_apache, harness_build_dir, monkeypatch):
    """Build all external modules (name=None)."""
    monkeypatch.chdir(harness_build_dir)

    mm = ModuleManager(compiled_apache)
    mm.work_dir = harness_build_dir
    mm.modules_out = harness_build_dir / "modules"

    mm.build_module(name=None, cc="clang")

    # Every .c in external_modules/ should have a corresponding .so
    sources = list(Config.EXTERNAL_MODULES_DIR.glob("*.c"))
    for src in sources:
        so_file = mm.modules_out / f"{src.stem}.so"
        assert so_file.exists(), f"{src.stem}.so not built"


def test_sanitizer_flags_extracted(compiled_apache):
    """_get_sanitizer_flags reads real config_vars.mk."""
    mm = ModuleManager(compiled_apache)
    flags = mm._get_sanitizer_flags()

    # The configured_apache fixture uses --asan, so we expect sanitizer flags
    assert isinstance(flags, list)
    # At minimum, ASan should be present (from our fixture's configure)
    san_str = " ".join(flags)
    assert "-fsanitize=address" in san_str, f"Expected ASan in flags, got: {flags}"
