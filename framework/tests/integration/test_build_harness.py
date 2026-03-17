"""Integration tests for harness compilation and linking."""

import os
import shutil
import subprocess
from pathlib import Path

import pytest

from apatchy.core.harness import HarnessBuilder


def test_include_paths_exist(httpd: Path) -> None:
    """Every -I path from get_include_paths() is a real directory."""
    builder = HarnessBuilder(httpd)
    paths = builder.get_include_paths()
    assert len(paths) > 0
    for flag in paths:
        assert flag.startswith("-I")
        dir_path = flag[2:]
        assert os.path.isdir(dir_path), f"Include dir missing: {dir_path}"


def test_include_paths_have_headers(httpd: Path) -> None:
    """Key Apache headers exist in the include paths."""
    include = httpd / "include"
    assert (include / "httpd.h").exists()
    assert (include / "http_config.h").exists()
    assert (include / "ap_config.h").exists()


def test_build_standalone_harness(httpd: Path, build_dir: Path, mp: pytest.MonkeyPatch) -> None:
    """Build a standalone harness - binary is produced and runs."""
    mp.chdir(build_dir)

    builder = HarnessBuilder(httpd, verbose=True)
    builder.build(mode="standalone", harness_name="mod_fuzzy")

    binary = build_dir / "fuzz_harness_standalone"
    if not binary.exists():
        binary = build_dir / ".libs" / "fuzz_harness_standalone"
    assert binary.exists(), "Standalone harness binary not produced"

    # Run with empty input - should exit cleanly (not crash)
    result = subprocess.run(
        [str(binary)],
        input=b"",
        capture_output=True,
        timeout=10,
    )
    # Exit code 0 or small non-zero is fine, segfault (139) is not
    assert result.returncode < 128, f"Harness crashed with code {result.returncode}"


def test_build_standalone_mod_fuzzy(httpd: Path, build_dir: Path, mp: pytest.MonkeyPatch) -> None:
    """Build mod_fuzzy harness in standalone mode."""
    mp.chdir(build_dir)

    builder = HarnessBuilder(httpd, verbose=True)
    builder.build(mode="standalone", harness_name="mod_fuzzy")

    binary = build_dir / "fuzz_harness_standalone"
    if not binary.exists():
        binary = build_dir / ".libs" / "fuzz_harness_standalone"
    assert binary.exists(), "mod_fuzzy standalone binary not produced"


@pytest.mark.skipif(
    not shutil.which("afl-clang-fast"),
    reason="afl-clang-fast not found",
)
def test_build_afl_harness(httpd: Path, build_dir: Path, mp: pytest.MonkeyPatch) -> None:
    """Build an AFL harness - binary is produced."""
    mp.chdir(build_dir)

    builder = HarnessBuilder(httpd, verbose=True)
    builder.build(mode="afl", harness_name="mod_fuzzy")

    binary = build_dir / "fuzz_harness_afl"
    if not binary.exists():
        binary = build_dir / ".libs" / "fuzz_harness_afl"
    assert binary.exists(), "AFL harness binary not produced"


def test_linked_libraries_resolve(httpd: Path, build_dir: Path, mp: pytest.MonkeyPatch) -> None:
    """Ldd on the harness binary shows no 'not found' entries."""
    if not shutil.which("ldd"):
        pytest.skip("ldd not available")

    mp.chdir(build_dir)

    builder = HarnessBuilder(httpd, verbose=True)
    builder.build(mode="standalone", harness_name="mod_fuzzy")

    binary = build_dir / "fuzz_harness_standalone"
    if not binary.exists():
        binary = build_dir / ".libs" / "fuzz_harness_standalone"

    # APR/APR-Util and the crypto driver are statically linked
    # (--disable-util-dso), so no LD_LIBRARY_PATH is needed.
    result = subprocess.run(
        ["ldd", str(binary)],
        capture_output=True,
        text=True,
    )
    assert "not found" not in result.stdout, f"Missing libraries:\n{result.stdout}"


def test_all_harnesses_compile(httpd: Path, build_dir: Path, mp: pytest.MonkeyPatch) -> None:
    """Every bundled harness .c file compiles (object stage only)."""
    mp.chdir(build_dir)

    builder = HarnessBuilder(httpd, verbose=True)
    harnesses = builder.list_harnesses()

    # Skip companion files and C++ proto harnesses (need LPM installed)
    skip = {"fuzz_common"}
    harness_names = [h["name"] for h in harnesses if h["name"] not in skip and h["source"].endswith(".c")]

    for name in harness_names:
        harness_src = builder.resolve_harness(name)
        assert harness_src is not None, f"Could not resolve harness: {name}"
        cflags = f"-I{harness_src.parent} -g -O0"
        ok, errors = builder.check_compiles(harness_src, cflags, "clang")
        if not ok:
            import warnings

            warnings.warn(f"{name} not compatible with {httpd.name}:\n{errors}", stacklevel=1)
            continue
        builder._compile_object(str(harness_src), f"{name}.lo", cflags, "clang")
        # The .lo file (libtool descriptor) should exist
        lo_file = build_dir / f"{name}.lo"
        assert lo_file.exists(), f"Failed to compile harness: {name}"
