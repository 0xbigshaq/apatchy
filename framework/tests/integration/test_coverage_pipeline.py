"""Integration tests for the coverage pipeline.

These tests verify that:
- A coverage build tree can be created separately
- Coverage-instrumented harness compiles and links
- llvm-profdata/llvm-cov are detected correctly
"""

import shutil
from pathlib import Path

import pytest

from apatchy.managers.config_manager import ConfigManager
from apatchy.managers.report_manager import ReportManager
from apatchy.utils.build_tree import AlternateBuildTree



def test_detect_llvm_toolchain(httpd: Path) -> None:
    """_detect_llvm_toolchain finds a matched clang/profdata/cov triple."""
    cm = ConfigManager(build_mode="coverage")
    rm = ReportManager(httpd, cm)

    try:
        profdata, cov, cc = rm._detect_llvm_toolchain()
    except FileNotFoundError:
        pytest.skip("No matched LLVM toolchain found")

    assert "profdata" in profdata
    assert "cov" in cov
    assert "clang" in cc




def test_find_afl_instances_single(httpd: Path, build_dir: Path) -> None:
    """Detect single-instance AFL output layout."""
    cm = ConfigManager()
    rm = ReportManager(httpd, cm)

    # Create fake single-instance layout
    (build_dir / "default" / "queue").mkdir(parents=True)
    (build_dir / "default" / "queue" / "id:000000").touch()

    instances = rm._find_afl_instances(str(build_dir))
    assert len(instances) == 1
    assert instances[0].name == "default"


def test_find_afl_instances_parallel(httpd: Path, build_dir: Path) -> None:
    """Detect parallel AFL output layout."""
    cm = ConfigManager()
    rm = ReportManager(httpd, cm)

    # Create fake parallel layout
    for name in ("main01", "sec01", "sec02"):
        (build_dir / name / "queue").mkdir(parents=True)
        (build_dir / name / "queue" / "id:000000").touch()

    instances = rm._find_afl_instances(str(build_dir))
    assert len(instances) == 3
    names = {i.name for i in instances}
    assert names == {"main01", "sec01", "sec02"}


def test_find_afl_instances_empty(httpd: Path, tmp_path: Path) -> None:
    """No instances found in empty directory."""
    cm = ConfigManager()
    rm = ReportManager(httpd, cm)

    instances = rm._find_afl_instances(str(tmp_path))
    assert len(instances) == 0




def test_alternate_build_tree_creation(httpd: Path, work_dir: Path) -> None:
    """AlternateBuildTree creates a -cov copy with rewritten paths."""
    tree = AlternateBuildTree(httpd, "-test-cov")

    # Clean up any previous test tree
    if tree.alt_root.exists():
        shutil.rmtree(tree.alt_root)

    tree._ensure_tree()
    try:
        assert tree.alt_root.exists()
        assert (tree.alt_root / "configure").exists()
        assert (tree.alt_root / "modules").is_dir()

        # Verify paths were rewritten in Makefile
        makefile = tree.alt_root / "Makefile"
        if makefile.exists():
            text = makefile.read_text()
            assert str(tree.alt_root.resolve()) in text
    finally:
        # Clean up the test tree
        if tree.alt_root.exists():
            shutil.rmtree(tree.alt_root)


def test_afl_config_hash_deterministic(httpd: Path) -> None:
    """afl_config_hash returns consistent hash for the same config."""
    h1 = AlternateBuildTree.afl_config_hash(httpd)
    h2 = AlternateBuildTree.afl_config_hash(httpd)
    assert h1 == h2
    assert len(h1) == 64  # SHA-256 hex
