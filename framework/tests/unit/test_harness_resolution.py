"""Tests for harness listing and resolution in apatchy.core.harness."""

from pathlib import Path

from apatchy.config import Config
from apatchy.core.harness import COMPILERS, HarnessBuilder

# --- COMPILERS mapping ---


def test_compilers_afl():
    """COMPILERS maps 'afl' to afl-clang-fast."""
    assert COMPILERS["afl"] == "afl-clang-fast"


def test_compilers_libfuzzer():
    """COMPILERS maps 'libfuzzer' to clang."""
    assert COMPILERS["libfuzzer"] == "clang"


def test_compilers_standalone():
    """COMPILERS maps 'standalone' to clang."""
    assert COMPILERS["standalone"] == "clang"


def test_compilers_coverage():
    """COMPILERS maps 'coverage' to clang."""
    assert COMPILERS["coverage"] == "clang"


# --- list_harnesses ---


def test_list_harnesses_returns_list():
    """list_harnesses() returns a non-empty list."""
    harnesses = HarnessBuilder.list_harnesses()
    assert isinstance(harnesses, list)
    assert len(harnesses) > 0


def test_list_harnesses_has_name_and_source():
    """Each harness entry has name, source, and description keys."""
    harnesses = HarnessBuilder.list_harnesses()
    for h in harnesses:
        assert "name" in h
        assert "source" in h
        assert "description" in h


def test_list_harnesses_contains_known():
    """list_harnesses() includes mod_fuzzy and mod_fuzzy_deflate."""
    harnesses = HarnessBuilder.list_harnesses()
    names = [h["name"] for h in harnesses]
    assert "mod_fuzzy" in names
    assert "mod_fuzzy_deflate" in names


def test_list_harnesses_sources_are_c_files():
    """All harness source paths end in .c."""
    harnesses = HarnessBuilder.list_harnesses()
    for h in harnesses:
        assert h["source"].endswith(".c")


# --- resolve_harness ---


def test_resolve_harness_by_name():
    """resolve_harness('mod_fuzzy') finds mod_fuzzy.c."""
    result = HarnessBuilder.resolve_harness("mod_fuzzy")
    assert result is not None
    assert result.name == "mod_fuzzy.c"
    assert result.exists()


def test_resolve_harness_mod_fuzzy():
    """resolve_harness('mod_fuzzy') finds the harness."""
    result = HarnessBuilder.resolve_harness("mod_fuzzy")
    assert result is not None
    assert result.exists()


def test_resolve_harness_nonexistent():
    """resolve_harness() returns None for unknown harness."""
    result = HarnessBuilder.resolve_harness("nonexistent_harness_xyz")
    assert result is None


def test_resolve_harness_returns_path():
    """resolve_harness() returns a Path instance."""
    result = HarnessBuilder.resolve_harness("mod_fuzzy")
    assert isinstance(result, Path)


def test_resolve_harness_literal_path():
    """resolve_harness() accepts a literal file path."""
    known = Config.HARNESSES_DIR / "mod_fuzzy.c"
    result = HarnessBuilder.resolve_harness(str(known))
    assert result is not None
    assert result.exists()
