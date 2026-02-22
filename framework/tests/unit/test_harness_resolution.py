"""Tests for harness listing and resolution in apatchy.core.harness."""

from pathlib import Path

from apatchy.core.harness import HarnessBuilder, COMPILERS
from apatchy.config import Config


# --- COMPILERS mapping ---

def test_compilers_afl():
    assert COMPILERS["afl"] == "afl-clang-fast"


def test_compilers_libfuzzer():
    assert COMPILERS["libfuzzer"] == "clang"


def test_compilers_standalone():
    assert COMPILERS["standalone"] == "clang"


def test_compilers_coverage():
    assert COMPILERS["coverage"] == "clang"


# --- list_harnesses ---

def test_list_harnesses_returns_list():
    harnesses = HarnessBuilder.list_harnesses()
    assert isinstance(harnesses, list)
    assert len(harnesses) > 0


def test_list_harnesses_has_name_and_source():
    harnesses = HarnessBuilder.list_harnesses()
    for h in harnesses:
        assert "name" in h
        assert "source" in h
        assert "description" in h


def test_list_harnesses_contains_known():
    harnesses = HarnessBuilder.list_harnesses()
    names = [h["name"] for h in harnesses]
    # These harnesses exist in the repo
    assert "uri_parse" in names
    assert "full_pipeline" in names


def test_list_harnesses_sources_are_c_files():
    harnesses = HarnessBuilder.list_harnesses()
    for h in harnesses:
        assert h["source"].endswith(".c")


# --- resolve_harness ---

def test_resolve_harness_by_name():
    result = HarnessBuilder.resolve_harness("uri_parse")
    assert result is not None
    assert result.name == "uri_parse.c"
    assert result.exists()


def test_resolve_harness_full_pipeline():
    result = HarnessBuilder.resolve_harness("full_pipeline")
    assert result is not None
    assert result.exists()


def test_resolve_harness_nonexistent():
    result = HarnessBuilder.resolve_harness("nonexistent_harness_xyz")
    assert result is None


def test_resolve_harness_returns_path():
    result = HarnessBuilder.resolve_harness("uri_parse")
    assert isinstance(result, Path)


def test_resolve_harness_literal_path():
    """resolve_harness accepts a literal file path."""
    known = Config.HARNESSES_DIR / "uri_parse.c"
    result = HarnessBuilder.resolve_harness(str(known))
    assert result is not None
    assert result.exists()
