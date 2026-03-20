"""Tests for apatchy.core.build_meta.BuildMeta."""

import pytest

from apatchy.core.build_meta import BuildMeta


def test_save_and_load(tmp_path):
    """BuildMeta round-trips through JSON."""
    meta = BuildMeta(
        tree="vanilla",
        cc="clang",
        cflags="-g -O0",
        ldflags="-no-pie",
        asan=True,
        ubsan=False,
        httpd_version="2.4.65",
        config_hash="abc123",
    )
    meta.save(tmp_path)
    loaded = BuildMeta.load(tmp_path)
    assert loaded.tree == "vanilla"
    assert loaded.asan is True
    assert loaded.ubsan is False
    assert loaded.cflags == "-g -O0"
    assert loaded.httpd_version == "2.4.65"
    assert loaded.config_hash == "abc123"


def test_exists_true(tmp_path):
    """exists() returns True when metadata file is present."""
    meta = BuildMeta(tree="lf")
    meta.save(tmp_path)
    assert BuildMeta.exists(tmp_path) is True


def test_exists_false(tmp_path):
    """exists() returns False when no metadata file."""
    assert BuildMeta.exists(tmp_path) is False


def test_load_missing_raises(tmp_path):
    """load() raises FileNotFoundError when file is missing."""
    with pytest.raises(FileNotFoundError):
        BuildMeta.load(tmp_path)


def test_load_ignores_unknown_fields(tmp_path):
    """load() ignores extra fields in JSON (forward compat)."""
    import json

    data = {"tree": "cov", "cc": "clang", "future_field": "ignored"}
    (tmp_path / ".apatchy_build.json").write_text(json.dumps(data))
    loaded = BuildMeta.load(tmp_path)
    assert loaded.tree == "cov"
    assert not hasattr(loaded, "future_field")
