"""Tests for apatchy.compat version-aware build compatibility."""

from pathlib import Path

from apatchy.compat import (
    CompatEntry,
    _parse_version,
    extract_version_from_path,
    get_compat_flags,
)

# --- _parse_version ---

def test_parse_version_three_parts():
    """_parse_version handles standard X.Y.Z strings."""
    assert _parse_version("2.4.52") == (2, 4, 52)


def test_parse_version_large_patch():
    """_parse_version handles large patch numbers."""
    assert _parse_version("2.4.999") == (2, 4, 999)


def test_parse_version_single_digit():
    """_parse_version handles single-digit components."""
    assert _parse_version("1.0.0") == (1, 0, 0)


# --- extract_version_from_path ---

def test_extract_version_standard():
    """extract_version_from_path parses httpd-X.Y.Z directory names."""
    result = extract_version_from_path(Path("/some/path/httpd-2.4.52"))
    assert result == "2.4.52"


def test_extract_version_suffixed():
    """extract_version_from_path handles -cov and -standalone suffixes."""
    assert extract_version_from_path(Path("/path/httpd-2.4.62-cov")) == "2.4.62"
    assert extract_version_from_path(Path("/path/httpd-2.4.62-standalone")) == "2.4.62"


def test_extract_version_non_httpd():
    """extract_version_from_path returns None for non-httpd directories."""
    assert extract_version_from_path(Path("/path/something-else")) is None


def test_extract_version_no_version():
    """extract_version_from_path returns None for plain 'httpd' directory."""
    assert extract_version_from_path(Path("/path/httpd")) is None


# --- get_compat_flags: OpenSSL 3.0 entry ---

def test_openssl3_matches_old_version():
    """OpenSSL 3.0 compat entry matches httpd 2.4.52."""
    result = get_compat_flags("2.4.52")
    assert "openssl3-deprecations" in result.applied_ids
    assert "-Wno-error=deprecated-declarations" in result.cflags


def test_openssl3_matches_boundary():
    """OpenSSL 3.0 compat entry matches httpd 2.4.58 (inclusive upper bound)."""
    result = get_compat_flags("2.4.58")
    assert "openssl3-deprecations" in result.applied_ids


def test_openssl3_skips_new_version():
    """OpenSSL 3.0 compat entry does not match httpd 2.4.62."""
    result = get_compat_flags("2.4.62")
    assert "openssl3-deprecations" not in result.applied_ids
    assert "-Wno-error=deprecated-declarations" not in result.cflags


def test_no_matches_returns_empty():
    """get_compat_flags returns empty lists when nothing matches."""
    result = get_compat_flags("99.99.99")
    assert result.cflags == []
    assert result.ldflags == []
    assert result.configure_args == []
    assert result.applied_ids == []


# --- CompatEntry with min_version ---

def test_min_version_excludes_older():
    """An entry with min_version excludes versions below it."""
    entry = CompatEntry(
        id="test-min",
        description="test",
        min_version="2.4.50",
        max_version="2.4.55",
        cflags=["-Wtest"],
    )
    from apatchy import compat
    original = list(compat.COMPAT_REGISTRY)
    try:
        compat.COMPAT_REGISTRY.append(entry)
        assert "test-min" not in get_compat_flags("2.4.49").applied_ids
        assert "test-min" in get_compat_flags("2.4.50").applied_ids
        assert "test-min" in get_compat_flags("2.4.53").applied_ids
        assert "test-min" in get_compat_flags("2.4.55").applied_ids
        assert "test-min" not in get_compat_flags("2.4.56").applied_ids
    finally:
        compat.COMPAT_REGISTRY[:] = original


# --- ConfigManager integration ---

def test_generate_build_config_with_version():
    """ConfigManager applies compat flags when httpd_version is given."""
    from apatchy.managers.config_manager import ConfigManager
    cm = ConfigManager(build_mode="fuzz")
    result = cm.generate_build_config(httpd_version="2.4.52")
    assert "-Wno-error=deprecated-declarations" in result["CFLAGS"]


def test_generate_build_config_without_version():
    """ConfigManager omits compat flags when no version is given."""
    from apatchy.managers.config_manager import ConfigManager
    cm = ConfigManager(build_mode="fuzz")
    result = cm.generate_build_config()
    assert "-Wno-error=deprecated-declarations" not in result["CFLAGS"]


def test_generate_build_config_new_version_no_compat():
    """ConfigManager does not add compat flags for versions past the range."""
    from apatchy.managers.config_manager import ConfigManager
    cm = ConfigManager(build_mode="fuzz")
    result = cm.generate_build_config(httpd_version="2.4.62")
    assert "-Wno-error=deprecated-declarations" not in result["CFLAGS"]
