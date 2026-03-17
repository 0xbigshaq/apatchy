"""Tests for apatchy.config.Config."""

from pathlib import Path

from apatchy.config import Config


def test_project_root_is_absolute():
    """PROJECT_ROOT is an absolute path."""
    assert Config.PROJECT_ROOT.is_absolute()


def test_work_dir_is_absolute():
    """WORK_DIR is an absolute path."""
    assert Config.WORK_DIR.is_absolute()


def test_src_dir_is_absolute():
    """SRC_DIR is an absolute path."""
    assert Config.SRC_DIR.is_absolute()


def test_toolchain_dir_is_absolute():
    """TOOLCHAIN_DIR is an absolute path."""
    assert Config.TOOLCHAIN_DIR.is_absolute()


def test_get_apache_dir_with_version():
    """get_apache_dir() returns WORK_DIR/httpd-{version}."""
    result = Config.get_apache_dir("2.4.58")
    assert result == Config.WORK_DIR / "httpd-2.4.58"


def test_get_apache_dir_returns_path():
    """get_apache_dir() returns a Path object."""
    result = Config.get_apache_dir("2.4.62")
    assert isinstance(result, Path)


def test_default_apache_version_format():
    """DEFAULT_APACHE_VERSION is a valid X.Y.Z string."""
    v = Config.DEFAULT_APACHE_VERSION
    parts = v.split(".")
    assert len(parts) == 3
    assert all(p.isdigit() for p in parts)


def test_mirror_url_is_https():
    """APACHE_MIRROR uses HTTPS."""
    assert Config.APACHE_MIRROR.startswith("https://")


def test_archive_url_is_https():
    """APACHE_ARCHIVE uses HTTPS."""
    assert Config.APACHE_ARCHIVE.startswith("https://")


def test_harnesses_dir_exists():
    """HARNESSES_DIR exists on disk."""
    assert Config.HARNESSES_DIR.is_dir()
