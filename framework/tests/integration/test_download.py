"""Integration tests for Apache HTTPD download and extraction."""

from pathlib import Path


def test_source_dir_exists(httpd_src: Path) -> None:
    """Downloaded source directory exists."""
    assert httpd_src.exists()
    assert httpd_src.is_dir()


def test_configure_script_present(httpd_src: Path) -> None:
    """The autoconf configure script is in the source root."""
    assert (httpd_src / "configure").exists()


def test_modules_dir_present(httpd_src: Path) -> None:
    """The modules/ directory exists with subdirectories."""
    modules = httpd_src / "modules"
    assert modules.is_dir()
    subdirs = [d for d in modules.iterdir() if d.is_dir()]
    assert len(subdirs) > 0


def test_server_dir_present(httpd_src: Path) -> None:
    """The server/ directory exists (contains main.c, etc.)."""
    assert (httpd_src / "server").is_dir()


def test_apr_dependency(httpd_src: Path) -> None:
    """APR source is present in srclib/apr."""
    apr = httpd_src / "srclib" / "apr"
    assert apr.is_dir()
    assert (apr / "configure").exists()


def test_apr_util_dependency(httpd_src: Path) -> None:
    """APR-Util source is present in srclib/apr-util."""
    apr_util = httpd_src / "srclib" / "apr-util"
    assert apr_util.is_dir()
    assert (apr_util / "configure").exists()


def test_expat_dependency(httpd_src: Path) -> None:
    """Bundled Expat is present in srclib/apr-util/xml/expat."""
    expat = httpd_src / "srclib" / "apr-util" / "xml" / "expat"
    assert expat.is_dir()


def test_redownload_skipped(httpd_src: Path, work_dir: Path) -> None:
    """Calling download_apache again is a no-op."""
    from apatchy.core.downloader import Downloader

    dl = Downloader()
    dl.work_dir = work_dir

    version = httpd_src.name.replace("httpd-", "")
    result = dl.download_apache(version=version)
    assert result == httpd_src
