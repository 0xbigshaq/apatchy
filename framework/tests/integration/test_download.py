"""Integration tests for Apache HTTPD download and extraction."""


def test_source_dir_exists(apache_source):
    """Downloaded source directory exists."""
    assert apache_source.exists()
    assert apache_source.is_dir()


def test_configure_script_present(apache_source):
    """The autoconf configure script is in the source root."""
    assert (apache_source / "configure").exists()


def test_modules_dir_present(apache_source):
    """The modules/ directory exists with subdirectories."""
    modules = apache_source / "modules"
    assert modules.is_dir()
    subdirs = [d for d in modules.iterdir() if d.is_dir()]
    assert len(subdirs) > 0


def test_server_dir_present(apache_source):
    """The server/ directory exists (contains main.c, etc.)."""
    assert (apache_source / "server").is_dir()


def test_apr_dependency(apache_source):
    """APR source is present in srclib/apr."""
    apr = apache_source / "srclib" / "apr"
    assert apr.is_dir()
    assert (apr / "configure").exists()


def test_apr_util_dependency(apache_source):
    """APR-Util source is present in srclib/apr-util."""
    apr_util = apache_source / "srclib" / "apr-util"
    assert apr_util.is_dir()
    assert (apr_util / "configure").exists()


def test_expat_dependency(apache_source):
    """Bundled Expat is present in srclib/apr-util/xml/expat."""
    expat = apache_source / "srclib" / "apr-util" / "xml" / "expat"
    assert expat.is_dir()


def test_redownload_skipped(apache_source, integration_work_dir):
    """Calling download_apache again is a no-op."""
    from apatchy.core.downloader import Downloader

    dl = Downloader()
    dl.work_dir = integration_work_dir

    version = apache_source.name.replace("httpd-", "")
    result = dl.download_apache(version=version)
    assert result == apache_source
