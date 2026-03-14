"""Integration tests for Apache configure and compile."""

import re
from pathlib import Path

from apatchy.core.harness import HarnessBuilder


def test_config_vars_generated(httpd_configured: Path) -> None:
    """Configure produces build/config_vars.mk."""
    config_vars = httpd_configured / "build" / "config_vars.mk"
    assert config_vars.exists()
    assert config_vars.stat().st_size > 0


def test_config_vars_has_cc(httpd_configured: Path) -> None:
    """config_vars.mk defines a CC variable."""
    config_vars = httpd_configured / "build" / "config_vars.mk"
    text = config_vars.read_text()
    assert re.search(r"^CC\s*=", text, re.MULTILINE)


def test_config_vars_has_cflags(httpd_configured: Path) -> None:
    """config_vars.mk defines CFLAGS."""
    config_vars = httpd_configured / "build" / "config_vars.mk"
    text = config_vars.read_text()
    assert re.search(r"^CFLAGS\s*=", text, re.MULTILINE)


def test_config_status_generated(httpd_configured: Path) -> None:
    """Configure produces config.status."""
    assert (httpd_configured / "config.status").exists()


def test_session_modules_enabled(httpd_configured: Path) -> None:
    """Session and crypto modules are enabled in the build."""
    config_status = (httpd_configured / "config.status").read_text()
    # The configure flags should include session-related options
    assert "session" in config_status.lower()


def test_httpd_binary_exists(httpd: Path) -> None:
    """Make produces the httpd binary."""
    assert (httpd / "httpd").exists()


def test_module_libraries_built(httpd: Path) -> None:
    """Static module .la files are produced."""
    modules = httpd / "modules"
    la_files = list(modules.rglob("libmod_*.la"))
    # Filter out .libs/ duplicates
    la_files = [f for f in la_files if ".libs" not in str(f)]
    assert len(la_files) > 10, f"Expected many modules, got {len(la_files)}"


def test_apr_built(httpd: Path) -> None:
    """APR library is built."""
    apr_lib = httpd / "srclib" / "apr" / "libapr-1.la"
    assert apr_lib.exists()


def test_apr_util_built(httpd: Path) -> None:
    """APR-Util library is built."""
    aprutil_lib = httpd / "srclib" / "apr-util" / "libaprutil-1.la"
    assert aprutil_lib.exists()


def test_parse_config_vars_real(httpd: Path) -> None:
    """HarnessBuilder._parse_config_vars works on the real file."""
    builder = HarnessBuilder(httpd)
    config_vars = builder._parse_config_vars()

    assert isinstance(config_vars, dict)
    assert "CC" in config_vars
    assert "CFLAGS" in config_vars
    assert len(config_vars) > 10


def test_get_system_libs_real(httpd: Path) -> None:
    """HarnessBuilder._get_system_libs extracts real library flags."""
    builder = HarnessBuilder(httpd)
    config_vars = builder._parse_config_vars()
    libs = builder._get_system_libs(config_vars)

    assert isinstance(libs, list)
    # Should find at least PCRE libs
    lib_str = " ".join(libs)
    assert "-l" in lib_str or "pcre" in lib_str.lower()
