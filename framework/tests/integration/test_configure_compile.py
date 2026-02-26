"""Integration tests for Apache configure and compile."""

import re

from apatchy.core.harness import HarnessBuilder


def test_config_vars_generated(configured_apache):
    """Configure produces build/config_vars.mk."""
    config_vars = configured_apache / "build" / "config_vars.mk"
    assert config_vars.exists()
    assert config_vars.stat().st_size > 0


def test_config_vars_has_cc(configured_apache):
    """config_vars.mk defines a CC variable."""
    config_vars = configured_apache / "build" / "config_vars.mk"
    text = config_vars.read_text()
    assert re.search(r"^CC\s*=", text, re.MULTILINE)


def test_config_vars_has_cflags(configured_apache):
    """config_vars.mk defines CFLAGS."""
    config_vars = configured_apache / "build" / "config_vars.mk"
    text = config_vars.read_text()
    assert re.search(r"^CFLAGS\s*=", text, re.MULTILINE)


def test_config_status_generated(configured_apache):
    """Configure produces config.status."""
    assert (configured_apache / "config.status").exists()


def test_session_modules_enabled(configured_apache):
    """Session and crypto modules are enabled in the build."""
    config_status = (configured_apache / "config.status").read_text()
    # The configure flags should include session-related options
    assert "session" in config_status.lower()



def test_httpd_binary_exists(compiled_apache):
    """Make produces the httpd binary."""
    httpd = compiled_apache / "httpd"
    assert httpd.exists()


def test_module_libraries_built(compiled_apache):
    """Static module .la files are produced."""
    modules = compiled_apache / "modules"
    la_files = list(modules.rglob("libmod_*.la"))
    # Filter out .libs/ duplicates
    la_files = [f for f in la_files if ".libs" not in str(f)]
    assert len(la_files) > 10, f"Expected many modules, got {len(la_files)}"


def test_apr_built(compiled_apache):
    """APR library is built."""
    apr_lib = compiled_apache / "srclib" / "apr" / "libapr-1.la"
    assert apr_lib.exists()


def test_apr_util_built(compiled_apache):
    """APR-Util library is built."""
    aprutil_lib = compiled_apache / "srclib" / "apr-util" / "libaprutil-1.la"
    assert aprutil_lib.exists()



def test_parse_config_vars_real(compiled_apache):
    """HarnessBuilder._parse_config_vars works on the real file."""
    builder = HarnessBuilder(compiled_apache)
    config_vars = builder._parse_config_vars()

    assert isinstance(config_vars, dict)
    assert "CC" in config_vars
    assert "CFLAGS" in config_vars
    assert len(config_vars) > 10


def test_get_system_libs_real(compiled_apache):
    """HarnessBuilder._get_system_libs extracts real library flags."""
    builder = HarnessBuilder(compiled_apache)
    config_vars = builder._parse_config_vars()
    libs = builder._get_system_libs(config_vars)

    assert isinstance(libs, list)
    # Should find at least PCRE libs
    lib_str = " ".join(libs)
    assert "-l" in lib_str or "pcre" in lib_str.lower()
