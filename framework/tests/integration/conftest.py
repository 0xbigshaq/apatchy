"""Session-scoped fixtures for integration tests.

These fixtures manage a real Apache HTTPD source tree under
.test_cache/ so that expensive operations (download, configure,
compile) happen once per test run and persist across runs.
"""

import os
import shutil

import pytest

from apatchy.config import Config


def pytest_collection_modifyitems(items):
    """Auto-apply the 'integration' marker to every test in the integration/ directory."""
    for item in items:
        if "/integration/" in str(item.fspath):
            item.add_marker(pytest.mark.integration)

_ALL_VERSIONS = [
    "2.4.62",
    "2.4.63",
]

def _get_versions():
    """Return the list of Apache versions to test.

    If APATCHY_TEST_VERSIONS is set (comma-separated), use only those.
    Otherwise test all versions in _ALL_VERSIONS.
    """
    env = os.environ.get("APATCHY_TEST_VERSIONS")
    if env:
        return [v.strip() for v in env.split(",") if v.strip()]
    return _ALL_VERSIONS

APACHE_VERSIONS = _get_versions()


def _require_tool(name):
    """Skip the entire test session if a tool is missing."""
    if not shutil.which(name):
        pytest.skip(f"{name} not found on PATH", allow_module_level=True)



@pytest.fixture(scope="session")
def integration_work_dir(tmp_path_factory):
    """Return a persistent working directory for integration tests.

    Uses framework/.test_cache/ so builds survive across test runs.
    Falls back to a pytest tmp dir if the cache can't be created.
    """
    cache = Config.PROJECT_ROOT / "framework" / ".test_cache"
    try:
        cache.mkdir(exist_ok=True)
        return cache
    except OSError:
        return tmp_path_factory.mktemp("integration")



@pytest.fixture(scope="session", params=APACHE_VERSIONS)
def apache_source(request, integration_work_dir):
    """Download and extract Apache HTTPD source.

    Returns the httpd root Path (e.g. .test_cache/httpd-2.4.62).
    Skips download if already present.
    """
    from apatchy.core.downloader import Downloader

    version = request.param
    dl = Downloader()
    dl.work_dir = integration_work_dir

    httpd_root = dl.download_apache(version=version)
    assert httpd_root.exists(), f"Download failed: {httpd_root} does not exist"
    return httpd_root



@pytest.fixture(scope="session")
def configured_apache(apache_source):
    """Configure Apache for fuzzing (with ASan + session/crypto).

    Skips if already configured (config_vars.mk exists).
    Returns the httpd root Path.
    """
    _require_tool("make")

    config_vars = apache_source / "build" / "config_vars.mk"
    if config_vars.exists():
        return apache_source

    from apatchy.managers.build_manager import BuildManager
    from apatchy.managers.config_manager import ConfigManager

    cm = ConfigManager(build_mode="fuzz", asan=True)
    bm = BuildManager(apache_source, cm, verbose=True)
    bm.configure_httpd()

    assert config_vars.exists(), "configure failed: config_vars.mk not generated"
    return apache_source



@pytest.fixture(scope="session")
def compiled_apache(configured_apache):
    """Compile Apache (make). Skips if already compiled.

    Returns the httpd root Path.
    """
    httpd_binary = configured_apache / "httpd"
    if httpd_binary.exists():
        return configured_apache

    from apatchy.managers.build_manager import BuildManager
    from apatchy.managers.config_manager import ConfigManager

    cm = ConfigManager(build_mode="fuzz", asan=True)
    bm = BuildManager(configured_apache, cm, verbose=True)
    bm.compile_httpd(clean=False)

    assert httpd_binary.exists(), "Compilation failed: httpd binary not produced"
    return configured_apache



@pytest.fixture
def harness_build_dir(integration_work_dir):
    """Temporary directory for harness builds, cleaned between tests."""
    build_dir = integration_work_dir / "_harness_build"
    if build_dir.exists():
        shutil.rmtree(build_dir)
    build_dir.mkdir()
    return build_dir
