"""Session-scoped fixtures for integration tests.

These fixtures manage a real Apache HTTPD source tree under
.test_cache/ so that expensive operations (download, configure,
compile) happen once per test run and persist across runs.
"""

import os
import shutil
from pathlib import Path

import pytest

from apatchy.config import Config


def pytest_collection_modifyitems(items: list[pytest.Item]) -> None:
    """Auto-apply the 'integration' marker to every test in the integration/ directory."""
    for item in items:
        if "/integration/" in str(item.fspath):
            item.add_marker(pytest.mark.integration)


_ALL_VERSIONS = [
    "2.4.62",
    "2.4.63",
]


def _get_versions() -> list[str]:
    """Return the list of Apache versions to test.

    If APATCHY_TEST_VERSIONS is set (comma-separated), use only those.
    Otherwise test all versions in _ALL_VERSIONS.
    """
    env = os.environ.get("APATCHY_TEST_VERSIONS")
    if env:
        return [v.strip() for v in env.split(",") if v.strip()]
    return _ALL_VERSIONS


APACHE_VERSIONS = _get_versions()


def _require_tool(name: str) -> None:
    """Skip the entire test session if a tool is missing."""
    if not shutil.which(name):
        pytest.skip(f"{name} not found on PATH", allow_module_level=True)


@pytest.fixture(scope="session")
def work_dir(tmp_path_factory: pytest.TempPathFactory) -> Path:
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
def httpd_src(request: pytest.FixtureRequest, work_dir: Path) -> Path:
    """Download and extract Apache HTTPD source.

    Returns the httpd root Path (e.g. .test_cache/httpd-2.4.62).
    Skips download if already present.
    """
    from apatchy.core.downloader import Downloader

    version = request.param
    dl = Downloader()
    dl.work_dir = work_dir

    httpd_root = dl.download_apache(version=version)
    assert httpd_root.exists(), f"Download failed: {httpd_root} does not exist"
    return httpd_root


@pytest.fixture(scope="session")
def httpd_configured(httpd_src: Path) -> Path:
    """Configure Apache for fuzzing (with ASan + session/crypto).

    Skips if already configured (config_vars.mk exists).
    Returns the httpd root Path.
    """
    _require_tool("make")

    config_vars = httpd_src / "build" / "config_vars.mk"
    if config_vars.exists():
        return httpd_src

    from apatchy.managers.build_manager import BuildManager
    from apatchy.managers.config_manager import ConfigManager

    cm = ConfigManager(build_mode="fuzz", asan=True)
    bm = BuildManager(httpd_src, cm, verbose=True)
    bm.configure_httpd()

    assert config_vars.exists(), "configure failed: config_vars.mk not generated"
    return httpd_src


@pytest.fixture(scope="session")
def httpd(httpd_configured: Path) -> Path:
    """Compile Apache (make). Skips if already compiled.

    Returns the httpd root Path.
    """
    httpd_binary = httpd_configured / "httpd"
    if httpd_binary.exists():
        return httpd_configured

    from apatchy.managers.build_manager import BuildManager
    from apatchy.managers.config_manager import ConfigManager

    cm = ConfigManager(build_mode="fuzz", asan=True)
    bm = BuildManager(httpd_configured, cm, verbose=True)
    bm.compile_httpd(clean=False)

    assert httpd_binary.exists(), "Compilation failed: httpd binary not produced"
    return httpd_configured


@pytest.fixture
def build_dir(work_dir: Path) -> Path:
    """Temporary directory for harness builds, cleaned between tests."""
    d = work_dir / "_harness_build"
    if d.exists():
        shutil.rmtree(d)
    d.mkdir()
    return d


@pytest.fixture
def mp(monkeypatch: pytest.MonkeyPatch) -> pytest.MonkeyPatch:
    """Short alias for the monkeypatch fixture."""
    return monkeypatch
