"""Global configuration constants for the apatchy framework.

This module centralises every path, URL, and default value that
the rest of the package needs.  All values are class-level
attributes on :class:`Config` so they can be referenced without
instantiation (e.g. ``Config.WORK_DIR``).
"""

import os
from pathlib import Path


class Config:
    """Central configuration store for the fuzzer.

    All attributes are **class-level** - there is no need to create an
    instance.  Paths that depend on the current working directory are
    resolved once at import time.
    """

    PROJECT_ROOT = Path(__file__).parent.parent.parent.parent.resolve()
    APACHE_MIRROR = "https://dlcdn.apache.org/httpd"
    APACHE_ARCHIVE = "https://archive.apache.org/dist/httpd"

    # Directories
    WORK_DIR = Path(os.getcwd())
    SRC_DIR = PROJECT_ROOT / "src" / "apatchy"
    TOOLCHAIN_DIR = WORK_DIR / "toolchain"

    # Defaults
    DEFAULT_APACHE_VERSION = "2.4.46"

    # Toolchain config
    TOOLCHAIN_CONFIG = WORK_DIR / "toolchain.config"

    OBJ_DIR = WORK_DIR / ".objects"
    FRAMEWORK_DIR = Path(__file__).parent.parent.parent.resolve()
    PROTOS_DIR = FRAMEWORK_DIR / "protos"
    HARNESSES_DIR = FRAMEWORK_DIR / "harnesses"
    EXTERNAL_MODULES_DIR = Path(__file__).parent / "external_modules"
    DEV_DIR = WORK_DIR / "dev"

    @classmethod
    def get_apache_dir(cls, version: str) -> Path:
        """Return the expected source directory for a given Apache version.

        Parameters
        ----------
        version : str
            Apache HTTPD version string, e.g. ``"2.4.62"``.

        Returns
        -------
        Path
            Absolute path to the ``httpd-<version>`` directory inside
            :attr:`WORK_DIR`.
        """
        return cls.WORK_DIR / f"httpd-{version}"
