"""Version-aware build compatibility registry.

Different HTTPD versions have different build issues when compiled
against modern system libraries (e.g. OpenSSL 3.0 deprecations).
This module maintains a registry of known issues and the compiler
flags or configure arguments needed to work around them.

To add a new compatibility fix, append a :class:`CompatEntry` to
:data:`COMPAT_REGISTRY`.  The :func:`get_compat_flags` function
aggregates all entries that match a given HTTPD version string.

Example::

    COMPAT_REGISTRY.append(
        CompatEntry(
            id="example-fix",
            description="Short explanation of the issue.",
            max_version="2.4.60",
            cflags=["-Wno-error=some-warning"],
        )
    )
"""

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

from packaging.version import Version


def extract_version_from_path(httpd_root: Path) -> Optional[str]:
    """Extract the HTTPD version from a directory name.

    Handles both plain (``httpd-2.4.52``) and suffixed
    (``httpd-2.4.52-cov``) directory names.

    Parameters
    ----------
    httpd_root : Path
        Path whose final component is an ``httpd-X.Y.Z`` directory.

    Returns
    -------
    str or None
        The version string (e.g. ``"2.4.52"``), or *None* if the
        directory name does not match the expected pattern.
    """
    match = re.match(r"httpd-(\d+\.\d+\.\d+)", httpd_root.name)
    if match:
        return match.group(1)
    return None


@dataclass(frozen=True)
class CompatEntry:
    """A single build compatibility fix for a range of HTTPD versions.

    Parameters
    ----------
    id : str
        Short unique identifier used in log messages.
    description : str
        Human-readable explanation of why this fix exists.
    min_version : str or None
        Inclusive lower bound (e.g. ``"2.4.0"``).
        ``None`` means no lower bound.
    max_version : str or None
        Inclusive upper bound (e.g. ``"2.4.58"``).
        ``None`` means no upper bound.
    cflags : list of str
        Extra ``CFLAGS`` to append.
    ldflags : list of str
        Extra ``LDFLAGS`` to append.
    configure_args : list of str
        Extra arguments to pass to ``./configure``.
    """

    id: str
    description: str
    min_version: Optional[str] = None
    max_version: Optional[str] = None
    cflags: List[str] = field(default_factory=list)
    ldflags: List[str] = field(default_factory=list)
    configure_args: List[str] = field(default_factory=list)


@dataclass(frozen=True)
class CompatResult:
    """Aggregated compatibility flags from all matching registry entries."""

    cflags: List[str]
    ldflags: List[str]
    configure_args: List[str]
    applied_ids: List[str]



COMPAT_REGISTRY: List[CompatEntry] = [
    CompatEntry(
        id="openssl3-deprecations",
        description=(
            "httpd <= 2.4.58 uses OpenSSL ENGINE, SRP, DH, and EC_KEY "
            "APIs that were deprecated in OpenSSL 3.0.  With "
            "--enable-maintainer-mode (-Werror) these deprecation "
            "warnings become build failures."
        ),
        max_version="2.4.58",
        cflags=["-Wno-error=deprecated-declarations"],
    ),
]


def get_compat_flags(httpd_version: str) -> CompatResult:
    """Return aggregated compatibility flags for *httpd_version*.

    Iterates :data:`COMPAT_REGISTRY` and collects flags from every
    entry whose version range includes *httpd_version*.

    Parameters
    ----------
    httpd_version : str
        HTTPD version string, e.g. ``"2.4.52"``.

    Returns
    -------
    CompatResult
        Aggregated ``cflags``, ``ldflags``, ``configure_args``, and the
        list of matched entry IDs (``applied_ids``).
    """
    version = Version(httpd_version)
    applied_ids: List[str] = []
    cflags: List[str] = []
    ldflags: List[str] = []
    configure_args: List[str] = []

    for entry in COMPAT_REGISTRY:
        if entry.min_version is not None and version < Version(entry.min_version):
            continue
        if entry.max_version is not None and version > Version(entry.max_version):
            continue
        applied_ids.append(entry.id)
        cflags.extend(entry.cflags)
        ldflags.extend(entry.ldflags)
        configure_args.extend(entry.configure_args)

    return CompatResult(
        cflags=cflags,
        ldflags=ldflags,
        configure_args=configure_args,
        applied_ids=applied_ids,
    )
