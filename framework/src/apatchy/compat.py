import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

from packaging.specifiers import SpecifierSet
from packaging.version import Version

from apatchy.config import Config

OPENSSL3_COMPAT_H = str(Config.HARNESSES_DIR / "openssl3_compat.h")


def extract_version_from_path(httpd_root: Path) -> Optional[str]:
    match = re.match(r"httpd-(\d+\.\d+\.\d+)", httpd_root.name)
    if match:
        return match.group(1)
    return None


@dataclass(frozen=True)
class CompatEntry:
    """A build compatibility fix applied to HTTPD versions matching a specifier.

    The ``versions`` field uses PEP 440 version specifiers (via
    ``packaging.specifiers.SpecifierSet``).  Examples::

        "<=2.4.58"              # all versions up to 2.4.58
        ">=2.4.32,<=2.4.51"    # versions 2.4.32 through 2.4.51
        ">=2.4.0,<2.4.60"      # inclusive start, exclusive end
    """

    id: str
    description: str
    versions: str
    cflags: List[str] = field(default_factory=list)
    ldflags: List[str] = field(default_factory=list)
    configure_args: List[str] = field(default_factory=list)

    def matches(self, version: Version) -> bool:  # noqa: D102
        return version in SpecifierSet(self.versions)


@dataclass(frozen=True)
class CompatResult:  # noqa: D101
    cflags: List[str]
    ldflags: List[str]
    configure_args: List[str]
    applied_ids: List[str]


COMPAT_REGISTRY: List[CompatEntry] = [
    CompatEntry(
        id="openssl3-deprecations",
        description=(
            "httpd <= 2.4.58 uses OpenSSL ENGINE, SRP, DH, and EC_KEY "
            "APIs that were deprecated in OpenSSL 3.0. With "
            "--enable-maintainer-mode (-Werror) these deprecation "
            "warnings become build failures."
        ),
        versions="<=2.4.58",
        cflags=["-Wno-error=deprecated-declarations"],
    ),
    CompatEntry(
        id="openssl3-removed-api",
        description=(
            "httpd <= 2.4.51 calls ERR_GET_FUNC which was removed "
            "(not just deprecated) in OpenSSL 3.0, causing a linker "
            "error. Also uses implicit function declarations that "
            "newer clang treats as errors."
        ),
        versions="<=2.4.51",
        cflags=[
            "-Wno-error=deprecated-declarations",
            "-Wno-implicit-function-declaration",
            f"-include {OPENSSL3_COMPAT_H}",
        ],
    ),
    CompatEntry(
        id="wo-strict-prototype",
        description=(
            "httpd <= 2.4.51 has function declarations without prototypes "
            "and other warnings that newer clang treats as errors."
        ),
        versions="<=2.4.51",
        cflags=[
            "-Wno-strict-prototypes",
            "-Wno-unused-but-set-variable",
            "-Wno-single-bit-bitfield-constant-conversion",
        ],
    ),
]


def get_compat_flags(httpd_version: str) -> CompatResult:
    version = Version(httpd_version)
    applied_ids: List[str] = []
    cflags: List[str] = []
    ldflags: List[str] = []
    configure_args: List[str] = []

    for entry in COMPAT_REGISTRY:
        if entry.matches(version):
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
