"""Compiler-flag generation and httpd config-file resolution.

:class:`ConfigManager` decides which compiler (``afl-clang-fast`` vs
``clang``) and which sanitizer/coverage flags should be used for a
given build, and resolves the runtime ``fuzz.conf`` config file path.
"""

from pathlib import Path
from typing import Dict, Optional

from apatchy.compat import get_compat_flags
from apatchy.utils.logger import get_logger

logger = get_logger(__name__)


class ConfigManager:
    """Generate ``CFLAGS``/``LDFLAGS`` and resolve httpd config paths."""

    def __init__(
        self,
        build_mode: str = "fuzz",
        engine: str = "afl",
        config_name: str = "fuzz.conf",
        asan: bool = False,
        ubsan: bool = False,
        intsan: bool = False,
        truncsan: bool = False,
    ) -> None:
        self.build_mode = build_mode
        self.engine = engine
        self.config_name = config_name
        self.asan = asan
        self.ubsan = ubsan
        self.intsan = intsan
        self.truncsan = truncsan
        self.logger = logger
        self.httpd_config_path: Optional[Path] = None

    def generate_build_config(self, httpd_version: Optional[str] = None) -> Dict[str, str]:
        """Generate ``CFLAGS`` and ``LDFLAGS`` based on the build mode.

        Sanitizer flags (ASan, UBSan, IntSan, TruncSan) are orthogonal
        and can be combined with any mode.  When *httpd_version* is
        provided, version-specific compatibility flags from
        :mod:`apatchy.compat` are appended automatically.

        When ``intsan`` is enabled, a compile-time ignorelist
        (``configs/intsan.ignorelist``) is applied automatically to
        suppress false positives in APR internals.
        """
        cflags = ["-g", "-O0", "-fno-omit-frame-pointer"]
        ldflags = []
        cc = None

        if self.build_mode == "fuzz":
            self.logger.info("Using afl-clang-fast for AFL instrumentation")
            cc = "afl-clang-fast"
            # Clang is stricter than gcc; suppress format warnings that
            # Apache's upstream code triggers under -Werror (maintainer-mode).
            cflags.append("-Wno-error=format")
            # AFL SanCov instrumentation produces non-PIC objects.
            # Disable PIE to avoid R_X86_64_32S relocation errors at link time.
            ldflags.append("-no-pie")

        elif self.build_mode == "coverage":
            self.logger.info("Enabling Coverage Instrumentation")
            cflags.append("-fprofile-instr-generate")
            cflags.append("-fcoverage-mapping")
            ldflags.append("-fprofile-instr-generate")
            # Apache modules may have been compiled with AFL SanCov
            # instrumentation (non-PIC). Disable PIE to avoid
            # R_X86_64_32S relocation errors at link time.
            ldflags.append("-no-pie")

        # ASan is orthogonal to the build mode - it can be combined with
        # any compiler (fuzz, coverage, or default).
        if self.asan:
            self.logger.info("Enabling AddressSanitizer")
            cflags.append("-fsanitize=address")
            ldflags.append("-fsanitize=address")

        if self.ubsan:
            self.logger.info("Enabling UndefinedBehaviorSanitizer")
            cflags.append("-fsanitize=undefined")
            ldflags.append("-fsanitize=undefined")

        if self.intsan:
            self.logger.info("Enabling unsigned-integer-overflow sanitizer")
            cflags.append("-fsanitize=unsigned-integer-overflow")
            ldflags.append("-fsanitize=unsigned-integer-overflow")
            ignorelist = self._resolve_ignorelist("intsan.ignorelist")
            if ignorelist:
                self.logger.info(f"Applying intsan ignorelist: {ignorelist}")
                cflags.append(f"-fsanitize-ignorelist={ignorelist}")
            else:
                self.logger.warning(
                    "--intsan is noisy on Apache internals (hash, crypto). "
                    "Ignorelist not found at configs/intsan.ignorelist."
                )

        if self.truncsan:
            self.logger.info("Enabling implicit-unsigned-integer-truncation sanitizer")
            self.logger.warning(
                "--truncsan is noisy on Apache internals. Consider using it only for targeted module auditing."
            )
            cflags.append("-fsanitize=implicit-unsigned-integer-truncation")
            ldflags.append("-fsanitize=implicit-unsigned-integer-truncation")

        # Apply version-specific compatibility flags when the HTTPD
        # version is known (see apatchy.compat for the registry).
        if httpd_version:
            compat = get_compat_flags(httpd_version)
            for entry_id in compat.applied_ids:
                self.logger.info(f"Applying compat fix: {entry_id}")
            cflags.extend(compat.cflags)
            ldflags.extend(compat.ldflags)

        result = {
            "CFLAGS": " ".join(cflags),
            "LDFLAGS": " ".join(ldflags),
        }
        if cc:
            result["CC"] = cc
        return result

    def get_httpd_config(self, config_name: Optional[str] = None) -> Optional[Path]:
        """Return the path to the requested httpd config file.

        Look in the package resources or a local configs directory.
        """
        if config_name is None:
            config_name = self.config_name

        # 1. Try the path as given (supports relative/absolute paths)
        direct_path = Path(config_name)
        if direct_path.exists():
            return direct_path.resolve()

        # 2. Fall back to ./configs/<name>
        user_config_path = Path("configs") / config_name
        if user_config_path.exists():
            return user_config_path.resolve()

        self.logger.warning(f"Config file '{config_name}' not found")
        return None

    def _resolve_ignorelist(self, filename: str) -> Optional[Path]:
        """Locate a sanitizer ignorelist file in the configs directory."""
        # Try relative to cwd
        candidate = Path("configs") / filename
        if candidate.exists():
            return candidate.resolve()

        # Fall back to the package configs directory
        from apatchy.config import Config

        candidate = Config.PROJECT_ROOT / "framework" / "configs" / filename
        if candidate.exists():
            return candidate.resolve()

        return None

    def validate_configuration(self) -> None:
        """Verify compiler compatibility (e.g. clang for coverage)."""
        # Todo: implement validation
        pass
