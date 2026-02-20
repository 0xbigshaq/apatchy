"""Compiler-flag generation and httpd config-file resolution.

:class:`ConfigManager` decides which compiler (``afl-clang-fast`` vs
``clang``) and which flags (``-fsanitize=address``, coverage, etc.)
should be used for a given build, and resolves the runtime
``fuzz.conf`` config file path.
"""

from pathlib import Path
from typing import Dict, Optional
from apatchy.utils.logger import get_logger

logger = get_logger(__name__)


class ConfigManager:
    """Generate ``CFLAGS``/``LDFLAGS`` and resolve httpd config paths."""
    def __init__(self, build_mode: str = "fuzz", engine: str = "afl", config_name: str = "fuzz.conf", asan: bool = False, ubsan: bool = False, intsan: bool = False, truncsan: bool = False) -> None:
        self.build_mode = build_mode
        self.engine = engine
        self.config_name = config_name
        self.asan = asan
        self.ubsan = ubsan
        self.intsan = intsan
        self.truncsan = truncsan
        self.logger = logger
        self.httpd_config_path: Optional[Path] = None

    def generate_build_config(self) -> Dict[str, str]:
        """
        Generates CFLAGS and LDFLAGS based on the build mode.
        ASan is an independent flag that can be combined with any mode.
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
            self.logger.warning("--intsan is noisy on Apache internals (hash, crypto). Consider using it only for targeted module auditing.")
            cflags.append("-fsanitize=unsigned-integer-overflow")
            ldflags.append("-fsanitize=unsigned-integer-overflow")

        if self.truncsan:
            self.logger.info("Enabling implicit-unsigned-integer-truncation sanitizer")
            self.logger.warning("--truncsan is noisy on Apache internals. Consider using it only for targeted module auditing.")
            cflags.append("-fsanitize=implicit-unsigned-integer-truncation")
            ldflags.append("-fsanitize=implicit-unsigned-integer-truncation")

        result = {
            "CFLAGS": " ".join(cflags),
            "LDFLAGS": " ".join(ldflags),
        }
        if cc:
            result["CC"] = cc
        return result

    def get_httpd_config(self, config_name: Optional[str] = None) -> Optional[Path]:
        """
        Returns the path to the requested httpd config file.
        Here we would look in the package resources or a local configs directory.
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

    def validate_configuration(self) -> None:
        # Todo: Verify compiler compatibility (e.g., clang for coverage)
        pass
