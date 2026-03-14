from pathlib import Path
from typing import Dict, Optional

from apatchy.compat import get_compat_flags
from apatchy.core import toolchain_config
from apatchy.utils.logger import get_logger

logger = get_logger(__name__)


class ConfigManager:
    """Generate compiler flags and resolve httpd config paths for a build.

    ``ConfigManager`` is the central place that translates high-level build
    intentions (fuzzing, coverage, debugging) and sanitizer choices into the
    concrete ``CFLAGS``, ``LDFLAGS``, and ``CC`` values that
    :class:`~apatchy.managers.build_manager.BuildManager` passes to Apache's
    ``./configure``. It also resolves the path to the Apache config file
    (e.g. ``fuzz.conf``) that other managers pass to the harness at runtime.

    Build modes:

    * ``"fuzz"`` - optimized build (``-O2``) with AFL++ instrumentation via
      ``afl-clang-fast``.
    * ``"coverage"`` - unoptimized build (``-O0 -g``) with LLVM source-based
      coverage (``-fcoverage-mapping`` / ``-fprofile-instr-generate``).
    * anything else - plain debug build (``-O0 -g``), no special instrumentation.

    Sanitizers are orthogonal to the build mode and can be freely combined:

    * ``asan`` - AddressSanitizer (heap/stack buffer overflows, use-after-free).
    * ``ubsan`` - UndefinedBehaviorSanitizer (signed overflow, null deref, etc.).
    * ``intsan`` - unsigned-integer-overflow checks. A compile-time ignorelist
      (``configs/intsan.ignorelist``) is applied automatically to suppress
      false positives in APR internals.
    * ``truncsan`` - implicit-unsigned-integer-truncation checks. Noisy on
      Apache internals, best used for targeted module auditing.

    When a known httpd version is passed to :meth:`generate_build_config`,
    version-specific compatibility flags from :mod:`apatchy.compat` are
    appended automatically.

    Args:
        build_mode: Build profile. ``"fuzz"`` (default), ``"coverage"``, or
            any other string for a plain debug build.
        engine: Fuzzing engine name. Currently only used for labeling.
        config_name: Filename of the httpd config to resolve at runtime.
            Defaults to ``"fuzz.conf"``.
        asan: Enable AddressSanitizer.
        ubsan: Enable UndefinedBehaviorSanitizer.
        intsan: Enable unsigned-integer-overflow sanitizer.
        truncsan: Enable implicit-unsigned-integer-truncation sanitizer.

    CLI usage:

    ``ConfigManager`` is created implicitly by several CLI commands. The
    ``configure`` command exposes the most options:

    .. code-block:: bash

        # Fuzz build with ASan + UBSan
        apatchy configure --mode fuzz --asan --ubsan

        # Coverage build for triage
        apatchy configure --mode coverage

        # Fuzz with all integer sanitizers
        apatchy configure --mode fuzz --asan --intsan --truncsan

    Example:
        .. code-block:: python

            from apatchy.managers.config_manager import ConfigManager

            # Fuzz build with ASan + UBSan
            config = ConfigManager(build_mode="fuzz", asan=True, ubsan=True)
            flags = config.generate_build_config(httpd_version="2.4.58")
            # flags == {"CC": "afl-clang-fast",
            #           "CFLAGS": "-O2 -fno-omit-frame-pointer ...",
            #           "LDFLAGS": "-no-pie -fsanitize=address ..."}

            # Coverage build for triage
            cov_config = ConfigManager(build_mode="coverage")
            cov_flags = cov_config.generate_build_config()
    """

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
        ldflags = []
        cc = None

        # Fuzz builds use -O2 for throughput; debug/coverage/standalone
        # builds use -O0 -g for accurate crash triage and debugging.
        if self.build_mode == "fuzz":
            cflags = ["-O2", "-fno-omit-frame-pointer"]
        else:
            cflags = ["-g", "-O0", "-fno-omit-frame-pointer"]

        def both(flag: str):
            (cflags.append(flag), ldflags.append(flag))

        if self.build_mode == "fuzz":
            self.logger.info("Using afl-clang-fast for AFL instrumentation")
            cc = toolchain_config.resolve_tool("afl-clang-fast") or "afl-clang-fast"
            # Clang is stricter than gcc; suppress format warnings that
            # Apache's upstream code triggers under -Werror (maintainer-mode).
            cflags.append("-Wno-error=format")
            # AFL SanCov instrumentation produces non-PIC objects.
            # Disable PIE to avoid R_X86_64_32S relocation errors at link time.
            ldflags.append("-no-pie")

        elif self.build_mode == "coverage":
            self.logger.info("Enabling Coverage Instrumentation")
            cflags.append("-fcoverage-mapping")
            both("-fprofile-instr-generate")
            # Apache modules may have been compiled with AFL SanCov
            # instrumentation (non-PIC). Disable PIE to avoid
            # R_X86_64_32S relocation errors at link time.
            ldflags.append("-no-pie")

        elif self.build_mode == "libfuzzer":
            self.logger.info("Enabling LibFuzzer instrumentation")
            both("-fsanitize=fuzzer-no-link")
            cflags.append("-Wno-error")

        # ASan is orthogonal to the build mode - it can be combined with
        # any compiler (fuzz, coverage, or default).
        if self.asan:
            self.logger.info("Enabling AddressSanitizer")
            both("-fsanitize=address")

        if self.ubsan:
            self.logger.info("Enabling UndefinedBehaviorSanitizer")
            both("-fsanitize=undefined")
            # fix SIGILL issue
            both("-fsanitize-recover=all")  # continue execution after reporting (don't abort)
            both("-fno-sanitize-trap")  # emit runtime report instead of ud1/ud2 trap

        if self.intsan:
            self.logger.info("Enabling unsigned-integer-overflow sanitizer")
            both("-fsanitize=unsigned-integer-overflow")
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
            both("-fsanitize=implicit-unsigned-integer-truncation")

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
        """Return the path to the requested httpd config file."""
        if config_name is None:
            config_name = self.config_name

        config_path = Path(config_name)
        if config_path.exists():
            return config_path.resolve()

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
