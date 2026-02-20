"""Utility for creating alternate Apache build trees with different compiler flags.

Used by coverage and standalone modes to build a separate copy of the Apache
source tree without AFL instrumentation, so that harnesses link cleanly against
vanilla or coverage-instrumented objects.
"""

import hashlib
import os
import re
import shutil
from pathlib import Path

from apatchy.utils.logger import get_logger
from apatchy.core.process_runner import ProcessRunner

logger = get_logger(__name__)


class AlternateBuildTree:
    """Creates and manages a copy of an Apache build tree with different compiler flags."""

    def __init__(self, httpd_root: Path, suffix: str) -> None:
        self.httpd_root = httpd_root
        self.suffix = suffix
        self.alt_root = httpd_root.parent / (httpd_root.name + suffix)
        self.runner = ProcessRunner()

    def ensure_build(self, cc: str, cflags: str, ldflags: str) -> Path:
        """Create the alternate tree (if needed) and rebuild Apache with the given flags.

        Returns the path to the alternate httpd root.
        """
        self._ensure_tree()

        # Integrity check: verify Makefiles reference the alt path.
        if self._needs_recreate():
            logger.info(f"{self.suffix} tree has stale paths - recreating...")
            shutil.rmtree(self.alt_root)
            self._ensure_tree()

        # Staleness detection: if user re-ran `apatchy configure`, rebuild.
        hash_file = self.alt_root / ".afl_config_hash"
        current_hash = self.afl_config_hash(self.httpd_root)
        if hash_file.exists():
            saved_hash = hash_file.read_text().strip()
            if saved_hash != current_hash:
                logger.info(
                    f"AFL config changed since last {self.suffix} build - recreating..."
                )
                shutil.rmtree(self.alt_root)
                self._ensure_tree()
        else:
            logger.info(
                f"Incomplete {self.suffix} tree (no build hash) - recreating..."
            )
            shutil.rmtree(self.alt_root)
            self._ensure_tree()

        # Fast path: already built and up to date.
        libmain = self.alt_root / "server" / "libmain.la"
        if libmain.exists() and hash_file.exists():
            logger.info(f"{self.suffix} build ready: {self.alt_root.name}/")
            return self.alt_root

        # Build
        logger.info(f"Rebuilding Apache with {self.suffix} flags (CC={cc})...")
        self.patch_build_flags(cc, cflags, ldflags, self.alt_root)
        self.runner.run_command(["make", "clean"], cwd=self.alt_root)
        jobs = os.cpu_count() or 4
        make_cmd = [
            "make", f"-j{jobs}",
            f"CC={cc}",
            f"CFLAGS={cflags}",
        ]
        # CC and CFLAGS are passed on the command line as well for top-level
        # targets.  LDFLAGS is only patched in config files (not passed on the
        # command line) because command-line LDFLAGS clobbers the Makefile
        # variable everywhere, breaking libtool's transitive dependency
        # resolution (support utilities lose -lcrypt/-lm).
        self.runner.run_command(make_cmd, cwd=self.alt_root)

        # Save config hash after successful build
        hash_file.write_text(current_hash)

        return self.alt_root

    def _ensure_tree(self) -> None:
        """Create the alternate tree via copytree + path rewriting if it doesn't exist."""
        if not self.alt_root.exists():
            logger.info(f"Creating {self.suffix} build tree: {self.alt_root.name}/ ...")
            shutil.copytree(self.httpd_root, self.alt_root, symlinks=True)
            self.rewrite_paths(
                self.alt_root,
                str(self.httpd_root.resolve()),
                str(self.alt_root.resolve()),
            )

    def _needs_recreate(self) -> bool:
        """Check if the tree's Makefiles reference the correct path."""
        makefile = self.alt_root / "Makefile"
        if not makefile.exists():
            return False
        text = makefile.read_text()
        return str(self.alt_root.resolve()) not in text

    @staticmethod
    def rewrite_paths(tree: Path, old_prefix: str, new_prefix: str) -> None:
        """Replace hardcoded absolute paths in build-system files.

        Apache's ``configure`` bakes the build directory into Makefiles,
        libtool scripts, ``.la`` files, ``config.status``, etc.  After
        copying the tree we must rewrite these so ``make`` operates on the
        copy rather than the original.
        """
        globs = ["Makefile", "*.mk", "config.status", "config.nice",
                 "config.log", "libtool", "*.la"]
        for pattern in globs:
            for path in tree.rglob(pattern):
                if not path.is_file():
                    continue
                try:
                    text = path.read_text()
                except (UnicodeDecodeError, OSError):
                    continue
                replaced = text.replace(old_prefix, new_prefix)
                if replaced != text:
                    path.write_text(replaced)

    @staticmethod
    def patch_build_flags(cc: str, cflags: str, ldflags: str, httpd_root: Path) -> None:
        """Patch CC, CFLAGS, and LDFLAGS across all build-system files.

        The AFL build bakes afl-clang-fast, -fsanitize=address, and other
        AFL-specific flags into config_vars.mk, apr_rules.mk, rules.mk,
        and libtool scripts throughout the tree (including srclib/apr and
        srclib/apr-util).  We must patch ALL of them so the alternate build
        compiles and links cleanly without AFL or ASan references.

        LDFLAGS is patched in config files rather than passed on the make
        command line because command-line LDFLAGS clobbers the Makefile
        variable everywhere, which breaks libtool's transitive dependency
        resolution (support utilities lose -lcrypt, -lm, etc.).
        """
        # --- Patch libtool scripts (CC, LTCC, LTCFLAGS) ---
        for lt in httpd_root.rglob("libtool"):
            if not lt.is_file():
                continue
            text = lt.read_text()
            patched = re.sub(
                r'^(CC=)".*"', rf'\1"{cc}"', text, flags=re.MULTILINE,
            )
            patched = re.sub(
                r'^(LTCC=)".*"', rf'\1"{cc}"', patched, flags=re.MULTILINE,
            )
            patched = re.sub(
                r'^(LTCFLAGS=)".*"', rf'\1"{cflags}"', patched, flags=re.MULTILINE,
            )
            if patched != text:
                lt.write_text(patched)
                logger.info(f"Patched CC/CFLAGS in {lt}")

        # --- Patch all .mk config files (config_vars.mk, apr_rules.mk, rules.mk) ---
        for mk in httpd_root.rglob("*.mk"):
            if not mk.is_file():
                continue
            try:
                text = mk.read_text()
            except (UnicodeDecodeError, OSError):
                continue
            patched = re.sub(
                r'^(CC\s*=\s*).*$', rf'\1{cc}', text, flags=re.MULTILINE,
            )
            patched = re.sub(
                r'^(CPP\s*=\s*).*$', rf'\1{cc} -E', patched, flags=re.MULTILINE,
            )
            patched = re.sub(
                r'^(CFLAGS\s*=).*$', rf'\1{cflags}', patched, flags=re.MULTILINE,
            )
            patched = re.sub(
                r'^(LDFLAGS\s*=).*$', rf'\1{ldflags}', patched, flags=re.MULTILINE,
            )
            if patched != text:
                mk.write_text(patched)
                logger.info(f"Patched build flags in {mk}")

        # --- Patch top-level Makefiles that reference CC/CPP directly ---
        for mf in httpd_root.rglob("Makefile"):
            if not mf.is_file():
                continue
            try:
                text = mf.read_text()
            except (UnicodeDecodeError, OSError):
                continue
            patched = re.sub(
                r'^(CPP\s*=\s*).*$', rf'\1{cc} -E', text, flags=re.MULTILINE,
            )
            if patched != text:
                mf.write_text(patched)
                logger.info(f"Patched CPP in {mf}")

    @staticmethod
    def afl_config_hash(httpd_root: Path) -> str:
        """Hash the ac_cs_config line from config.status for staleness detection."""
        config_status = httpd_root / "config.status"
        if not config_status.exists():
            return ""
        for line in config_status.read_text().splitlines():
            if line.startswith("ac_cs_config="):
                return hashlib.sha256(line.encode()).hexdigest()
        return ""
