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

from apache_fuzzer.utils.logger import get_logger
from apache_fuzzer.core.process_runner import ProcessRunner

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

        # Staleness detection: if user re-ran `fuzzer configure`, rebuild.
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
        self.patch_libtool_cc(cc, self.alt_root)
        self.runner.run_command(["make", "clean"], cwd=self.alt_root)
        jobs = os.cpu_count() or 4
        make_cmd = [
            "make", f"-j{jobs}",
            f"CC={cc}",
            f"CFLAGS={cflags}",
        ]
        # Only override LDFLAGS if non-empty; passing LDFLAGS= (empty) on
        # the command line clobbers the Makefile's built-in value and breaks
        # linking of support utilities that need -lcrypt.
        if ldflags:
            make_cmd.append(f"LDFLAGS={ldflags}")
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
    def patch_libtool_cc(cc: str, httpd_root: Path) -> None:
        """Patch libtool scripts and config_vars.mk to use the given CC.

        Apache's configure bakes the original CC into libtool scripts.  When
        we override CC on the make command line, object compilation uses the
        new CC but libtool's link step still uses the hardcoded value.
        """
        libtool_files = list(httpd_root.rglob("libtool"))
        config_vars_files = list(httpd_root.rglob("config_vars.mk"))

        for lt in libtool_files:
            text = lt.read_text()
            patched = re.sub(
                r'^(CC=)".*"',
                rf'\1"{cc}"',
                text,
                flags=re.MULTILINE,
            )
            patched = re.sub(
                r'^(LTCC=)".*"',
                rf'\1"{cc}"',
                patched,
                flags=re.MULTILINE,
            )
            if patched != text:
                lt.write_text(patched)
                logger.info(f"Patched CC in {lt}")

        for cv in config_vars_files:
            text = cv.read_text()
            patched = re.sub(
                r'^(CC\s*=\s*).*$',
                rf'\1{cc}',
                text,
                flags=re.MULTILINE,
            )
            if patched != text:
                cv.write_text(patched)
                logger.info(f"Patched CC in {cv}")

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
