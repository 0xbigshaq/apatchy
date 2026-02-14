import glob
import os
import shutil
import subprocess
from pathlib import Path
from typing import List, Optional, Tuple
from apache_fuzzer.utils.logger import get_logger
from apache_fuzzer.utils.build_tree import AlternateBuildTree
from apache_fuzzer.core.process_runner import ProcessRunner
from apache_fuzzer.managers.config_manager import ConfigManager
from apache_fuzzer.core.harness import HarnessBuilder

logger = get_logger(__name__)


class ReportManager:
    def __init__(self, httpd_root: Path, config_manager: ConfigManager) -> None:
        self.httpd_root = httpd_root
        self.config_manager = config_manager
        self.logger = logger
        self.runner = ProcessRunner()
        self.work_dir = Path(".").resolve()

    @staticmethod
    def _clang_major_version(cc: str) -> Optional[int]:
        """Return the LLVM major version of a clang binary, or None."""
        try:
            result = subprocess.run(
                [cc, "--version"], capture_output=True, text=True, timeout=5
            )
            for line in result.stdout.splitlines():
                if "version" in line.lower():
                    for i, word in enumerate(line.split()):
                        if word == "version" and i + 1 < len(line.split()):
                            return int(line.split()[i + 1].split(".")[0])
        except (FileNotFoundError, subprocess.TimeoutExpired, ValueError):
            pass
        return None

    def _detect_llvm_toolchain(self) -> Tuple[str, str, str]:
        """Auto-detect a matched clang / llvm-profdata / llvm-cov triple.

        All three must come from the same LLVM major version so that the
        profraw format produced by the compiler is readable by the tools.
        We locate the compiler first, determine its real version, then find
        llvm-profdata / llvm-cov binaries co-installed with it (same
        directory) to avoid picking up mismatched toolchain copies.

        Returns (profdata_bin, cov_bin, cc).
        """
        # Build a list of candidate clang binaries, newest first
        candidates = [f"clang-{v}" for v in range(20, 10, -1)] + ["clang"]

        for cc in candidates:
            cc_path = shutil.which(cc)
            if not cc_path:
                continue
            major = self._clang_major_version(cc)
            if major is None:
                continue

            # Look for matching llvm tools in the SAME directory as the
            # compiler first (avoids picking up mismatched toolchain copies),
            # then fall back to PATH search.
            cc_dir = str(Path(cc_path).parent)
            profdata_name = f"llvm-profdata-{major}"
            cov_name = f"llvm-cov-{major}"

            # Prefer co-located binaries
            profdata_colocated = Path(cc_dir) / profdata_name
            cov_colocated = Path(cc_dir) / cov_name
            if profdata_colocated.is_file() and cov_colocated.is_file():
                self.logger.info(
                    f"Using LLVM-{major} toolchain: {cc} ({cc_path}), "
                    f"{profdata_colocated}, {cov_colocated}"
                )
                return str(profdata_colocated), str(cov_colocated), cc

            # Fall back to PATH
            profdata_path = shutil.which(profdata_name)
            cov_path = shutil.which(cov_name)
            if profdata_path and cov_path:
                self.logger.info(
                    f"Using LLVM-{major} toolchain: {cc}, "
                    f"{profdata_name}, {cov_name}"
                )
                return profdata_name, cov_name, cc

        raise FileNotFoundError(
            "No matched LLVM toolchain found. Install a complete set, e.g.: "
            "apt install clang-14 llvm-14"
        )

    def _find_afl_queue(self, afl_dir: str) -> Optional[Path]:
        """Find the AFL queue directory, checking common subdirectory layouts."""
        afl_path = Path(afl_dir).resolve()
        if not afl_path.exists():
            self.logger.error(f"AFL output directory not found: {afl_path}")
            return None

        # Check common AFL++ queue locations
        for subdir in ["default/queue", "main/queue", "queue"]:
            candidate = afl_path / subdir
            if candidate.is_dir():
                self.logger.info(f"Found AFL queue: {candidate}")
                return candidate

        self.logger.error(
            f"No queue directory found in {afl_path}. "
            "Expected default/queue, main/queue, or queue."
        )
        return None

    def _get_ld_library_path(self, httpd_root: Optional[Path] = None) -> str:
        """Build LD_LIBRARY_PATH for APR/APR-Util .libs directories.

        Args:
            httpd_root: Explicit httpd root to use. Falls back to self.httpd_root.
        """
        root = httpd_root or self.httpd_root
        srclib = root / "srclib"
        if srclib.exists():
            lib_paths = [
                str(srclib / "apr" / ".libs"),
                str(srclib / "apr-util" / ".libs"),
                # APR-Util's DSO loader searches LD_LIBRARY_PATH for crypto
                # drivers (apr_crypto_openssl-1.so).  Include the in-tree
                # build directory so it finds the coverage-rebuilt driver
                # instead of a stale AFL-instrumented installed copy.
                str(srclib / "apr-util" / "crypto" / ".libs"),
            ]
            existing = os.environ.get("LD_LIBRARY_PATH", "")
            return ":".join(lib_paths + ([existing] if existing else []))
        return os.environ.get("LD_LIBRARY_PATH", "")

    def _ensure_coverage_build(self, cc: str) -> Path:
        """Ensure the separate coverage tree is configured and compiled.

        Returns the Path to the coverage httpd root.
        """
        tree = AlternateBuildTree(self.httpd_root, "-cov")
        return tree.ensure_build(
            cc=cc,
            cflags="-g -O0 -fno-omit-frame-pointer"
            " -fprofile-instr-generate -fcoverage-mapping"
            " -Wno-error=format",
            ldflags="-fprofile-instr-generate -lcrypt -lm",
        )

    def _build_coverage_modules(self, cc: str, cov_root: Path) -> List[Path]:
        """Build coverage-instrumented copies of external modules (.so).

        Looks for module sources in EXTERNAL_MODULES_DIR, compiles each with
        coverage flags, and places them in <work_dir>/modules/ (overwriting
        the AFL-instrumented version).  Returns the list of built .so paths.
        """
        from apache_fuzzer.config import Config

        modules_dir = self.work_dir / "modules"
        if not Config.EXTERNAL_MODULES_DIR.exists():
            return []

        sources = list(Config.EXTERNAL_MODULES_DIR.glob("*.c"))
        if not sources:
            return []

        modules_dir.mkdir(exist_ok=True)
        built = []

        includes = [
            f"-I{cov_root}/include",
            f"-I{cov_root}/srclib/apr/include",
            f"-I{cov_root}/srclib/apr-util/include",
            f"-I{cov_root}/os/unix",
            f"-I{cov_root}/server",
        ]
        mods = cov_root / "modules"
        if mods.exists():
            for p in mods.iterdir():
                if p.is_dir():
                    includes.append(f"-I{p}")

        for src in sources:
            name = src.stem
            output = modules_dir / f"{name}.so"
            cmd = [
                cc, "-fPIC", "-shared",
                "-g", "-O0",
                "-fprofile-instr-generate", "-fcoverage-mapping",
                "-o", str(output),
                str(src),
                *includes,
            ]
            self.logger.info(f"Building coverage-instrumented {name}.so ...")
            try:
                subprocess.run(cmd, check=True, capture_output=True, text=True)
                built.append(output)
            except subprocess.CalledProcessError as e:
                self.logger.warning(f"Failed to build coverage {name}.so: {e.stderr}")

        return built

    def _build_coverage_harness(self, cc: str) -> Tuple[Path, Path]:
        """Build fuzz_harness_coverage with coverage instrumentation flags.

        Uses the separate coverage build tree so the AFL build is untouched.
        Returns (harness_path, cov_httpd_root).
        """
        cov_root = self._ensure_coverage_build(cc)

        build_config = self.config_manager.generate_build_config()
        cflags = build_config.get("CFLAGS", "")
        ldflags = build_config.get("LDFLAGS", "")

        # Skip harness rebuild if it's already newer than the coverage libs
        harness = self.work_dir / ".libs" / "fuzz_harness_coverage"
        libmain = cov_root / "server" / "libmain.la"
        if harness.exists() and libmain.exists():
            if harness.stat().st_mtime > libmain.stat().st_mtime:
                self.logger.info(f"Coverage harness up to date: {harness}")
                return harness, cov_root

        builder = HarnessBuilder(cov_root)
        self.logger.info("Building coverage-instrumented harness...")
        builder.build(mode="coverage", cflags=cflags, ldflags=ldflags, cc=cc)

        # The real binary is in .libs/ (libtool wrapper is in cwd)
        harness = self.work_dir / ".libs" / "fuzz_harness_coverage"
        if not harness.exists():
            harness = self.work_dir / "fuzz_harness_coverage"
        if not harness.exists():
            raise FileNotFoundError("Failed to build fuzz_harness_coverage")

        self.logger.info(f"Coverage harness built: {harness}")
        return harness, cov_root

    def _replay_corpus(
        self, harness: Path, queue_dir: Path, prof_dir: Path, config_path: Path,
        httpd_root: Optional[Path] = None,
    ) -> int:
        """Replay AFL queue through coverage harness, producing .profraw files."""
        env = os.environ.copy()
        # Set env vars for LIBFUZZER/AFL entry points (kept for compatibility)
        env["FUZZ_CONF"] = str(config_path)
        env["FUZZ_ROOT"] = str(self.work_dir)
        env["LD_LIBRARY_PATH"] = self._get_ld_library_path(httpd_root)

        # The standalone entry point (used by coverage builds) reads -f/-d
        # command-line args, not FUZZ_CONF/FUZZ_ROOT env vars.
        harness_cmd = [
            str(harness),
            "-f", str(config_path),
            "-d", str(self.work_dir),
        ]

        # Collect test cases (AFL names them id:NNNNNN,...)
        test_cases = sorted(queue_dir.glob("id:*"))
        if not test_cases:
            # Fall back: try all files
            test_cases = sorted(
                f for f in queue_dir.iterdir() if f.is_file() and f.name != ".state"
            )

        if not test_cases:
            self.logger.error(f"No test cases found in {queue_dir}")
            return 0

        self.logger.info(f"Replaying {len(test_cases)} test cases...")

        count = 0
        for i, tc in enumerate(test_cases):
            prof_file = prof_dir / f"prof-{i}.profraw"
            run_env = env.copy()
            run_env["LLVM_PROFILE_FILE"] = str(prof_file)

            try:
                with open(tc, "rb") as stdin_f:
                    subprocess.run(
                        harness_cmd,
                        stdin=stdin_f,
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                        env=run_env,
                        timeout=10,
                    )
                count += 1
            except subprocess.TimeoutExpired:
                self.logger.warning(f"Timeout replaying {tc.name}, skipping")
            except Exception as e:
                self.logger.warning(f"Error replaying {tc.name}: {e}")

        self.logger.info(f"Replayed {count}/{len(test_cases)} test cases")
        return count

    def generate_coverage(
        self,
        afl_dir: str = "afl-output",
        config_name: str = "fuzz.conf",
        output_dir: str = "coverage-report",
    ) -> None:
        """Full coverage pipeline: build harness, replay corpus, merge, generate report."""
        # Detect LLVM toolchain (matched compiler + analysis tools)
        try:
            profdata_bin, cov_bin, cc = self._detect_llvm_toolchain()
        except FileNotFoundError as e:
            self.logger.error(str(e))
            return

        # 2. Find AFL queue
        queue_dir = self._find_afl_queue(afl_dir)
        if not queue_dir:
            return

        # Build coverage harness (uses separate -cov tree, AFL build untouched)
        try:
            harness, cov_root = self._build_coverage_harness(cc)
        except Exception as e:
            self.logger.error(f"Failed to build coverage harness: {e}")
            return

        # Build coverage-instrumented external modules (e.g. mod_pwn.so)
        cov_modules = self._build_coverage_modules(cc, cov_root)

        # Resolve httpd config
        config_path = self.config_manager.get_httpd_config(config_name)
        if not config_path:
            self.logger.error(f"Config '{config_name}' not found")
            return

        # 5. Replay corpus
        prof_dir = Path(output_dir).resolve() / "profraw"
        prof_dir.mkdir(parents=True, exist_ok=True)

        count = self._replay_corpus(harness, queue_dir, prof_dir, config_path, httpd_root=cov_root)
        if count == 0:
            self.logger.error("No test cases were replayed successfully")
            return

        # Merge profraw files
        profraw_files = list(prof_dir.glob("*.profraw"))
        if not profraw_files:
            self.logger.error("No .profraw files generated")
            return

        merged_profdata = Path(output_dir).resolve() / "merged.profdata"
        self.logger.info(f"Merging {len(profraw_files)} profraw files...")
        merge_cmd = [
            profdata_bin, "merge", "-sparse",
            *[str(f) for f in profraw_files],
            "-o", str(merged_profdata),
        ]
        try:
            subprocess.run(merge_cmd, check=True, capture_output=True, text=True)
        except subprocess.CalledProcessError as e:
            self.logger.error(f"llvm-profdata merge failed: {e.stderr}")
            return

        # Generate HTML report
        html_dir = Path(output_dir).resolve() / "html"
        html_dir.mkdir(parents=True, exist_ok=True)

        self.logger.info("Generating HTML coverage report...")
        extra_objects = [f"--object={so}" for so in cov_modules]
        show_cmd = [
            cov_bin, "show",
            str(harness),
            *extra_objects,
            f"-instr-profile={merged_profdata}",
            "-format=html",
            f"-output-dir={html_dir}",
            "-show-line-counts-or-regions",
            "-show-instantiations=false",
        ]
        try:
            subprocess.run(show_cmd, check=True, capture_output=True, text=True)
        except subprocess.CalledProcessError as e:
            self.logger.error(f"llvm-cov show failed: {e.stderr}")
            return

        # Print summary
        self.logger.info("Coverage summary:")
        report_cmd = [
            cov_bin, "report",
            str(harness),
            *extra_objects,
            f"-instr-profile={merged_profdata}",
        ]
        try:
            result = subprocess.run(
                report_cmd, check=True, capture_output=True, text=True
            )
            print(result.stdout)
        except subprocess.CalledProcessError as e:
            self.logger.error(f"llvm-cov report failed: {e.stderr}")
            return

        self.logger.info(f"HTML report: {html_dir / 'index.html'}")
        self.logger.info("Coverage report complete. AFL build is untouched.")

    def triage_crash(self, crash_file: Path, harness_binary: Path) -> None:
        self.logger.info(f"Triaging crash: {crash_file}")

        config_path = self.config_manager.get_httpd_config()
        if not config_path:
            self.logger.error("Config not found for triage.")
            return

        env = os.environ.copy()
        env["FUZZ_CONF"] = str(config_path)
        env["FUZZ_ROOT"] = str(self.work_dir)
        env["LD_LIBRARY_PATH"] = self._get_ld_library_path()

        # Preload the APR crypto DSO so the AFL-instrumented harness can
        # resolve __afl_area_ptr when mod_session_crypto dlopen()s it.
        crypto_so = self.httpd_root / "srclib" / "apr-util" / "crypto" / ".libs" / "apr_crypto_openssl-1.so"
        if crypto_so.exists():
            existing = env.get("LD_PRELOAD", "")
            env["LD_PRELOAD"] = f"{crypto_so}:{existing}" if existing else str(crypto_so)

        # NOTE: LD_PRELOAD is inherited by child processes, but the harness
        # calls unsetenv("LD_PRELOAD") early so that ASan's llvm-symbolizer
        # subprocess doesn't inherit the AFL-instrumented crypto DSO.

        # Build command with both env vars (AFL entry point) and
        # command-line args (standalone entry point) for config/root.
        cmd = [
            str(harness_binary),
            "-f", str(config_path),
            "-d", str(self.work_dir),
        ]

        try:
            crash_data = Path(crash_file).read_bytes()
            # Run harness with crash input piped to stdin.
            # We use subprocess directly because ProcessRunner doesn't
            # support binary stdin.
            result = subprocess.run(
                cmd, env=env, input=crash_data,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                timeout=30,
            )

            self.logger.info("Crash Output (Stderr):")
            print(result.stderr.decode("utf-8", errors="replace"))

            if result.stdout:
                self.logger.info("Stdout:")
                print(result.stdout.decode("utf-8", errors="replace"))

        except subprocess.TimeoutExpired:
            self.logger.error("Triage timed out (30s)")
        except Exception as e:
            self.logger.error(f"Failed to triage crash: {e}")
