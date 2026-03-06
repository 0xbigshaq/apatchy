"""Coverage-report generation and crash triage.

:class:`ReportManager` drives the full coverage pipeline - building
a coverage-instrumented harness, replaying the AFL corpus, merging
profraw data, and producing an HTML report via ``llvm-cov``.  It also
provides :meth:`~ReportManager.triage_crash` for reproducing
individual crash inputs.
"""

import os
import shutil
import subprocess
from pathlib import Path
from typing import List, Optional, Tuple

from apatchy.core import toolchain_config
from apatchy.core.harness import HarnessBuilder
from apatchy.core.process_runner import ProcessRunner
from apatchy.managers.config_manager import ConfigManager
from apatchy.utils.build_tree import AlternateBuildTree
from apatchy.utils.logger import get_logger

logger = get_logger(__name__)


class ReportManager:
    """Generate LLVM-based coverage reports and triage crash inputs."""

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
            result = subprocess.run([cc, "--version"], capture_output=True, text=True, timeout=5)
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

        Resolution order:
        - ``toolchain.config`` - honours ``apatchy setup llvm`` results.
        - Co-located binaries in the same directory as the compiler.
        - PATH search.

        Returns (profdata_bin, cov_bin, cc).
        """
        # Build a list of candidate clang binaries, newest first
        candidates = [f"clang-{v}" for v in range(20, 10, -1)] + ["clang"]

        for cc in candidates:
            cc_path = toolchain_config.resolve_tool(cc)
            if not cc_path:
                continue
            major = self._clang_major_version(cc_path)
            if major is None:
                continue

            profdata_name = f"llvm-profdata-{major}"
            cov_name = f"llvm-cov-{major}"

            # Check toolchain.config
            profdata_cfg = toolchain_config.resolve_tool(profdata_name, section="coverage")
            cov_cfg = toolchain_config.resolve_tool(cov_name, section="coverage")
            if profdata_cfg and cov_cfg:
                self.logger.info(f"using LLVM-{major} from toolchain config")
                return profdata_cfg, cov_cfg, cc_path

            # Co-located binaries next to the compiler
            cc_dir = str(Path(cc_path).parent)
            profdata_colocated = Path(cc_dir) / profdata_name
            cov_colocated = Path(cc_dir) / cov_name
            if profdata_colocated.is_file() and cov_colocated.is_file():
                self.logger.info(f"using LLVM-{major} (co-located with {cc_path})")
                return str(profdata_colocated), str(cov_colocated), cc_path

            # Fall back to PATH
            profdata_path = shutil.which(profdata_name)
            cov_path = shutil.which(cov_name)
            if profdata_path and cov_path:
                self.logger.info(f"using LLVM-{major} from PATH")
                return profdata_path, cov_path, cc_path

        raise FileNotFoundError(
            "No matched LLVM toolchain found. Install a complete set, e.g.: apt install clang-14 llvm-14"
        )

    def _find_afl_instances(self, afl_dir: str) -> List[Path]:
        """Find all AFL++ instance directories (supports single and parallel layouts).

        Returns a list of instance directories, each expected to contain
        queue/ and optionally crashes/ subdirectories.

        Layouts handled:
        - Single:   <afl_dir>/default/queue   -> [<afl_dir>/default]
        - Parallel:  <afl_dir>/main01/queue, <afl_dir>/sec01/queue, ...
        - Flat:      <afl_dir>/queue           -> [<afl_dir>]
        """
        afl_path = Path(afl_dir).resolve()
        if not afl_path.exists():
            self.logger.error(f"AFL output directory not found: {afl_path}")
            return []

        instances = []

        # Check every subdirectory for a queue/ folder (covers default/,
        # main01/, sec01/, sec02/, etc.)
        for child in sorted(afl_path.iterdir()):
            if child.is_dir() and (child / "queue").is_dir():
                instances.append(child)

        # Flat layout: queue/ directly under afl_dir
        if not instances and (afl_path / "queue").is_dir():
            instances.append(afl_path)

        if instances:
            names = [p.name for p in instances]
            self.logger.info(f"Found {len(instances)} AFL instance(s): {', '.join(names)}")
        else:
            self.logger.error(
                f"No queue directories found in {afl_path}. "
                "Expected <instance>/queue subdirectories (e.g. default/queue, main01/queue)."
            )

        return instances

    @staticmethod
    def _find_llvm_symbolizer() -> Optional[str]:
        """Locate ``llvm-symbolizer`` on the system.

        Resolution order:
        - ``toolchain.config`` - picks up locally-downloaded copies.
        2. Unversioned ``llvm-symbolizer`` in PATH.
        3. Versioned binary matching the compiler version.
        4. Lowest available versioned binary in PATH.
        """
        # Check toolchain.config
        for name in ("llvm-symbolizer",):
            path = toolchain_config.resolve_tool(name)
            if path:
                return path

        # Also try versioned names from config
        compiler_ver: Optional[int] = None
        try:
            out = subprocess.check_output(
                ["afl-clang-fast", "--version"],
                stderr=subprocess.DEVNULL,
                text=True,
                timeout=5,
            )
            import re

            m = re.search(r"clang version (\d+)", out)
            if m:
                compiler_ver = int(m.group(1))
        except (OSError, subprocess.SubprocessError):
            pass

        if compiler_ver:
            path = toolchain_config.resolve_tool(f"llvm-symbolizer-{compiler_ver}")
            if path:
                return path

        # Unversioned in PATH
        plain = shutil.which("llvm-symbolizer")
        if plain:
            return plain

        # 3-4. Scan PATH for versioned variants.
        candidates: dict[int, str] = {}
        for d in os.environ.get("PATH", "").split(":"):
            try:
                entries = os.listdir(d)
            except OSError:
                continue
            for name in entries:
                if name.startswith("llvm-symbolizer-"):
                    suffix = name.split("-")[-1]
                    try:
                        ver = int(suffix)
                    except ValueError:
                        continue
                    candidates.setdefault(ver, os.path.join(d, name))

        if not candidates:
            return None

        # Prefer the version matching the compiler, else lowest available.
        if compiler_ver and compiler_ver in candidates:
            return candidates[compiler_ver]
        return candidates[min(candidates)]

    def _ensure_coverage_build(self, cc: str) -> Path:
        """Ensure the separate coverage tree is configured and compiled.

        Returns the Path to the coverage httpd root.
        """
        tree = AlternateBuildTree(self.httpd_root, "-cov")
        return tree.ensure_build(
            cc=cc,
            cflags="-g -O0 -fno-omit-frame-pointer -fprofile-instr-generate -fcoverage-mapping -Wno-error",
            ldflags="-fprofile-instr-generate -lcrypt -lm",
        )

    def _build_coverage_modules(self, cc: str, cov_root: Path) -> List[Path]:
        """Build coverage-instrumented copies of external modules (.so).

        Looks for module sources in EXTERNAL_MODULES_DIR, compiles each with
        coverage flags, and places them in <work_dir>/modules/ (overwriting
        the AFL-instrumented version).  Returns the list of built .so paths.
        """
        from apatchy.config import Config

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
                cc,
                "-fPIC",
                "-shared",
                "-g",
                "-O0",
                "-fprofile-instr-generate",
                "-fcoverage-mapping",
                "-o",
                str(output),
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

    def _build_coverage_harness(self, cc: str, harness_name: str = None) -> Tuple[Path, Path]:
        """Build fuzz_harness_coverage with coverage instrumentation flags.

        Uses the separate coverage build tree so the AFL build is untouched.
        Returns (harness_path, cov_httpd_root).
        """
        cov_root = self._ensure_coverage_build(cc)

        build_config = self.config_manager.generate_build_config()
        cflags = build_config.get("CFLAGS", "")
        ldflags = build_config.get("LDFLAGS", "")

        # Skip harness rebuild if it's already newer than the coverage libs
        harness = self.work_dir / "fuzz_harness_coverage"
        if not harness.exists():
            harness = self.work_dir / ".libs" / "fuzz_harness_coverage"
        libmain = cov_root / "server" / "libmain.la"
        if harness.exists() and libmain.exists() and harness.stat().st_mtime > libmain.stat().st_mtime:
            self.logger.info(f"Coverage harness up to date: {harness}")
            return harness, cov_root

        builder = HarnessBuilder(cov_root)
        self.logger.info("Building coverage-instrumented harness...")
        builder.build(mode="coverage", cflags=cflags, ldflags=ldflags, cc=cc, harness_name=harness_name)

        # With static APR (--disable-shared), the binary is in cwd.
        # Fall back to .libs/ for older shared-library builds.
        harness = self.work_dir / "fuzz_harness_coverage"
        if not harness.exists():
            harness = self.work_dir / ".libs" / "fuzz_harness_coverage"
        if not harness.exists():
            raise FileNotFoundError("Failed to build fuzz_harness_coverage")

        self.logger.info(f"Coverage harness built: {harness}")
        return harness, cov_root

    def _replay_corpus(
        self,
        harness: Path,
        queue_dir: Path,
        prof_dir: Path,
        config_path: Path,
        httpd_root: Optional[Path] = None,
        prof_offset: int = 0,
    ) -> int:
        """Replay AFL queue through coverage harness, producing .profraw files."""
        env = os.environ.copy()
        # Set env vars for LIBFUZZER/AFL entry points (kept for compatibility)
        env["FUZZ_CONF"] = str(config_path)
        env["FUZZ_ROOT"] = str(self.work_dir)

        # The standalone entry point (used by coverage builds) reads -f/-d
        # command-line args, not FUZZ_CONF/FUZZ_ROOT env vars.
        harness_cmd = [
            str(harness),
            "-f",
            str(config_path),
            "-d",
            str(self.work_dir),
        ]

        # Collect test cases (AFL names them id:NNNNNN,...)
        test_cases = sorted(queue_dir.glob("id:*"))
        if not test_cases:
            # Fall back: try all files
            test_cases = sorted(f for f in queue_dir.iterdir() if f.is_file() and f.name != ".state")

        if not test_cases:
            self.logger.error(f"No test cases found in {queue_dir}")
            return 0

        self.logger.info(f"Replaying {len(test_cases)} test cases...")

        count = 0
        for i, tc in enumerate(test_cases):
            prof_file = prof_dir / f"prof-{prof_offset + i}.profraw"
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
        harness_name: str = None,
    ) -> None:
        """Full coverage pipeline: build harness, replay corpus, merge, generate report."""
        # Detect LLVM toolchain (matched compiler + analysis tools)
        try:
            profdata_bin, cov_bin, cc = self._detect_llvm_toolchain()
        except FileNotFoundError as e:
            self.logger.error(str(e))
            return

        # Find AFL instances
        instances = self._find_afl_instances(afl_dir)
        if not instances:
            return

        # Build coverage harness (uses separate -cov tree, AFL build untouched)
        try:
            harness, cov_root = self._build_coverage_harness(cc, harness_name=harness_name)
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

        # Replay corpus from all instances (queue + crashes)
        prof_dir = Path(output_dir).resolve() / "profraw"
        prof_dir.mkdir(parents=True, exist_ok=True)

        count = 0
        for instance in instances:
            queue_dir = instance / "queue"
            self.logger.info(f"Replaying queue from {instance.name}/ ({len(list(queue_dir.iterdir()))} entries)...")
            count += self._replay_corpus(
                harness, queue_dir, prof_dir, config_path, httpd_root=cov_root, prof_offset=count
            )

            crashes_dir = instance / "crashes"
            if crashes_dir.is_dir() and any(crashes_dir.iterdir()):
                self.logger.info(f"Replaying crashes from {instance.name}/...")
                count += self._replay_corpus(
                    harness, crashes_dir, prof_dir, config_path, httpd_root=cov_root, prof_offset=count
                )

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
            profdata_bin,
            "merge",
            "-sparse",
            *[str(f) for f in profraw_files],
            "-o",
            str(merged_profdata),
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
            cov_bin,
            "show",
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
            cov_bin,
            "report",
            str(harness),
            *extra_objects,
            f"-instr-profile={merged_profdata}",
        ]
        try:
            result = subprocess.run(report_cmd, check=True, capture_output=True, text=True)
            print(result.stdout)
        except subprocess.CalledProcessError as e:
            self.logger.error(f"llvm-cov report failed: {e.stderr}")
            return

        self.logger.info(f"HTML report: {html_dir / 'index.html'}")
        self.logger.info("Coverage report complete. AFL build is untouched.")

    def _triage_env(
        self,
        no_color: bool = False,
        suppress: Optional[str] = None,
    ) -> Tuple[dict, Optional[Path]]:
        """Build the environment dict shared by single-crash and pipeline triage."""
        config_path = self.config_manager.get_httpd_config()
        if not config_path:
            raise FileNotFoundError("Config not found for triage.")

        supp_path = None
        if suppress:
            supp_path = Path(suppress).resolve()
            if not supp_path.exists():
                raise FileNotFoundError(f"Suppression file not found: {supp_path}")
            self.logger.info(f"Using UBSan suppression file: {supp_path}")

        env = os.environ.copy()
        env["FUZZ_CONF"] = str(config_path)
        env["FUZZ_ROOT"] = str(self.work_dir)

        symbolizer = self._find_llvm_symbolizer()
        if symbolizer:
            env["ASAN_SYMBOLIZER_PATH"] = symbolizer
            self.logger.debug(f"Using symbolizer: {symbolizer}")

        color_val = "never" if no_color else "always"
        for var in ("ASAN_OPTIONS", "UBSAN_OPTIONS", "LSAN_OPTIONS"):
            existing = env.get(var, "")
            env[var] = f"{existing}:color={color_val}" if existing else f"color={color_val}"

        existing = env.get("UBSAN_OPTIONS", "")
        env["UBSAN_OPTIONS"] = f"{existing}:print_stacktrace=1"

        if supp_path:
            existing = env.get("UBSAN_OPTIONS", "")
            supp_opt = f"suppressions={supp_path}"
            env["UBSAN_OPTIONS"] = f"{existing}:{supp_opt}" if existing else supp_opt

        env["AFL_IGNORE_PROBLEMS"] = "1"

        return env, config_path

    def triage_pipeline(
        self,
        crash_dir: Path,
        harness_binary: Path,
        no_color: bool = False,
        suppress: Optional[str] = None,
        timeout: int = 30,
    ) -> None:
        r"""Concatenate numbered crash files from *crash_dir* and replay them.

        Files are sorted numerically (0, 1, 2, ...).  The harness must be
        built from ``mod_fuzzy_multi`` so it splits on ``\r\n\r\n``
        boundaries.
        """
        crash_dir = Path(crash_dir)
        if not crash_dir.is_dir():
            self.logger.error(f"Not a directory: {crash_dir}")
            return

        # Collect and sort files lexicographically.  Works for both plain
        # numeric names (0, 1, 2) and AFL crash IDs (id:000000, id:000001, ...)
        # since AFL zero-pads the IDs.
        files = sorted(
            (f for f in crash_dir.iterdir() if f.is_file()),
            key=lambda f: f.name,
        )
        if not files:
            self.logger.error(f"No files found in {crash_dir}")
            return

        self.logger.info(f"Pipeline triage: {len(files)} crash files from {crash_dir}")
        for f in files:
            self.logger.info(f"  [{f.name}] {f}")

        # Concatenate all crash data.  The multi harness splits on \r\n\r\n.
        combined = b""
        for f in files:
            data = f.read_bytes()
            combined += data
            # Make sure segment ends with \r\n\r\n so the multi harness
            # sees it as a complete request.
            if not data.endswith(b"\r\n\r\n"):
                combined += b"\r\n\r\n"

        try:
            env, config_path = self._triage_env(no_color=no_color, suppress=suppress)
        except FileNotFoundError as e:
            self.logger.error(str(e))
            return

        cmd = [
            str(harness_binary),
            "-f",
            str(config_path),
            "-d",
            str(self.work_dir),
        ]

        try:
            result = subprocess.run(  # noqa: UP022
                cmd,
                env=env,
                input=combined,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=timeout,
            )

            self.logger.info("Crash Output (Stderr):")
            print(result.stderr.decode("utf-8", errors="replace"))

            if result.stdout:
                self.logger.info("Stdout:")
                print(result.stdout.decode("utf-8", errors="replace"))

        except subprocess.TimeoutExpired:
            self.logger.error(f"Triage timed out ({timeout}s)")
        except Exception as e:
            self.logger.error(f"Failed to triage pipeline: {e}")

    def triage_crash(
        self,
        crash_file: Path,
        harness_binary: Path,
        no_color: bool = False,
        suppress: Optional[str] = None,
        timeout: int = 30,
    ) -> None:
        """Replay *crash_file* through *harness_binary* and print the sanitizer output.

        *suppress* is an optional path to a UBSan runtime suppression
        file (passed via ``UBSAN_OPTIONS=suppressions=``).  *timeout*
        controls how long the harness is allowed to run before being
        killed.
        """
        self.logger.info(f"Triaging crash: {crash_file}")

        try:
            env, config_path = self._triage_env(no_color=no_color, suppress=suppress)
        except FileNotFoundError as e:
            self.logger.error(str(e))
            return

        cmd = [
            str(harness_binary),
            "-f",
            str(config_path),
            "-d",
            str(self.work_dir),
        ]

        try:
            crash_data = Path(crash_file).read_bytes()
            # Run harness with crash input piped to stdin.
            # We use subprocess directly because ProcessRunner doesn't
            # support binary stdin.
            result = subprocess.run(  # noqa: UP022
                cmd,
                env=env,
                input=crash_data,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=timeout,
            )

            self.logger.info("Crash Output (Stderr):")
            print(result.stderr.decode("utf-8", errors="replace"))

            if result.stdout:
                self.logger.info("Stdout:")
                print(result.stdout.decode("utf-8", errors="replace"))

        except subprocess.TimeoutExpired:
            self.logger.error(f"Triage timed out ({timeout}s)")
        except Exception as e:
            self.logger.error(f"Failed to triage crash: {e}")
