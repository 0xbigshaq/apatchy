"""Coverage-report generation and crash triage.

:class:`ReportManager` drives the full coverage pipeline - building
a coverage-instrumented harness, replaying the AFL corpus, merging
profraw data, and producing an HTML report via ``llvm-cov``.  It also
provides :meth:`~ReportManager.triage_crash` for reproducing
individual crash inputs.
"""

import contextlib
import json
import os
import re
import shutil
import signal
import subprocess
import tempfile
import threading
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import List, Optional, Tuple

from rich.console import Console
from rich.console import Group as RichGroup
from rich.live import Live
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn
from rich.table import Table

from apatchy.compat import extract_version_from_path, get_compat_flags
from apatchy.core import toolchain_config
from apatchy.core.harness import HarnessBuilder
from apatchy.core.process_runner import ProcessRunner
from apatchy.managers.config_manager import ConfigManager
from apatchy.utils.build_tree import AlternateBuildTree
from apatchy.utils.logger import get_logger
from apatchy.utils.ui import UI, run_stream_panel

logger = get_logger(__name__)


class ReportManager:
    """Generate LLVM-based coverage reports and triage crash inputs."""

    def __init__(self, httpd_root: Path, config_manager: ConfigManager) -> None:
        self.httpd_root = httpd_root
        self.config_manager = config_manager
        self.logger = logger
        self.runner = ProcessRunner()
        self.work_dir = Path(".").resolve()

    def _inject_dark_mode_css(self, html_dir: Path) -> None:
        """Inject dark-mode CSS and shorten display paths in llvm-cov HTML."""
        css_path = Path(__file__).resolve().parent.parent / "templates" / "coverage_dark.css"
        if not css_path.is_file():
            self.logger.warning("Dark-mode CSS not found, skipping injection")
            return
        dark_css = css_path.read_text()
        style_tag = f"\n<style>\n{dark_css}</style>\n"
        prefix = str(self.work_dir).lstrip("/") + "/"
        display_prefix = ">" + prefix
        display_replacement = ">"
        count = 0
        for html_file in html_dir.rglob("*.html"):
            try:
                content = html_file.read_text(encoding="utf-8", errors="surrogateescape")
            except Exception:
                continue
            if "</head>" in content:
                content = content.replace("</head>", style_tag + "</head>", 1)
                content = content.replace(display_prefix, display_replacement)
                html_file.write_text(content, encoding="utf-8", errors="surrogateescape")
                count += 1
        self.logger.info(f"Injected dark-mode CSS into {count} HTML files")

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
        cflags = [
            "-g",
            "-O0",
            "-fno-omit-frame-pointer",
            "-fprofile-instr-generate",
            "-fcoverage-mapping",
            "-Wno-error",
        ]
        ldflags = ["-fprofile-instr-generate", "-lcrypt", "-lm"]

        httpd_version = extract_version_from_path(self.httpd_root)
        if httpd_version:
            compat = get_compat_flags(httpd_version)
            for entry_id in compat.applied_ids:
                logger.info(f"Applying compat fix: {entry_id}")
            cflags.extend(compat.cflags)
            ldflags.extend(compat.ldflags)

        tree = AlternateBuildTree(self.httpd_root, "-cov")
        return tree.ensure_build(
            cc=cc,
            cflags=" ".join(cflags),
            ldflags=" ".join(ldflags),
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
        libmain = cov_root / "server" / "libmain.la"
        if harness.exists() and libmain.exists() and harness.stat().st_mtime > libmain.stat().st_mtime:
            self.logger.info(f"Coverage harness up to date: {harness}")
            return harness, cov_root

        builder = HarnessBuilder(cov_root)
        self.logger.info("Building coverage-instrumented harness...")
        builder.build(mode="coverage", cflags=cflags, ldflags=ldflags, cc=cc, harness_name=harness_name)

        harness = self.work_dir / "fuzz_harness_coverage"
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
        jobs: int = 1,
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

        total = len(test_cases)
        workers = min(jobs, total)
        self.logger.info(f"Replaying {total} test cases ({workers} workers)...")

        count = 0
        progress = Progress(
            SpinnerColumn(),
            BarColumn(bar_width=20),
            TextColumn("[progress.description]{task.description}"),
            TextColumn("{task.completed}/{task.total}"),
        )
        overall_task = progress.add_task("Overall", total=total)

        # Pre-assign test cases to workers via round-robin
        worker_batches: list[list[tuple[int, Path]]] = [[] for _ in range(workers)]
        for i, tc in enumerate(test_cases):
            worker_batches[i % workers].append((i, tc))

        worker_task_ids = [progress.add_task(f"  Worker {w + 1}", total=len(worker_batches[w])) for w in range(workers)]

        def _run_worker(worker_id: int) -> int:
            ok = 0
            for i, tc in worker_batches[worker_id]:
                name = tc.name[:70].ljust(70)
                progress.update(worker_task_ids[worker_id], description=f"  [cyan]{name}[/]")
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
                    ok += 1
                except subprocess.TimeoutExpired:
                    self.logger.warning(f"Timeout replaying {tc.name}, skipping")
                except Exception as e:
                    self.logger.warning(f"Error replaying {tc.name}: {e}")
                progress.advance(worker_task_ids[worker_id])
                progress.advance(overall_task)
            progress.update(worker_task_ids[worker_id], description="  Done")
            return ok

        with Live(progress, console=Console(stderr=True), refresh_per_second=10):
            with ThreadPoolExecutor(max_workers=workers) as pool:
                futures = [pool.submit(_run_worker, w) for w in range(workers)]
                for future in as_completed(futures):
                    count += future.result()

            for tid in worker_task_ids:
                progress.remove_task(tid)
            progress.update(overall_task, description="Done", completed=total)

        self.logger.info(f"Replayed {count}/{total} test cases")
        return count

    def generate_coverage(
        self,
        afl_dir: str = "afl-output",
        config_name: str = "fuzz.conf",
        output_dir: str = "coverage-report",
        harness_name: str = None,
        exclude_file: str | None = None,
        jobs: int = 1,
        with_introspect=False,
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
                harness, queue_dir, prof_dir, config_path, httpd_root=cov_root, prof_offset=count, jobs=jobs
            )

            crashes_dir = instance / "crashes"
            if crashes_dir.is_dir() and any(crashes_dir.iterdir()):
                self.logger.info(f"Replaying crashes from {instance.name}/...")
                count += self._replay_corpus(
                    harness, crashes_dir, prof_dir, config_path, httpd_root=cov_root, prof_offset=count, jobs=jobs
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
        source_filters = []
        if exclude_file:
            exclude_path = Path(exclude_file)
            if not exclude_path.is_file():
                self.logger.error(f"Exclude file not found: {exclude_file}")
                return
            lines = [line.strip() for line in exclude_path.read_text().splitlines() if line.strip()]
            if lines:
                regex = "|".join(lines)
                source_filters.append(f"--ignore-filename-regex={regex}")
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
            *source_filters,
        ]
        try:
            subprocess.run(show_cmd, check=True, capture_output=True, text=True)
        except subprocess.CalledProcessError as e:
            self.logger.error(f"llvm-cov show failed: {e.stderr}")
            return

        self._inject_dark_mode_css(html_dir)

        # Print summary. If the user chose the introspect option,
        # it's better off to keep the output log clean since there
        # are more steps to be executed down the flow.
        if with_introspect:
            self.logger.info("Merging LLVM bitcode files")
            self._merge_llvm_bitcode(cc)
        else:
            self.logger.info("Coverage summary:")
            report_cmd = [
                cov_bin,
                "report",
                str(harness),
                *extra_objects,
                f"-instr-profile={merged_profdata}",
                *source_filters,
            ]
            try:
                result = subprocess.run(report_cmd, check=True, capture_output=True, text=True)
                print(result.stdout)
            except subprocess.CalledProcessError as e:
                self.logger.error(f"llvm-cov report failed: {e.stderr}")
                return

        self.logger.info(f"HTML report: {html_dir / 'index.html'}")
        self.logger.info("HTML Coverage report complete.")

    def generate_introspect(
        self,
        entry: str,
        profdata_path: str | None = None,
        binary_path: str | None = None,
        bitcode_path: str | None = None,
        output_path: str = "introspect.json",
        serve: bool = True,
        port: int = 9000,
    ) -> None:
        """Merge call tree analysis with coverage data into a single JSON."""
        try:
            _, cov_bin, cc = self._detect_llvm_toolchain()
        except FileNotFoundError as e:
            self.logger.error(str(e))
            return

        cov_root = Path(str(self.httpd_root) + "-cov")

        # auto-detect profdata
        profdata = Path(profdata_path) if profdata_path else Path("coverage-report") / "merged.profdata"
        if not profdata.is_file():
            self.logger.error(f"profdata not found: {profdata}")
            return

        # auto-detect coverage binary
        binary = Path(binary_path) if binary_path else self.work_dir / "fuzz_harness_coverage"
        if not binary.is_file():
            self.logger.error(f"coverage binary not found: {binary}")
            return

        # auto-detect combined bitcode, rebuild if missing
        bitcode = Path(bitcode_path) if bitcode_path else cov_root / "bitcode" / "combined.bc"
        if not bitcode.is_file():
            self.logger.info("Bitcode not found, building...")
            self._merge_llvm_bitcode(cc)
        if not bitcode.is_file():
            self.logger.error(f"bitcode not found: {bitcode}")
            return

        # auto-detect entry point
        if not entry:
            major = self._clang_major_version(cc)
            llvm_nm = shutil.which(f"llvm-nm-{major}") or shutil.which("llvm-nm")
            if llvm_nm:
                try:
                    result = subprocess.run(
                        [llvm_nm, "--defined-only", str(bitcode)],
                        capture_output=True,
                        text=True,
                        timeout=30,
                    )
                    symbols = {line.split()[-1] for line in result.stdout.splitlines() if len(line.split()) >= 3}
                    if "LLVMFuzzerTestOneInput" in symbols:
                        entry = "LLVMFuzzerTestOneInput"
                    elif "main" in symbols:
                        entry = "main"
                except Exception:
                    pass
            if not entry:
                self.logger.error("could not detect entry point, use --entry")
                return
            self.logger.info(f"Auto-detected entry point: {entry}")

        # we need to find wuxi binary
        # TODO: should we compile it via the CLI too?
        wuxi = Path(__file__).resolve().parent.parent.parent.parent / "introspector" / "build" / "wuxi"
        if not wuxi.is_file():
            self.logger.error(f"wuxi not found: {wuxi} (build the introspector first)")
            return

        self.logger.info("Exporting coverage data...")
        cov_cmd = [
            cov_bin,
            "export",
            "--format=text",
            f"-instr-profile={profdata}",
            str(binary),
        ]
        try:
            cov_result = subprocess.run(cov_cmd, check=True, capture_output=True, text=True)
        except subprocess.CalledProcessError as e:
            self.logger.error(f"llvm-cov export failed: {e.stderr}")
            return
        cov_data = json.loads(cov_result.stdout)

        # build coverage lookup: function name -> {hit, count}
        # llvm-cov prefixes static function names with "file.c:func_name",
        # wuxi uses the raw LLVM IR name without prefix. build both a
        # direct lookup and a stripped-prefix fallback.
        cov_lookup = {}
        cov_stripped = {}
        for func in cov_data["data"][0]["functions"]:
            name = func["name"]
            count = func["count"]
            regions = func.get("regions", [])
            lines_total = len(regions)
            lines_covered = sum(1 for r in regions if r[4] > 0)
            cov_entry = {
                "hit": count > 0,
                "count": count,
                "regions_total": lines_total,
                "regions_covered": lines_covered,
            }
            cov_lookup[name] = cov_entry
            if ":" in name:
                bare = name.split(":", 1)[1]
                cov_stripped[bare] = cov_entry

        # run our wuxi cpp tool
        from apatchy.utils.ui import run_stream_panel

        wuxi_out = Path(tempfile.mktemp(suffix=".json"))
        wuxi_cmd = [str(wuxi), str(bitcode), entry, "-f", str(wuxi_out)]
        returncode, _ = run_stream_panel(
            wuxi_cmd,
            label=f"Running call tree analysis for '{entry}'...",
        )
        if returncode != 0:
            self.logger.error("wuxi failed")
            return
        introspect = json.loads(wuxi_out.read_text())
        wuxi_out.unlink(missing_ok=True)

        # rewrite source_dir from the original tree to the -cov tree so
        # coverage HTML links resolve correctly
        orig_prefix = str(self.httpd_root.resolve())
        cov_prefix = str(cov_root.resolve())
        for func_meta in introspect.get("functions", {}).values():
            sd = func_meta.get("source_dir", "")
            if sd.startswith(orig_prefix):
                func_meta["source_dir"] = cov_prefix + sd[len(orig_prefix) :]

        # merge coverage into functions (try direct match, then stripped-prefix fallback)
        merged_count = 0
        for func_name, func_meta in introspect.get("functions", {}).items():
            cov = cov_lookup.get(func_name) or cov_stripped.get(func_name)
            if cov:
                func_meta["coverage"] = cov
                merged_count += 1
            else:
                func_meta["coverage"] = {
                    "hit": False,
                    "count": 0,
                    "regions_total": 0,
                    "regions_covered": 0,
                }

        total = len(introspect.get("functions", {}))
        self.logger.info(f"Coverage merged for {merged_count}/{total} functions")

        # build per-file line coverage lookup from segments
        # segments are a state machine: [line, col, count, hasCount, ...]
        # a segment sets the execution count from its line until the next segment
        line_counts = {}
        for cov_file in cov_data["data"][0].get("files", []):
            fname = cov_file["filename"]
            segs = cov_file.get("segments", [])
            if not segs:
                continue
            lines = {}
            for i, seg in enumerate(segs):
                line, _col, count, has_count = seg[0], seg[1], seg[2], seg[3]
                if not has_count:
                    continue
                end_line = segs[i + 1][0] if i + 1 < len(segs) else line
                for ln in range(line, end_line + 1):
                    lines[ln] = max(lines.get(ln, 0), count)
            line_counts[fname] = lines

        # annotate call tree nodes with site_count
        functions = introspect.get("functions", {})

        def annotate_site_counts(node, parent_name=None):
            site_file = node.get("site_file", "")
            site_line = node.get("site_line", 0)
            if site_file and site_line and parent_name:
                caller = functions.get(parent_name, {})
                source_dir = caller.get("source_dir", "")
                if source_dir:
                    full_path = source_dir.rstrip("/") + "/" + site_file
                    file_lines = line_counts.get(full_path, {})
                    node["site_count"] = file_lines.get(site_line, -1)
                else:
                    node["site_count"] = -1
            else:
                node["site_count"] = -1
            for child in node.get("children", []):
                annotate_site_counts(child, node["name"])

        annotate_site_counts(introspect.get("call_tree", {}))

        # assemble output directory with GUI, data, and coverage report
        gui_dist = Path(__file__).resolve().parent.parent.parent.parent / "introspector" / "gui" / "dist"
        out_dir = Path("introspect-report")
        if out_dir.exists():
            shutil.rmtree(out_dir)

        if gui_dist.is_dir():
            shutil.copytree(gui_dist, out_dir)
        else:
            out_dir.mkdir(parents=True)
            self.logger.warning(f"GUI dist not found at {gui_dist}, output will have no viewer")

        (out_dir / "introspect.json").write_text(json.dumps(introspect, indent=2))

        # generate HTML coverage report directly into the output directory
        cov_html_dir = out_dir / "coverage-report" / "html"
        cov_html_dir.mkdir(parents=True, exist_ok=True)
        self.logger.info("Generating HTML coverage report...")
        show_cmd = [
            cov_bin,
            "show",
            str(binary),
            f"-instr-profile={profdata}",
            "-format=html",
            f"-output-dir={cov_html_dir}",
            "-show-line-counts-or-regions",
            "-show-instantiations=false",
        ]
        try:
            subprocess.run(show_cmd, check=True, capture_output=True, text=True)
        except subprocess.CalledProcessError as e:
            self.logger.warning(f"llvm-cov show failed, coverage links will not work: {e.stderr}")

        self._inject_dark_mode_css(cov_html_dir)

        # also write standalone JSON
        out = Path(output_path)
        out.write_text(json.dumps(introspect, indent=2))

        UI.print_success(f"Introspect report: {out_dir}/")

        if not serve:
            return

        import http.server

        self.logger.info(f"Serving introspect report on http://localhost:{port}")

        def handler(*a, **kw):
            return http.server.SimpleHTTPRequestHandler(*a, directory=str(out_dir), **kw)

        server = http.server.HTTPServer(("", port), handler)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            self.logger.info("Server stopped")

    def _ensure_profile_build(self, cc: str) -> Path:
        """Ensure a separate profile tree is configured and compiled.

        The profile tree uses ``-g -O0 -fno-omit-frame-pointer`` with no
        sanitizers or coverage instrumentation, producing clean binaries
        for valgrind/callgrind profiling.

        Returns the Path to the profile httpd root.
        """
        cflags = [
            "-g",
            "-gdwarf-4",
            "-O0",
            "-fno-omit-frame-pointer",
            "-Wno-error",
        ]
        ldflags = ["-lcrypt", "-lm"]

        httpd_version = extract_version_from_path(self.httpd_root)
        if httpd_version:
            compat = get_compat_flags(httpd_version)
            for entry_id in compat.applied_ids:
                logger.info(f"Applying compat fix: {entry_id}")
            cflags.extend(compat.cflags)
            ldflags.extend(compat.ldflags)

        tree = AlternateBuildTree(self.httpd_root, "-prof")
        return tree.ensure_build(
            cc=cc,
            cflags=" ".join(cflags),
            ldflags=" ".join(ldflags),
        )

    def _build_profile_harness(self, cc: str, harness_name: str = None) -> Tuple[Path, Path]:
        """Build fuzz_harness_profile with debug symbols and no sanitizers.

        Uses a separate ``-prof`` build tree so the AFL build is untouched.
        Returns (harness_path, prof_httpd_root).
        """
        prof_root = self._ensure_profile_build(cc)

        build_config = self.config_manager.generate_build_config()
        cflags = build_config.get("CFLAGS", "")
        ldflags = build_config.get("LDFLAGS", "")

        # Strip any sanitizer flags - they conflict with valgrind
        cflags = " ".join(t for t in cflags.split() if not t.startswith(("-fsanitize", "-fno-sanitize")))
        ldflags = " ".join(t for t in ldflags.split() if not t.startswith(("-fsanitize", "-fno-sanitize")))

        harness = self.work_dir / "fuzz_harness_profile"
        libmain = prof_root / "server" / "libmain.la"
        if harness.exists() and libmain.exists() and harness.stat().st_mtime > libmain.stat().st_mtime:
            self.logger.info(f"Profile harness up to date: {harness}")
            return harness, prof_root

        builder = HarnessBuilder(prof_root)
        self.logger.info("Building profile harness (debug symbols, no sanitizers)...")
        builder.build(mode="profile", cflags=cflags, ldflags=ldflags, cc=cc, harness_name=harness_name)

        harness = self.work_dir / "fuzz_harness_profile"
        if not harness.exists():
            raise FileNotFoundError("Failed to build fuzz_harness_profile")

        self.logger.info(f"Profile harness built: {harness}")
        return harness, prof_root

    def _replay_corpus_callgrind(
        self,
        harness: Path,
        queue_dir: Path,
        output_dir: Path,
        config_path: Path,
        prof_offset: int = 0,
        jobs: int = 1,
        timeout: int = 120,
    ) -> int:
        """Replay AFL queue through harness under callgrind, producing .callgrind files."""
        env = os.environ.copy()
        env["FUZZ_CONF"] = str(config_path)
        env["FUZZ_ROOT"] = str(self.work_dir)

        harness_cmd = [
            str(harness),
            "-f",
            str(config_path),
            "-d",
            str(self.work_dir),
        ]

        test_cases = sorted(queue_dir.glob("id:*"))
        if not test_cases:
            test_cases = sorted(f for f in queue_dir.iterdir() if f.is_file() and f.name != ".state")

        if not test_cases:
            self.logger.error(f"No test cases found in {queue_dir}")
            return 0

        total = len(test_cases)
        workers = min(jobs, total)
        self.logger.info(f"Replaying {total} test cases under callgrind ({workers} workers)...")

        count = 0
        cancel = threading.Event()
        worker_batches: list[list[tuple[int, Path]]] = [[] for _ in range(workers)]
        for i, tc in enumerate(test_cases):
            worker_batches[i % workers].append((i, tc))

        with Progress(
            SpinnerColumn(),
            BarColumn(bar_width=20),
            TextColumn("[progress.description]{task.description}"),
            TextColumn("{task.completed}/{task.total}"),
            console=Console(stderr=True),
            refresh_per_second=4,
        ) as progress:
            overall_task = progress.add_task("Overall", total=total)
            worker_task_ids = [
                progress.add_task(f"  Worker {w + 1}", total=len(worker_batches[w])) for w in range(workers)
            ]

            def _run_worker(worker_id: int) -> int:
                ok = 0
                for i, tc in worker_batches[worker_id]:
                    if cancel.is_set():
                        break
                    name = tc.name[:70].ljust(70)
                    progress.update(worker_task_ids[worker_id], description=f"  [cyan]{name}[/]")
                    callgrind_out = output_dir / f"callgrind.out.{prof_offset + i}"
                    cmd = [
                        "valgrind",
                        "--tool=callgrind",
                        f"--callgrind-out-file={callgrind_out}",
                        "--collect-jumps=yes",
                        *harness_cmd,
                    ]
                    try:
                        with open(tc, "rb") as stdin_f:
                            proc = subprocess.Popen(
                                cmd,
                                stdin=stdin_f,
                                stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL,
                                env=env,
                            )
                            try:
                                proc.wait(timeout=timeout)
                            except subprocess.TimeoutExpired:
                                proc.kill()
                                proc.wait()
                                self.logger.warning(f"Timeout replaying {tc.name}, skipping")
                        if proc.returncode is not None:
                            ok += 1
                    except Exception as e:
                        self.logger.warning(f"Error replaying {tc.name}: {e}")
                    progress.advance(worker_task_ids[worker_id])
                    progress.advance(overall_task)
                progress.update(worker_task_ids[worker_id], description="  Done")
                return ok

            try:
                with ThreadPoolExecutor(max_workers=workers) as pool:
                    futures = [pool.submit(_run_worker, w) for w in range(workers)]
                    for future in as_completed(futures):
                        count += future.result()
            except KeyboardInterrupt:
                cancel.set()
                for future in futures:
                    future.cancel()
                for future in futures:
                    if not future.cancelled():
                        with contextlib.suppress(Exception):
                            count += future.result(timeout=5)
                return -1

            for tid in worker_task_ids:
                progress.remove_task(tid)

        self.logger.info(f"Replayed {count}/{total} test cases")
        return count

    def generate_callgrind(
        self,
        afl_dir: str = "afl-output",
        config_name: str = "fuzz.conf",
        output_dir: str = "callgrind-out",
        harness_name: str = None,
        jobs: int = 1,
        timeout: int = 120,
    ) -> None:
        """Replay AFL corpus under callgrind and collect output for kcachegrind.

        Automatically builds a dedicated ``-prof`` Apache tree with debug
        symbols, no sanitizers, and no coverage instrumentation so that
        callgrind output is clean and all function names are visible.
        """
        # Check valgrind is available
        if not shutil.which("valgrind"):
            self.logger.error("valgrind not found. Install with: apt install valgrind")
            return

        # Find AFL instances
        instances = self._find_afl_instances(afl_dir)
        if not instances:
            return

        # Build profile harness (separate -prof tree, no sanitizers)
        try:
            harness_path, prof_root = self._build_profile_harness("clang", harness_name=harness_name)
        except Exception as e:
            self.logger.error(f"Failed to build profile harness: {e}")
            return

        # Resolve httpd config
        config_path = self.config_manager.get_httpd_config(config_name)
        if not config_path:
            self.logger.error(f"Config '{config_name}' not found")
            return

        # Replay corpus under callgrind
        out_path = Path(output_dir).resolve()
        out_path.mkdir(parents=True, exist_ok=True)

        count = 0
        interrupted = False
        for instance in instances:
            queue_dir = instance / "queue"
            self.logger.info(f"Replaying queue from {instance.name}/ ({len(list(queue_dir.iterdir()))} entries)...")
            result = self._replay_corpus_callgrind(
                harness_path, queue_dir, out_path, config_path, prof_offset=count, jobs=jobs, timeout=timeout
            )
            if result < 0:
                interrupted = True
                break
            count += result

        if interrupted:
            return

        if count == 0:
            self.logger.error("No test cases were replayed successfully")
            return

        callgrind_files = sorted(f for f in out_path.glob("callgrind.out.*") if f.stat().st_size > 0)
        self.logger.info(f"Generated {len(callgrind_files)} callgrind output files in {out_path}")

        first_file = out_path / "callgrind.out.0"
        is_wsl = "microsoft" in Path("/proc/version").read_text().lower() if Path("/proc/version").exists() else False
        viewer = "qcachegrind.exe" if is_wsl else "kcachegrind"
        self.logger.info(f"View with: {viewer} {first_file}")

        answer = input("\nOpen in viewer now? [y/N] ").strip().lower()
        if answer == "y":
            subprocess.Popen(
                [viewer, str(first_file)],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )

    @staticmethod
    def _parse_config_vars(path: Path) -> dict:
        config_vars = {}
        if not path.exists():
            return config_vars
        for line in path.read_text().splitlines():
            m = re.match(r"^(\w+)\s*=\s*(.*)", line)
            if m:
                config_vars[m.group(1)] = m.group(2).strip()
        return config_vars

    def _merge_llvm_bitcode(self, cc: str) -> None:

        cov_root = Path(str(self.httpd_root) + "-cov")
        bc_path = cov_root / "bitcode"
        bc_path.mkdir(exist_ok=True)

        exclude_dirs = {
            "test",
            "tests",
            "support",
            "tools",
            "build",
            "examples",
            "benchmark",
            "win32",
            "os2",
            "netware",
            "beos",
        }
        exclude_files = {"modules.bc", "gen_test_char.bc", "exports.bc"}

        compile_db = cov_root / "compile_commands.json"  # god bless this file!! saved us so much time
        if not compile_db.exists():
            config_vars = self._parse_config_vars(cov_root / "build" / "config_vars.mk")
            cflags = config_vars.get("CFLAGS", "")
            jobs = os.cpu_count() or 4
            bear_cmd = [
                "bear",
                "--",
                "make",
                f"-j{jobs}",
                f"CC={cc}",
                f"CFLAGS={cflags}",
            ]
            subprocess.run(
                ["make", "clean"],
                cwd=cov_root,
                capture_output=True,
                text=True,
            )
            rc, _ = run_stream_panel(
                bear_cmd,
                cwd=str(cov_root),
                label="Tracing objects for introspection",
            )
            if rc != 0:
                self.logger.error("bear failed")
                return

        if not compile_db.exists():
            self.logger.error("compile_commands.json not generated")
            return

        # harness entries first so their symbols (main, fuzz_one_input) take
        # priority over httpd's main during duplicate-symbol resolution
        entries = []
        harness_cdb = self.work_dir / "harnesses" / "compile_commands.json"
        if harness_cdb.is_file():
            entries.extend(json.loads(harness_cdb.read_text()))
        else:
            self.logger.warning("Harness compile_commands.json not found, run 'apatchy link --bear' first")
        entries.extend(json.loads(compile_db.read_text()))

        filtered = []
        for e in entries:
            if not e.get("file", "").endswith(".c"):
                continue
            src = Path(e["file"])
            try:
                rel = src.relative_to(cov_root)
            except ValueError:
                try:
                    rel = src.relative_to(self.httpd_root)
                except ValueError:
                    # harness files won't be relative to cov_root or httpd_root
                    try:
                        rel = src.relative_to(self.work_dir)
                    except ValueError:
                        continue
            if set(rel.parts) & exclude_dirs:
                continue
            filtered.append(e)
        entries = filtered

        if not entries:
            self.logger.warning("No compilation entries found")
            return

        built = []
        failed = []

        status = Progress(SpinnerColumn(), TextColumn("{task.description}"))
        bar = Progress(BarColumn())
        status_task = status.add_task("[yellow]Emitting LLVM bitcode...")
        bar_task = bar.add_task("", total=len(entries))
        console = Console()

        with Live(RichGroup(status, bar), console=console, refresh_per_second=12):
            for entry in entries:
                src = Path(entry["file"])
                try:
                    dst = src.relative_to(cov_root)
                except ValueError:
                    try:
                        dst = src.relative_to(self.httpd_root)
                    except ValueError:
                        try:
                            dst = src.relative_to(self.work_dir)
                        except ValueError:
                            bar.advance(bar_task)
                            continue
                output = bc_path / dst.with_suffix(".bc")
                output.parent.mkdir(parents=True, exist_ok=True)

                args = list(entry.get("arguments", []))
                if not args:
                    cmd_str = entry.get("command", "")
                    args = cmd_str.split()
                if not args:
                    bar.advance(bar_task)
                    continue

                args[0] = cc
                new_args = []
                skip_next = 0
                for i, arg in enumerate(args):
                    if skip_next > 0:
                        skip_next -= 1
                        continue
                    if arg == "-o" and i + 1 < len(args):
                        new_args.extend(["-o", str(output)])
                        skip_next = 1
                        continue
                    # strip AFL instrumentation flags
                    if arg == "-Xclang" and i + 3 < len(args) and args[i + 1] == "-load":
                        skip_next = 3
                        continue
                    if arg.startswith("-fsanitize="):
                        continue
                    if arg == "-fno-experimental-new-pass-manager":
                        continue
                    if arg.startswith("-D__AFL_") or arg == "-DAFL_FUZZ":
                        continue
                    new_args.append(arg)
                if "-emit-llvm" not in new_args:
                    new_args.insert(1, "-emit-llvm")
                if "-w" not in new_args:
                    new_args.insert(1, "-w")

                status.update(
                    status_task,
                    description=f"[yellow]Emitting LLVM bitcode: {src.name} ({len(built)}/{len(entries)})",
                )
                try:
                    subprocess.run(
                        new_args,
                        cwd=entry.get("directory", str(cov_root)),
                        check=True,
                        capture_output=True,
                        text=True,
                    )
                    built.append(output)
                except subprocess.CalledProcessError as e:
                    failed.append((src.name, e.stderr))
                bar.advance(bar_task)

        if failed:
            with tempfile.NamedTemporaryFile(
                prefix="bitcode_errors_",
                suffix=".log",
                delete=False,
                mode="w",
            ) as log_file:
                for name, err in failed:
                    log_file.write(f"--- {name} ---\n{err}\n\n")
                log_path = log_file.name
            self.logger.warning(f"{len(failed)} files failed to compile:")
            for i in range(0, len(failed), 4):
                batch = ", ".join(n for n, _ in failed[i : i + 4])
                self.logger.warning(f"  {batch}")
            self.logger.info(f"Full error log: {log_path}")

        UI.print_success(f"Bitcode emitted for {len(built)}/{len(entries)} files")

        if not built:
            return

        major = self._clang_major_version(cc)
        llvm_link = shutil.which(f"llvm-link-{major}") or shutil.which("llvm-link")
        if not llvm_link:
            self.logger.error("llvm-link not found")
            return

        combined = bc_path / "combined.bc"
        llvm_nm = shutil.which(f"llvm-nm-{major}") or shutil.which("llvm-nm")
        candidates = [p for p in built if p.name not in exclude_files]

        seen_globals = {}
        link_targets = []
        skipped = []
        for bc_file in candidates:
            if not llvm_nm:
                link_targets.append(bc_file)
                continue
            try:
                result = subprocess.run(
                    [llvm_nm, "--defined-only", str(bc_file)],
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
                symbols = set()
                for line in result.stdout.splitlines():
                    parts = line.split()
                    if len(parts) >= 3 and parts[1] in ("T", "D", "B"):
                        symbols.add(parts[2])
                conflict = False
                for sym in symbols:
                    if sym in seen_globals:
                        conflict = True
                        break
                if conflict:
                    skipped.append(bc_file)
                    continue
                for sym in symbols:
                    seen_globals[sym] = bc_file
                link_targets.append(bc_file)
            except Exception:
                link_targets.append(bc_file)

        if skipped:
            self.logger.info(f"Skipped {len(skipped)} files with duplicate symbols")

        link_spinner = Progress(SpinnerColumn(), TextColumn("{task.description}"))
        link_spinner.add_task("[yellow]Linking LLVM bitcode objects for post-processing...")
        console = Console()
        try:
            with Live(link_spinner, console=console, refresh_per_second=12):
                subprocess.run(
                    [llvm_link, *[str(p) for p in link_targets], "-o", str(combined)],
                    check=True,
                    capture_output=True,
                    text=True,
                )
            UI.print_success(f"Bitcode linked -> {combined} ({len(link_targets)} modules)")
        except subprocess.CalledProcessError as e:
            self.logger.error(f"llvm-link failed: {e.stderr}")

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

    _BUG_LABELS = {
        "heap-use-after-free": "UAF",
        "heap-buffer-overflow": "heap-overflow",
        "stack-buffer-overflow": "stack-overflow",
        "global-buffer-overflow": "global-overflow",
        "double-free": "double-free",
        "SEGV": "SEGV",
        "integer-overflow": "int-overflow",
        "unsigned-integer-overflow": "int-overflow",
        "stack-use-after-return": "use-after-return",
        "use-after-poison": "use-after-poison",
        "null-dereference": "null-deref",
        "FPE": "FPE",
        "requested-alignment": "alignment",
        "alloc-dealloc-mismatch": "alloc-mismatch",
    }

    @staticmethod
    def _format_exit(returncode: int) -> str:
        """Format an exit code as ``SIGNAME(code)`` when killed by a signal."""
        if returncode < 0:
            try:
                name = signal.Signals(-returncode).name
            except ValueError:
                name = "SIG?"
            return f"{name}({returncode})"
        return str(returncode)

    @staticmethod
    def _classify_bugs(stderr: str) -> str:
        """Extract all bug types from sanitizer SUMMARY lines in *stderr*.

        Returns a comma-separated string of short labels (e.g.
        ``"int-overflow, UAF"``), or ``"unknown"`` if no SUMMARY lines
        are found.
        """
        labels: list[str] = []
        for m in re.finditer(r"^SUMMARY:\s*\S+:\s*(\S+)", stderr, re.MULTILINE):
            raw = m.group(1)
            label = ReportManager._BUG_LABELS.get(raw, raw)
            if label not in labels:
                labels.append(label)
        return ", ".join(labels) if labels else "unknown"

    def triage_bulk(
        self,
        crash_dir: Path,
        harness_binary: Path,
        no_color: bool = False,
        suppress: Optional[str] = None,
        timeout: int = 30,
    ) -> None:
        """Triage every crash file in *crash_dir* individually and print a summary table."""
        crash_dir = Path(crash_dir)
        if not crash_dir.is_dir():
            self.logger.error(f"Not a directory: {crash_dir}")
            return

        files = sorted(
            (f for f in crash_dir.iterdir() if f.is_file()),
            key=lambda f: f.name,
        )
        if not files:
            self.logger.error(f"No files found in {crash_dir}")
            return

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

        self.logger.info(f"Bulk triage: {len(files)} crash files from {crash_dir}")

        console = Console()
        results: list[tuple[str, str, str]] = []
        bug_counts: Counter[str] = Counter()

        spinner = Progress(SpinnerColumn(), TextColumn("{task.description}"))
        task_id = spinner.add_task("")

        with Live(spinner, console=console, refresh_per_second=12):
            for i, crash_file in enumerate(files, 1):
                # Update status line with current file and running totals.
                counts_str = ", ".join(f"{v} {k}" for k, v in bug_counts.most_common()) if bug_counts else "-"
                spinner.update(
                    task_id,
                    description=(
                        f"[yellow]Triaging[/yellow] [cyan]{crash_file.name}[/cyan] "
                        f"[dim]({i}/{len(files)})[/dim]  [dim]found:[/dim] {counts_str}"
                    ),
                )

                try:
                    crash_data = crash_file.read_bytes()
                    result = subprocess.run(  # noqa: UP022
                        cmd,
                        env=env,
                        input=crash_data,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        timeout=timeout,
                    )
                    stderr_text = result.stderr.decode("utf-8", errors="replace")
                    bug_type = self._classify_bugs(stderr_text)
                    exit_str = self._format_exit(result.returncode)
                    results.append((crash_file.name, bug_type, exit_str))
                    for label in bug_type.split(", "):
                        bug_counts[label] += 1
                except subprocess.TimeoutExpired:
                    results.append((crash_file.name, "timeout", "-"))
                    bug_counts["timeout"] += 1
                except Exception as e:
                    results.append((crash_file.name, f"error: {e}", "-"))
                    bug_counts["error"] += 1

        if not results:
            return

        # Print summary table using the project-wide Rich table style.
        table = Table(box=None, show_edge=False, pad_edge=False, header_style="bold underline")
        table.add_column("File", style="cyan")
        table.add_column("Bug Type", style="magenta")
        table.add_column("Exit", style="dim", justify="right")

        for name, bug, exit_code in results:
            table.add_row(name, bug, exit_code)

        console.print()
        console.print(table)

        # Print totals.
        counts_str = ", ".join(f"[bold]{v}[/bold] {k}" for k, v in bug_counts.most_common())
        console.print(f"\n[dim]{len(results)} crashes triaged:[/dim] {counts_str}")
