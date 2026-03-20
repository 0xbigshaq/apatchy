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
from rich.live import Live
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn
from rich.table import Table

from apatchy.compat import extract_version_from_path, get_compat_flags
from apatchy.core import toolchain_config
from apatchy.core.harness import HarnessBuilder
from apatchy.core.process_runner import ProcessRunner
from apatchy.managers.config_manager import ConfigManager
from apatchy.managers.introspector_manager import IntrospectorManager, clang_major_version
from apatchy.utils.build_tree import AlternateBuildTree
from apatchy.utils.logger import get_logger
from apatchy.utils.ui import UI, run_stream_panel

logger = get_logger(__name__)


class ReportManager:
    """Generate coverage reports, triage crashes, and profile fuzzing runs.

    ``ReportManager`` is the post-fuzzing analysis hub. It takes the raw
    output from a fuzzing session and produces actionable reports:

    **Coverage** (:meth:`generate_coverage`) - Rebuilds Apache with LLVM
    source-based coverage instrumentation, replays the fuzzer corpus
    through the harness, merges the raw profiles with ``llvm-profdata``,
    and generates an HTML report with ``llvm-cov``. Dark-mode CSS is
    injected automatically. Optionally chains into introspection.

    **Introspection** (:meth:`generate_introspect`) - Uses the
    :class:`~apatchy.managers.introspector_manager.IntrospectorManager`
    to extract a call tree and per-function coverage from LLVM bitcode
    and profdata, producing a JSON file that can be viewed in an
    interactive web UI.

    **Triage** - Replays individual crash files or entire directories
    through the coverage harness to extract sanitizer reports:

    * :meth:`triage_crash` - single file
    * :meth:`triage_bulk` - all files in a directory (parallel)

    **Profiling** (:meth:`generate_callgrind`) - Replays the corpus
    through ``valgrind --tool=callgrind`` to produce callgrind profiles
    for analysis with tools like KCachegrind.

    Args:
        httpd_root: Path to the Apache HTTPD source directory.
        config_manager: A :class:`~apatchy.managers.config_manager.ConfigManager`
            instance. For coverage, it should be created with
            ``build_mode="coverage"``.

    CLI usage:

    .. code-block:: bash

        # Triage a single crash file
        apatchy triage fuzz-output/default/crashes/id:000000

        # Triage all crashes in a directory
        apatchy triage --bulk fuzz-output/default/crashes/

        # Replay numbered crash files as sequential requests
        apatchy triage --pipeline fuzz-output/

        # Generate a coverage report from corpus
        apatchy coverage report --fuzzer-dir fuzz-output/

        # Coverage with introspection chained in
        apatchy coverage report --fuzzer-dir fuzz-output/ --with-introspect

        # Generate introspection data with interactive viewer
        apatchy introspect --entry ap_process_request

        # Generate callgrind profiles
        apatchy profile callgrind --fuzzer-dir fuzz-output/

    Example:
        .. code-block:: python

            from pathlib import Path
            from apatchy.managers.config_manager import ConfigManager
            from apatchy.managers.report_manager import ReportManager

            # Triage a crash
            config = ConfigManager(config_name="fuzz.conf")
            rm = ReportManager(Path("httpd-2.4.58"), config)
            rm.triage_crash("fuzz-output/default/crashes/id:000000", Path("fuzz_harness_coverage"))

            # Generate coverage
            cov_config = ConfigManager(build_mode="coverage")
            rm = ReportManager(Path("httpd-2.4.58"), cov_config)
            rm.generate_coverage(corpus_dir="fuzz-output/")
    """

    def __init__(self, httpd_root: Path, config_manager: ConfigManager) -> None:
        self.httpd_root = httpd_root
        self.config_manager = config_manager
        self.logger = logger
        self.runner = ProcessRunner()
        self.work_dir = Path(".").resolve()
        self.introspector = IntrospectorManager(httpd_root, self.work_dir)

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
            major = clang_major_version(cc_path)
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
            profdata_path = toolchain_config.resolve_tool(profdata_name)
            cov_path = toolchain_config.resolve_tool(cov_name)
            if profdata_path and cov_path:
                self.logger.info(f"using LLVM-{major} from PATH")
                return profdata_path, cov_path, cc_path

        raise FileNotFoundError(
            "No matched LLVM toolchain found. Install a complete set, e.g.: apt install clang-14 llvm-14"
        )

    def _collect_corpus_dirs(self, corpus_dir: str) -> List[Path]:
        """Collect directories of test case files from a corpus path.

        Returns a list of directories containing files to replay.

        Supported layouts:
        - Fuzzer output: <dir>/default/queue/   -> [default/queue, default/crashes]
        - Flat:          <dir>/queue/           -> [queue/, crashes/]
        - Plain:         <dir>/ (files directly) -> [dir]
        """
        corpus_path = Path(corpus_dir).resolve()
        if not corpus_path.exists():
            self.logger.error(f"Corpus directory not found: {corpus_path}")
            return []

        replay_dirs = []

        # Fuzzer output layout: look for queue/ subdirectories
        instances = []
        for child in sorted(corpus_path.iterdir()):
            if child.is_dir() and (child / "queue").is_dir():
                instances.append(child)

        if not instances and (corpus_path / "queue").is_dir():
            instances.append(corpus_path)

        if instances:
            names = [p.name for p in instances]
            self.logger.info(f"Found {len(instances)} fuzzer instance(s): {', '.join(names)}")
            for inst in instances:
                replay_dirs.append(inst / "queue")
                crashes = inst / "crashes"
                if crashes.is_dir() and any(crashes.iterdir()):
                    replay_dirs.append(crashes)
            return replay_dirs

        # Plain corpus: directory of files
        has_files = any(f.is_file() for f in corpus_path.iterdir())
        if has_files:
            self.logger.info(f"Using plain corpus directory: {corpus_path}")
            replay_dirs.append(corpus_path)
            return replay_dirs

        self.logger.error(
            f"No test cases found in {corpus_path}. Provide a fuzzer output directory or a plain directory of files."
        )
        return []

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

        # Try versioned name matching the compiler
        compiler_ver: Optional[int] = None
        cc = toolchain_config.resolve_tool("clang")
        if cc:
            try:
                out = subprocess.check_output(
                    [cc, "--version"],
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
        plain = toolchain_config.resolve_tool("llvm-symbolizer")
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

    def _build_coverage_modules(self, cc: str, cov_root: Path) -> List[Path]:
        """Build coverage-instrumented copies of external modules (.so).

        Looks for module sources in EXTERNAL_MODULES_DIR, compiles each with
        coverage flags, and places them in <work_dir>/modules/ (overwriting
        the fuzz-instrumented version).  Returns the list of built .so paths.
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
        """Build a coverage-instrumented proto harness.

        Requires the ``-cov`` tree to already exist (via ``apatchy make --tree cov``).
        Returns (harness_path, cov_httpd_root).
        """
        cov_root = self.httpd_root.parent / (self.httpd_root.name + "-cov")
        if not cov_root.exists():
            raise FileNotFoundError(
                f"Coverage tree not found at {cov_root.name}/. Run 'apatchy make --tree cov' first."
            )

        harness = self.work_dir / "fuzz_harness_coverage"
        harness_stamp = self.work_dir / ".cov_harness_name"
        libmain = cov_root / "server" / "libmain.la"
        cached_name = harness_stamp.read_text().strip() if harness_stamp.exists() else None
        name_matches = cached_name == (harness_name or "")
        mtime_ok = harness.exists() and libmain.exists() and harness.stat().st_mtime > libmain.stat().st_mtime
        if name_matches and mtime_ok:
            self.logger.info(f"Coverage harness up to date: {harness}")
            return harness, cov_root

        build_config = self.config_manager.generate_build_config()
        cflags = build_config.get("CFLAGS", "")
        ldflags = build_config.get("LDFLAGS", "")

        builder = HarnessBuilder(cov_root)
        self.logger.info("Building coverage-instrumented harness...")
        builder.build(mode="coverage", cflags=cflags, ldflags=ldflags, cc=cc, harness_name=harness_name)

        if not harness.exists():
            raise FileNotFoundError("Failed to build fuzz_harness_coverage")

        harness_stamp.write_text(harness_name or "")
        self.logger.info(f"Coverage harness built: {harness}")
        return harness, cov_root

    def _replay_corpus_proto(
        self,
        harness: Path,
        corpus_dirs: List[Path],
        prof_dir: Path,
        config_path: Path,
    ) -> int:
        """Replay a proto harness corpus by running libFuzzer with -runs=0.

        Passes all corpus directories to the libFuzzer binary at once so LPM
        deserializes each file as a proto message before calling the fuzzer
        body - the same path taken during actual fuzzing.
        """
        existing = [d for d in corpus_dirs if d.exists()]
        total = sum(len([f for f in d.iterdir() if f.is_file() and f.name != ".state"]) for d in existing)
        if total == 0:
            self.logger.error("No corpus files found for proto replay")
            return 0

        # Exclude crash dirs: replaying known-bad inputs in one in-process run
        # guarantees an abort midway. Non-proto replay uses per-subprocess
        # execution so it can safely include crashes; proto replay cannot.
        replay = [d for d in existing if "crash" not in d.name]

        env = os.environ.copy()
        env["FUZZ_CONF"] = str(config_path)
        env["FUZZ_ROOT"] = str(self.work_dir)
        env["LLVM_PROFILE_FILE"] = str(prof_dir / "proto-cov-%p.profraw")

        crash_sink = prof_dir / "replay-crashes"
        crash_sink.mkdir(exist_ok=True)

        cmd = [
            str(harness),
            "-runs=0",
            "-keep_going=1000000",
            f"-artifact_prefix={crash_sink}/",
        ] + [str(d) for d in replay]

        console = Console()
        spinner = Progress(SpinnerColumn(), TextColumn("{task.description}"))
        spinner.add_task(f"[yellow]Replaying[/yellow] [dim]{total} proto corpus files[/dim]")
        with Live(spinner, console=console, refresh_per_second=12):
            try:
                subprocess.run(cmd, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=300)
            except subprocess.TimeoutExpired:
                self.logger.warning("Proto corpus replay timed out")

        return total

    def generate_coverage(
        self,
        corpus_dir: str = "fuzz-output",
        config_name: str = "fuzz.conf",
        output_dir: str = "coverage-report",
        harness_name: str = None,
        exclude_file: str | None = None,
        with_introspect=False,
        with_modules=False,
    ) -> None:
        """Full coverage pipeline: build harness, replay corpus, merge, generate report."""
        # Detect LLVM toolchain (matched compiler + analysis tools)
        try:
            profdata_bin, cov_bin, cc = self._detect_llvm_toolchain()
        except FileNotFoundError as e:
            self.logger.error(str(e))
            return

        # Collect corpus directories
        replay_dirs = self._collect_corpus_dirs(corpus_dir)
        if not replay_dirs:
            return

        # Build coverage harness (uses separate -cov tree, fuzz build untouched)
        try:
            harness, cov_root = self._build_coverage_harness(cc, harness_name=harness_name)
        except Exception as e:
            self.logger.error(f"Failed to build coverage harness: {e}")
            return

        cov_modules = []
        if with_modules:
            cov_modules = self._build_coverage_modules(cc, cov_root)

        # Resolve httpd config
        config_path = self.config_manager.get_httpd_config(config_name)
        if not config_path:
            self.logger.error(f"Config '{config_name}' not found")
            return

        # Replay corpus
        prof_dir = Path(output_dir).resolve() / "profraw"
        if prof_dir.exists():
            for f in prof_dir.glob("*.profraw"):
                f.unlink()
        prof_dir.mkdir(parents=True, exist_ok=True)

        count = self._replay_corpus_proto(harness, replay_dirs, prof_dir, config_path)

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
            self.introspector.build_bitcode(cc)
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
        fuzzer_dir: str = "fuzz-output",
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
            self.introspector.build_bitcode(cc)
        if not bitcode.is_file():
            self.logger.error(f"bitcode not found: {bitcode}")
            return

        # parse entry points (comma-separated) or auto-detect
        if entry:
            entries = [e.strip() for e in entry.split(",") if e.strip()]
        else:
            entries = []
            major = clang_major_version(cc)
            llvm_nm = toolchain_config.resolve_tool(f"llvm-nm-{major}") or toolchain_config.resolve_tool("llvm-nm")
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
                        entries.append("LLVMFuzzerTestOneInput")
                    elif "main" in symbols:
                        entries.append("main")
                except Exception:
                    pass
            if not entries:
                self.logger.error("could not detect entry point, use --entry")
                return
            self.logger.info(f"Auto-detected entry point: {entries[0]}")

        # locate (and auto-build) the wuxi binary and GUI frontend
        introspector_root = Path(__file__).resolve().parent.parent.parent.parent / "introspector"
        wuxi = introspector_root / "build" / "wuxi"
        gui_dist = introspector_root / "gui" / "dist"

        if not gui_dist.is_dir():
            self.logger.info("GUI frontend not built, building...")
            gui_dir = str(introspector_root / "gui")
            rc, _ = run_stream_panel(
                ["npm", "install"],
                cwd=gui_dir,
                label="Installing GUI dependencies (npm install)...",
            )
            if rc != 0:
                self.logger.warning("npm install failed, introspect report will have no viewer")
            else:
                rc, _ = run_stream_panel(
                    ["npm", "run", "build"],
                    cwd=gui_dir,
                    label="Building GUI frontend (npm run build)...",
                )
                if rc != 0:
                    self.logger.warning("npm run build failed, introspect report will have no viewer")

        if not wuxi.is_file():
            self.logger.info("wuxi tool not built, building with cmake...")
            intr_dir = str(introspector_root)
            rc, _ = run_stream_panel(
                ["cmake", "-B", "build/"],
                cwd=intr_dir,
                label="Configuring wuxi (cmake)...",
            )
            if rc == 0:
                rc, _ = run_stream_panel(
                    ["cmake", "--build", "build/"],
                    cwd=intr_dir,
                    label="Building wuxi (cmake --build)...",
                )
            if rc != 0 or not wuxi.is_file():
                self.logger.error(f"Failed to build wuxi at {wuxi}")
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

        # run wuxi for each entry point and merge results
        merged_functions = {}
        merged_edges = []
        merged_trees = []
        seen_edges = set()
        orig_prefix = str(self.httpd_root.resolve())
        cov_prefix = str(cov_root.resolve())

        for entry_name in entries:
            wuxi_out = Path(tempfile.mktemp(suffix=".json"))
            wuxi_cmd = [str(wuxi), str(bitcode), entry_name, "-f", str(wuxi_out)]
            returncode, _ = run_stream_panel(
                wuxi_cmd,
                label=f"Running call tree analysis for '{entry_name}'...",
            )
            if returncode != 0:
                self.logger.error(f"wuxi failed for entry '{entry_name}'")
                return
            result = json.loads(wuxi_out.read_text())
            wuxi_out.unlink(missing_ok=True)

            # rewrite source_dir from the original tree to the -cov tree
            for func_meta in result.get("functions", {}).values():
                sd = func_meta.get("source_dir", "")
                if sd.startswith(orig_prefix + "/") or sd == orig_prefix:
                    func_meta["source_dir"] = cov_prefix + sd[len(orig_prefix) :]

            # merge functions (first occurrence wins)
            for fname, fmeta in result.get("functions", {}).items():
                if fname not in merged_functions:
                    merged_functions[fname] = fmeta

            # merge edges (deduplicate by caller+callee+site)
            for edge in result.get("call_edges", []):
                key = (edge["caller"], edge["callee"], edge.get("site_file", ""), edge.get("site_line", 0))
                if key not in seen_edges:
                    seen_edges.add(key)
                    merged_edges.append(edge)

            merged_trees.append(result.get("call_tree", {}))

        introspect = {
            "metadata": {"entry_points": entries},
            "functions": merged_functions,
            "call_tree": merged_trees,
            "call_edges": merged_edges,
        }

        # merge coverage into functions (try direct match, then stripped-prefix fallback)
        merged_count = 0
        for func_name, func_meta in introspect["functions"].items():
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

        total = len(introspect["functions"])
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

        for tree in introspect.get("call_tree", []):
            annotate_site_counts(tree)

        # assemble output directory with GUI, data, and coverage report
        out_dir = Path("introspect-report")
        if out_dir.exists():
            shutil.rmtree(out_dir)

        if gui_dist.is_dir():
            shutil.copytree(gui_dist, out_dir)
        else:
            out_dir.mkdir(parents=True)
            self.logger.warning(f"GUI dist not found at {gui_dist}, output will have no viewer")

        (out_dir / "introspect.json").write_text(json.dumps(introspect, indent=2))

        stat_file = Path(fuzzer_dir) / "stat.json"
        if stat_file.is_file():
            shutil.copy2(stat_file, out_dir / "stat.json")
            self.logger.info(f"Copied stat.json from {stat_file}")
        else:
            self.logger.info(f"No stat.json found in {fuzzer_dir}, stats tab will be empty")

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

        Uses a separate ``-prof`` build tree so the fuzz build is untouched.
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
        """Replay corpus through harness under callgrind, producing .callgrind files."""
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
        corpus_dir: str = "fuzz-output",
        config_name: str = "fuzz.conf",
        output_dir: str = "callgrind-out",
        harness_name: str = None,
        jobs: int = 1,
        timeout: int = 120,
    ) -> None:
        """Replay corpus under callgrind and collect output for kcachegrind.

        Automatically builds a dedicated ``-prof`` Apache tree with debug
        symbols, no sanitizers, and no coverage instrumentation so that
        callgrind output is clean and all function names are visible.
        """
        # Check valgrind is available
        if not toolchain_config.resolve_tool("valgrind"):
            self.logger.error("valgrind not found. Install with: apt install valgrind")
            return

        # Collect corpus directories
        replay_dirs = self._collect_corpus_dirs(corpus_dir)
        if not replay_dirs:
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
        for replay_dir in replay_dirs:
            self.logger.info(f"Replaying {replay_dir.name}/ ({len(list(replay_dir.iterdir()))} entries)...")
            result = self._replay_corpus_callgrind(
                harness_path, replay_dir, out_path, config_path, prof_offset=count, jobs=jobs, timeout=timeout
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

        return env, config_path

    def triage_crash(
        self,
        crash_file: Path,
        harness_binary: Path,
        no_color: bool = False,
        suppress: Optional[str] = None,
        timeout: int = 30,
        is_libfuzzer: bool = False,
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

        try:
            if is_libfuzzer:
                cmd = [
                    str(harness_binary),
                    "-runs=0",
                    str(Path(crash_file).resolve()),
                ]
                result = subprocess.run(  # noqa: UP022
                    cmd,
                    env=env,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    timeout=timeout,
                )
            else:
                cmd = [
                    str(harness_binary),
                    "-f",
                    str(config_path),
                    "-d",
                    str(self.work_dir),
                ]
                crash_data = Path(crash_file).read_bytes()
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
    def _extract_crash_site(stderr: str) -> str:
        """Extract crash site from sanitizer output as ``pc (func)``."""
        pc = None
        func = None
        pc_m = re.search(r"\(pc\s+(0x[0-9a-fA-F]+)", stderr)
        if pc_m:
            pc = pc_m.group(1)
        frame_m = re.search(r"#0\s+(0x[0-9a-fA-F]+)\s+in\s+(\S+)", stderr)
        if frame_m:
            if not pc:
                pc = frame_m.group(1)
            func = frame_m.group(2)
        if pc and func:
            return f"{pc} ({func})"
        if func:
            return func
        if pc:
            return pc
        return "-"

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
        is_libfuzzer: bool = False,
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

        standalone_cmd = None
        if not is_libfuzzer:
            standalone_cmd = [
                str(harness_binary),
                "-f",
                str(config_path),
                "-d",
                str(self.work_dir),
            ]

        self.logger.info(f"Bulk triage: {len(files)} crash files from {crash_dir}")

        console = Console()
        results: list[tuple[str, str, str, str]] = []
        bug_counts: Counter[str] = Counter()

        spinner = Progress(SpinnerColumn(), TextColumn("{task.description}"))
        task_id = spinner.add_task("")

        with Live(spinner, console=console, refresh_per_second=12):
            for i, crash_file in enumerate(files, 1):
                counts_str = ", ".join(f"{v} {k}" for k, v in bug_counts.most_common()) if bug_counts else "-"
                spinner.update(
                    task_id,
                    description=(
                        f"[yellow]Triaging[/yellow] [cyan]{crash_file.name}[/cyan] "
                        f"[dim]({i}/{len(files)})[/dim]  [dim]found:[/dim] {counts_str}"
                    ),
                )

                try:
                    if is_libfuzzer:
                        cmd = [
                            str(harness_binary),
                            "-runs=0",
                            str(crash_file.resolve()),
                        ]
                        result = subprocess.run(  # noqa: UP022
                            cmd,
                            env=env,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE,
                            timeout=timeout,
                        )
                    else:
                        crash_data = crash_file.read_bytes()
                        result = subprocess.run(  # noqa: UP022
                            standalone_cmd,
                            env=env,
                            input=crash_data,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE,
                            timeout=timeout,
                        )
                    stderr_text = result.stderr.decode("utf-8", errors="replace")
                    bug_type = self._classify_bugs(stderr_text)
                    crash_site = self._extract_crash_site(stderr_text)
                    exit_str = self._format_exit(result.returncode)
                    if result.returncode == 0 and bug_type == "unknown":
                        bug_type = "ok"
                    results.append((crash_file.name, bug_type, crash_site, exit_str))
                    for label in bug_type.split(", "):
                        bug_counts[label] += 1
                except subprocess.TimeoutExpired:
                    results.append((crash_file.name, "timeout", "-", "-"))
                    bug_counts["timeout"] += 1
                except Exception as e:
                    results.append((crash_file.name, f"error: {e}", "-", "-"))
                    bug_counts["error"] += 1

        if not results:
            return

        # Print summary table using the project-wide Rich table style.
        table = Table(box=None, show_edge=False, pad_edge=False, header_style="bold underline")
        table.add_column("File", style="cyan")
        table.add_column("Bug Type", style="magenta")
        table.add_column("Crash Site", style="yellow")
        table.add_column("Exit", style="dim", justify="right")

        for name, bug, site, exit_code in results:
            if bug == "ok":
                continue
            table.add_row(name, bug, site, exit_code)

        console.print()
        console.print(table)

        # Print totals.
        counts_str = ", ".join(f"[bold]{v}[/bold] {k}" for k, v in bug_counts.most_common())
        console.print(f"\n[dim]{len(results)} crashes triaged:[/dim] {counts_str}")
