import json
import os
import re
import subprocess
import tempfile
from pathlib import Path
from typing import Optional

from rich.console import Console
from rich.console import Group as RichGroup
from rich.live import Live
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn

from apatchy.core import toolchain_config
from apatchy.utils.logger import get_logger
from apatchy.utils.ui import UI, run_stream_panel

logger = get_logger(__name__)


def clang_major_version(cc: str) -> Optional[int]:
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


def _resolve_src_rel(src: Path, roots: list) -> Optional[Path]:
    for root in roots:
        try:
            return src.relative_to(root)
        except ValueError:
            continue
    return None


class IntrospectorManager:
    """Compile Apache C sources into LLVM bitcode and link them for introspection.

    ``IntrospectorManager`` is used by
    :class:`~apatchy.managers.report_manager.ReportManager` to produce the
    LLVM bitcode that the introspection pipeline needs for call-tree
    extraction and per-function coverage analysis.

    The workflow has two phases:

    1. **Emit bitcode** - Reads the ``compile_commands.json`` from the
       coverage build tree (``<httpd_root>-cov``). If the file does not
       exist, it runs ``bear`` to trace a fresh ``make`` and generate one.
       Each ``.c`` entry is re-compiled with ``-emit-llvm`` to produce a
       ``.bc`` file under ``<httpd_root>-cov/bitcode/``. Test, support,
       and platform-specific directories are excluded automatically.

    2. **Link bitcode** - All emitted ``.bc`` files are linked into a
       single ``combined.bc`` with ``llvm-link``. Before linking,
       ``llvm-nm`` is used to detect and skip files with duplicate global
       symbols to avoid link errors. The combined bitcode is consumed by
       the introspector C++ tool to build a call tree and by ``llvm-cov``
       to map coverage back to functions.

    ``IntrospectorManager`` is not invoked directly from the CLI. It is
    called internally when the user runs:

    .. code-block:: bash

        # Coverage report with introspection chained in
        apatchy coverage report --fuzzer-dir fuzz-output/ --with-introspect

        # Standalone introspection (auto-builds bitcode if missing)
        apatchy introspect ap_process_request_internal

    Args:
        httpd_root: Path to the Apache HTTPD source directory. The
            coverage build tree is expected at ``<httpd_root>-cov``.
        work_dir: Working directory where build artifacts, harnesses,
            and output files are stored.

    Example:
        .. code-block:: python

            from pathlib import Path
            from apatchy.managers.introspector_manager import IntrospectorManager

            im = IntrospectorManager(
                httpd_root=Path("httpd-2.4.58"),
                work_dir=Path("work"),
            )

            # Emit per-file .bc and link into combined.bc
            im.build_bitcode(cc="clang-18")
    """

    def __init__(self, httpd_root: Path, work_dir: Path) -> None:
        self.httpd_root = httpd_root
        self.work_dir = work_dir
        self.logger = logger

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

    def build_bitcode(self, cc: str) -> None:
        """Generate bitcode for C sources."""
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
        exclude_files = {"modules.bc", "gen_test_char.bc", "exports.bc", "main.bc"}

        roots = [cov_root, self.httpd_root, self.work_dir]

        compile_db = cov_root / "compile_commands.json"
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
            rel = _resolve_src_rel(Path(e["file"]), roots)
            if rel is None:
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
                dst = _resolve_src_rel(src, roots)
                if dst is None:
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
                    if arg == "-Xclang" and i + 3 < len(args) and args[i + 1] == "-load":
                        skip_next = 3
                        continue
                    if arg.startswith("-fsanitize="):
                        continue
                    if arg == "-fno-experimental-new-pass-manager":
                        continue
                    new_args.append(arg)
                if "-o" not in new_args:
                    new_args.extend(["-o", str(output)])
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

        major = clang_major_version(cc)
        llvm_link = (
            toolchain_config.resolve_tool(f"llvm-link-{major}")
            or toolchain_config.resolve_tool(f"llvm-link-{major}")
            or toolchain_config.resolve_tool("llvm-link")
        )
        if not llvm_link:
            self.logger.error("llvm-link not found")
            return

        combined = bc_path / "combined.bc"
        llvm_nm = (
            toolchain_config.resolve_tool(f"llvm-nm-{major}")
            or toolchain_config.resolve_tool(f"llvm-nm-{major}")
            or toolchain_config.resolve_tool("llvm-nm")
        )
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

        missing_bc = [p for p in link_targets if not p.exists()]
        if missing_bc:
            self.logger.error(f"{len(missing_bc)} .bc files missing, first: {missing_bc[0]}")
            return

        cmd = [llvm_link, *[str(p) for p in link_targets], "-o", str(combined)]

        link_spinner = Progress(SpinnerColumn(), TextColumn("{task.description}"))
        link_spinner.add_task("[yellow]Linking LLVM bitcode objects for post-processing...")
        console = Console()
        try:
            with Live(link_spinner, console=console, refresh_per_second=12):
                subprocess.run(cmd, check=True, capture_output=True, text=True)
            UI.print_success(f"Bitcode linked -> {combined} ({len(link_targets)} modules)")
        except subprocess.CalledProcessError as e:
            self.logger.error(f"llvm-link failed (rc={e.returncode}): {e.stderr}")
        except FileNotFoundError as e:
            self.logger.error(f"llvm-link binary not found: {e}")
        except OSError as e:
            self.logger.error(f"llvm-link OS error: {e}")
