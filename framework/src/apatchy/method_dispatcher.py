"""Command dispatcher that routes CLI sub-commands to the appropriate manager.

The :class:`MethodDispatcher` acts as the glue between the argument parser
(defined in :mod:`apatchy.main`) and the various manager classes that
implement each workflow step (download, configure, link, fuzz, ...).
"""

import argparse
import os
from pathlib import Path
from typing import Optional

from apatchy.config import Config
from apatchy.core import toolchain_config
from apatchy.core.downloader import Downloader
from apatchy.managers.build_manager import BuildManager
from apatchy.managers.config_manager import ConfigManager
from apatchy.managers.dev_manager import DevManager
from apatchy.managers.fuzz_manager import FuzzManager
from apatchy.managers.module_manager import ModuleManager
from apatchy.managers.report_manager import ReportManager
from apatchy.managers.toolchain_manager import ToolchainManager
from apatchy.utils.logger import get_logger

# from apatchy.core.harness import HarnessBuilder # Used inside BuildManager

logger = get_logger(__name__)


class MethodDispatcher:
    """Route parsed CLI arguments to the correct manager method.

    Managers are created lazily - only when the corresponding command
    is invoked - because most of them require a resolved HTTPD source
    tree or engine-specific configuration.
    """

    def __init__(self) -> None:
        self.downloader = Downloader()
        self.config_manager: Optional[ConfigManager] = None
        self.build_manager: Optional[BuildManager] = None
        self.fuzz_manager: Optional[FuzzManager] = None
        self.report_manager: Optional[ReportManager] = None
        self.toolchain_manager: Optional[ToolchainManager] = None

    def dispatch(self, args: argparse.Namespace) -> None:
        """Inspect *args.command* and delegate to the matching handler."""
        command = args.command
        logger.info(f"Dispatching command: {command}")

        if command == "download":
            self._handle_download(args)
        elif command == "configure":
            self._handle_configure(args)
        elif command == "make":
            self._handle_compile(args)
        elif command == "link":
            self._handle_link(args)
        elif command == "fuzz":
            self._handle_fuzz(args)
        elif command == "triage":
            self._handle_triage(args)
        elif command == "coverage":
            self._handle_coverage(args)
        elif command == "introspect":
            self._handle_introspect(args)
        elif command == "profile":
            self._handle_profile(args)
        elif command == "setup":
            self._handle_setup(args)
        elif command == "harness":
            self._handle_harness(args)
        elif command == "module":
            self._handle_module(args)
        elif command == "dev":
            self._handle_dev(args)
        elif command == "test":
            self._handle_test(args)
        elif command == "docs":
            self._handle_docs(args)
        elif command == "bug":
            self._handle_bug(args)
        elif command == "clean":
            self._handle_clean(args)
        else:
            logger.error(f"Unknown command: {command}")

    def _handle_download(self, args: argparse.Namespace) -> None:
        action = getattr(args, "action", None)
        if action == "list":
            self._handle_download_list()
        elif args.version:
            self.downloader.download_apache(args.version)
        else:
            self._handle_download_interactive()

    def _handle_download_list(self) -> None:
        from rich.console import Console
        from rich.table import Table

        console = Console()
        console.print("[dim]Fetching available versions from archive.apache.org...[/dim]")

        versions = self.downloader.list_versions()
        if not versions:
            console.print("[yellow]No versions found.[/yellow]")
            return

        table = Table(box=None, show_edge=False, pad_edge=False, header_style="bold underline")
        table.add_column("Version", style="cyan")
        table.add_column("Source", style="dim")
        table.add_column("Local", style="green")

        default = Config.DEFAULT_APACHE_VERSION

        for entry in reversed(versions):
            v = entry["version"]
            label = v
            if v == default:
                label = f"{v} (default)"

            source = "mirror" if entry["mirror"] else "archive"
            local = "downloaded" if entry["downloaded"] else ""
            table.add_row(label, source, local)

        console.print(table)
        console.print(
            f"\n[dim]{len(versions)} versions available.  Download with: apatchy download --version <version>[/dim]"
        )

    def _handle_download_interactive(self) -> None:
        from rich.console import Console

        from apatchy.utils.picker import pick_option

        console = Console()
        console.print("[dim]Fetching available versions from archive.apache.org...[/dim]")

        versions = self.downloader.list_versions()
        if not versions:
            console.print("[yellow]No versions found.[/yellow]")
            return

        default = Config.DEFAULT_APACHE_VERSION

        # Build display items (newest first)
        entries = list(reversed(versions))
        display: list[str] = []
        pre_selected = 0
        for i, entry in enumerate(entries):
            v = entry["version"]
            parts = [v]
            if v == default:
                parts.append("(default)")
                pre_selected = i
            parts.append("mirror" if entry["mirror"] else "archive")
            if entry["downloaded"]:
                parts.append("[downloaded]")
            display.append("  ".join(parts))

        choice = pick_option(display, title="Select Apache HTTPD version to download", selected=pre_selected)
        if choice is None:
            console.print("[dim]Cancelled.[/dim]")
            return

        selected_version = entries[choice]["version"]
        self.downloader.download_apache(selected_version)

    def _handle_configure(self, args: argparse.Namespace) -> None:
        # We need to know which Apache version we are working with
        # For now, assume default or find unique one in work dir
        # Todo: Add logic to find active httpd dir
        httpd_root = self._get_active_httpd()
        if not httpd_root:
            return

        verbose = getattr(args, "verbose", False)
        self.config_manager = ConfigManager(
            build_mode=args.mode,
            asan=getattr(args, "asan", False),
            ubsan=getattr(args, "ubsan", False),
            ubsan_ignorelist=getattr(args, "ubsan_ignorelist", None),
            intsan=getattr(args, "intsan", False),
            truncsan=getattr(args, "truncsan", False),
        )
        self.build_manager = BuildManager(httpd_root, self.config_manager, verbose=verbose)
        self.build_manager.configure_httpd()

    def _handle_compile(self, args: argparse.Namespace) -> None:
        httpd_root = self._get_active_httpd()
        if not httpd_root:
            return

        verbose = getattr(args, "verbose", False)
        self.config_manager = ConfigManager()  # Defaults
        self.build_manager = BuildManager(httpd_root, self.config_manager, verbose=verbose)
        jobs = getattr(args, "jobs", None)
        self.build_manager.compile_httpd(jobs=jobs, bear=getattr(args, "bear", False))

    def _handle_link(self, args: argparse.Namespace) -> None:
        httpd_root = self._get_active_httpd()
        if not httpd_root:
            return

        verbose = getattr(args, "verbose", False)
        self.config_manager = ConfigManager()
        self.build_manager = BuildManager(httpd_root, self.config_manager, verbose=verbose)
        self.build_manager.build_harness(
            mode=args.engine,
            harness_name=getattr(args, "harness", None),
            bear=getattr(args, "bear", False),
        )

    def _handle_fuzz(self, args: argparse.Namespace) -> None:
        self.config_manager = ConfigManager(config_name=args.config)
        self.fuzz_manager = FuzzManager(self.config_manager)

        harness_path = Config.WORK_DIR / f"fuzz_harness_{args.engine}"
        if not harness_path.exists():
            logger.error(f"Harness not found: {harness_path}. Run 'apatchy link {args.engine}' first.")
            return

        self.fuzz_manager.start_fuzzer(
            harness_path,
            engine=args.engine,
            grammar=getattr(args, "grammar", None),
            seed_dir=getattr(args, "seed_dir", None),
            resume=getattr(args, "resume", False),
            output_dir=getattr(args, "output_dir", "fuzz-output"),
            suppress=getattr(args, "suppress", None),
            timeout=getattr(args, "timeout", None),
            debug=getattr(args, "debug", False),
            workers=getattr(args, "workers", 1),
            pulse_interval=getattr(args, "pulse_interval", 60),
        )

    def _handle_triage(self, args: argparse.Namespace) -> None:
        httpd_root = self._get_active_httpd()
        if not httpd_root:
            return

        self.config_manager = ConfigManager(config_name=args.config)

        self.report_manager = ReportManager(httpd_root, self.config_manager)

        harness_path = Config.WORK_DIR / "fuzz_harness_coverage"
        if not harness_path.exists():
            logger.error("No coverage harness found. Run 'apatchy coverage' first to build it.")
            return

        if args.pipeline:
            logger.error("--pipeline is deprecated and will be re-written with proto multi-request support.")
            return

        modes = sum(bool(x) for x in (args.crash_file, args.bulk))
        if modes == 0:
            logger.error("Either a crash file or --bulk <dir> is required.")
            return
        if modes > 1:
            logger.error("Only one of crash file and --bulk can be used at a time.")
            return

        if args.bulk:
            self.report_manager.triage_bulk(
                args.bulk,
                harness_path,
                no_color=args.no_color,
                suppress=getattr(args, "suppress", None),
                timeout=args.timeout,
                is_libfuzzer=True,
            )
        else:
            self.report_manager.triage_crash(
                args.crash_file,
                harness_path,
                no_color=args.no_color,
                suppress=getattr(args, "suppress", None),
                timeout=args.timeout,
                is_libfuzzer=True,
            )

    def _get_toolchain_manager(self, verbose: bool = False) -> ToolchainManager:
        if self.toolchain_manager is None:
            self.toolchain_manager = ToolchainManager(verbose=verbose)
        return self.toolchain_manager

    def _handle_setup(self, args: argparse.Namespace) -> None:
        from rich.console import Console
        from rich.table import Table

        console = Console()
        verbose = getattr(args, "verbose", False)
        tm = self._get_toolchain_manager(verbose=verbose)

        action = getattr(args, "action", None)
        if not action:
            logger.error("No setup sub-command specified. Use: check, afl, llvm, libtool")
            return

        force = getattr(args, "force", False)

        if action == "check":
            deps = tm.check()
            table = Table(box=None, show_edge=False, pad_edge=False, header_style="bold underline")
            table.add_column("Category", style="dim")
            table.add_column("Name", style="cyan")
            table.add_column("Status", style="bold")
            table.add_column("Version", style="magenta")
            table.add_column("Path / Hint", style="dim")

            for dep in deps:
                status = "[green]OK[/green]" if dep.found else "[red]MISSING[/red]"
                detail = dep.path if dep.found else dep.install_hint
                table.add_row(dep.category, dep.name, status, dep.version, detail)

            console.print()
            console.print(table)
            found = sum(1 for d in deps if d.found)
            total = len(deps)
            color = "green" if found == total else "yellow"
            console.print(f"\n[{color}]{found}/{total} dependencies satisfied.[/{color}]")
            console.print(f"[dim]Toolchain config: {Config.TOOLCHAIN_CONFIG}[/dim]")

        elif action == "libtool":
            tm.setup("libtool", force=force)
            console.print(f"[dim]Toolchain config: {Config.TOOLCHAIN_CONFIG}[/dim]")

        elif action == "afl":
            tm.setup("afl", force=force)
            console.print(f"[dim]Toolchain config: {Config.TOOLCHAIN_CONFIG}[/dim]")

        elif action == "llvm":
            llvm_version = getattr(args, "llvm_version", None)
            tm.setup("llvm", force=force, llvm_version=llvm_version)
            console.print(f"[dim]Toolchain config: {Config.TOOLCHAIN_CONFIG}[/dim]")

        elif action == "lpm":
            tm.setup("lpm", force=force)
            console.print(f"[dim]Toolchain config: {Config.TOOLCHAIN_CONFIG}[/dim]")

    def _handle_harness(self, args: argparse.Namespace) -> None:
        from rich.console import Console
        from rich.table import Table

        from apatchy.core.harness import HarnessBuilder

        console = Console()

        action = getattr(args, "action", None)
        if not action:
            logger.error("No harness sub-command specified. Use: list")
            return

        if action == "list":
            harnesses = HarnessBuilder.list_harnesses()
            if not harnesses:
                console.print("[yellow]No harness files found.[/yellow]")
                return
            table = Table(box=None, show_edge=False, pad_edge=False, header_style="bold underline")
            table.add_column("Name", style="cyan")
            table.add_column("Description", style="magenta")
            for h in harnesses:
                table.add_row(h["name"], h["description"] or "(no description)")
            console.print(table)

    def _handle_coverage(self, args: argparse.Namespace) -> None:
        action = getattr(args, "action", None)
        if action == "report":
            httpd_root = self._get_active_httpd()
            if not httpd_root:
                return
            self.config_manager = ConfigManager(build_mode="coverage", config_name=args.config)
            self.report_manager = ReportManager(httpd_root, self.config_manager)
            self.report_manager.generate_coverage(
                corpus_dir=args.fuzzer_dir,
                config_name=args.config,
                output_dir=args.output,
                harness_name=getattr(args, "harness", None),
                exclude_file=getattr(args, "exclude", None),
                with_introspect=getattr(args, "with_introspect", False),
                with_modules=getattr(args, "with_modules", False),
            )
        else:
            logger.error("No coverage sub-command specified. Use: report")

    def _handle_introspect(self, args: argparse.Namespace) -> None:
        httpd_root = self._get_active_httpd()
        if not httpd_root:
            return
        self.config_manager = ConfigManager(build_mode="coverage")
        self.report_manager = ReportManager(httpd_root, self.config_manager)
        self.report_manager.generate_introspect(
            entry=args.entry,
            profdata_path=getattr(args, "profdata", None),
            binary_path=getattr(args, "binary", None),
            bitcode_path=getattr(args, "bitcode", None),
            output_path=getattr(args, "output", "introspect.json"),
            serve=not getattr(args, "no_serve", False),
            port=getattr(args, "port", 9000),
        )

    def _handle_profile(self, args: argparse.Namespace) -> None:
        action = getattr(args, "action", None)
        if action == "callgrind":
            httpd_root = self._get_active_httpd()
            if not httpd_root:
                return
            self.config_manager = ConfigManager(config_name=args.config)
            self.report_manager = ReportManager(httpd_root, self.config_manager)
            self.report_manager.generate_callgrind(
                corpus_dir=args.fuzzer_dir,
                config_name=args.config,
                output_dir=args.output,
                harness_name=getattr(args, "harness", None),
                jobs=getattr(args, "jobs", 1),
                timeout=getattr(args, "timeout", 120),
            )
        else:
            logger.error("No profile sub-command specified. Use: callgrind")

    def _handle_module(self, args: argparse.Namespace) -> None:
        from rich.console import Console
        from rich.table import Table

        console = Console()

        httpd_root = self._get_active_httpd()
        if not httpd_root:
            return

        mm = ModuleManager(httpd_root)
        action = getattr(args, "action", None)
        if not action:
            logger.error("No module sub-command specified. Use: build, list")
            return

        if action == "build":
            mm.build_module(name=getattr(args, "name", None), cc=getattr(args, "cc", None))

        elif action == "list":
            modules = mm.list_modules()
            if not modules:
                console.print("[yellow]No external module sources found.[/yellow]")
                return
            table = Table(box=None, show_edge=False, pad_edge=False, header_style="bold underline")
            table.add_column("Name", style="cyan")
            table.add_column("Source", style="dim")
            table.add_column("Built", style="green")
            for m in modules:
                table.add_row(m["name"], m["source"], m["built"] or "(not built)")
            console.print(table)

    def _handle_dev(self, args: argparse.Namespace) -> None:
        from rich.console import Console
        from rich.table import Table

        console = Console()

        httpd_root = self._get_active_httpd()
        if not httpd_root:
            return

        dm = DevManager(httpd_root)
        action = getattr(args, "action", None)
        if not action:
            logger.error("No dev sub-command specified. Use: init, build, list")
            return

        if action == "init":
            try:
                project_dir = dm.init_project(args.name)
                console.print(f"[green]Created dev project:[/green] {project_dir}")
                console.print(f"[dim]Edit {project_dir / 'harness.c'} then run: apatchy dev build {args.name}[/dim]")
            except FileExistsError as e:
                logger.error(str(e))

        elif action == "build":
            dm.build_project(args.name, engine=args.engine)

        elif action == "list":
            projects = dm.list_projects()
            if not projects:
                console.print("[yellow]No dev projects found. Run 'apatchy dev init <name>' to create one.[/yellow]")
                return
            table = Table(box=None, show_edge=False, pad_edge=False, header_style="bold underline")
            table.add_column("Name", style="cyan")
            table.add_column("Path", style="dim")
            table.add_column("Built", style="green")
            table.add_column("CompDB", style="magenta")
            for p in projects:
                table.add_row(p["name"], p["path"], p["built"] or "(not built)", p["compdb"])
            console.print(table)

    def _handle_test(self, args: argparse.Namespace) -> None:
        import subprocess
        import sys

        tests_dir = Config.PROJECT_ROOT / "framework" / "tests"
        if not tests_dir.exists():
            logger.error(f"Tests directory not found at {tests_dir}")
            return

        cmd = [sys.executable, "-m", "pytest", "-v"]

        scope = getattr(args, "scope", None)
        if scope == "unit":
            cmd.append(str(tests_dir / "unit"))
        elif scope == "integration":
            cmd.append(str(tests_dir / "integration"))
        else:
            cmd.append(str(tests_dir))

        filter_expr = getattr(args, "filter_expr", None)
        if filter_expr:
            cmd.extend(["-k", filter_expr])

        if getattr(args, "failfast", False):
            cmd.append("-x")

        if getattr(args, "cov", False):
            cmd.extend(["--cov=apatchy", "--cov-report=term-missing"])

        env = os.environ.copy()
        apache_version = getattr(args, "apache_version", None)
        if apache_version:
            env["APATCHY_TEST_VERSIONS"] = apache_version

        logger.info(f"Running: {' '.join(cmd)}")
        result = subprocess.run(cmd, cwd=str(Config.PROJECT_ROOT / "framework"), env=env)
        raise SystemExit(result.returncode)

    def _handle_docs(self, args: argparse.Namespace) -> None:
        import shutil
        import subprocess

        source_dir = Config.PROJECT_ROOT / "docs"
        build_dir = source_dir / "_build" / "html"

        if not source_dir.exists():
            logger.error(f"Sphinx source directory not found at {source_dir}")
            return

        sphinx = toolchain_config.resolve_tool("sphinx-build")
        if sphinx is None:
            logger.error("sphinx-build not found. Install with: pip install './framework[docs]'")
            return

        # Generate Apache HTTPD Doxygen assets (tag file + HTML) for doxylink cross-references
        self._ensure_doxygen_tagfile(source_dir, rebuild=getattr(args, "rebuild", False))

        # Clean stale build artifacts before rebuilding
        build_root = source_dir / "_build"
        if build_root.exists():
            shutil.rmtree(build_root)

        logger.info("Building Sphinx documentation...")
        result = subprocess.run(
            [sphinx, "-b", "html", str(source_dir), str(build_dir)],
            cwd=str(Config.PROJECT_ROOT),
        )
        if result.returncode != 0:
            logger.error("Sphinx build failed")
            return

        # Move Doxygen HTML into the Sphinx output so /doxygen/ links work without a separate server
        doxy_html = source_dir / "_doxygen" / "html"
        doxy_dest = build_dir / "doxygen"
        if doxy_html.exists():
            if doxy_dest.exists():
                shutil.rmtree(doxy_dest)
            shutil.move(str(doxy_html), str(doxy_dest))
            logger.info(f"Doxygen HTML moved to {doxy_dest}")

        index = build_dir / "index.html"
        logger.info(f"Documentation built at {index}")

        if args.serve is not None:
            import functools
            import http.server

            port = args.serve
            bind = getattr(args, "bind", "localhost")
            handler = functools.partial(http.server.SimpleHTTPRequestHandler, directory=str(build_dir))
            logger.info(f"Serving docs at http://{bind}:{port}/ (Ctrl+C to stop)")
            with http.server.HTTPServer((bind, port), handler) as server:
                server.serve_forever()

    def _ensure_doxygen_tagfile(self, docs_dir: Path, *, rebuild: bool = False) -> None:
        """Generate the Apache HTTPD Doxygen tag file and HTML if they don't already exist."""
        import shutil
        import subprocess

        doxy_dir = docs_dir / "_doxygen"
        tag_file = doxy_dir / "httpd.tag"
        html_dir = doxy_dir / "html"

        if rebuild:
            logger.info("Rebuilding Doxygen output (--rebuild)...")
            if tag_file.exists():
                tag_file.unlink()
            if html_dir.exists():
                shutil.rmtree(html_dir)
        elif tag_file.exists() and html_dir.exists():
            return

        doxygen = toolchain_config.resolve_tool("doxygen")
        if doxygen is None:
            logger.warning("doxygen not found; Apache API cross-references will be unavailable")
            return

        httpd_dir = self._get_active_httpd()
        if httpd_dir is None:
            logger.warning("No httpd source found; skipping Doxygen generation")
            return

        doxyfile = doxy_dir / "Doxyfile"
        if not doxyfile.exists():
            logger.warning(f"Doxyfile not found at {doxyfile}; skipping Doxygen generation")
            return

        logger.info(f"Generating Doxygen tag file and HTML from {httpd_dir.name}...")
        env = {**os.environ, "HTTPD_SRC": str(httpd_dir)}
        result = subprocess.run(
            [doxygen, str(doxyfile)],
            cwd=str(doxy_dir),
            env=env,
        )
        if result.returncode != 0:
            logger.warning("Doxygen generation failed; API cross-references will be unavailable")
        else:
            if tag_file.exists():
                logger.info(f"Doxygen tag file generated at {tag_file}")
            if html_dir.exists():
                logger.info(f"Doxygen HTML generated at {html_dir}")

    def _get_active_httpd(self) -> Optional[Path]:
        # reuse logic to find httpd directory
        # For now, use default version
        version = Config.DEFAULT_APACHE_VERSION
        target = Config.get_apache_dir(version)
        if not target.exists():
            # Try finding any httpd-*
            dirs = [
                d
                for d in Config.WORK_DIR.glob("httpd-*")
                if not d.name.endswith(("-cov", "-standalone", "-prof", "-lf"))
            ]
            if len(dirs) == 1:
                return dirs[0]
            elif len(dirs) > 1:
                logger.error("Multiple httpd directories found. Please specify (todo).")
                return None
            else:
                logger.error("No httpd directory found. Run 'download' first.")
                return None
        return target

    def _handle_bug(self, args: argparse.Namespace) -> None:
        from rich.console import Console
        from rich.table import Table

        from apatchy.managers.bug_manager import BugManager

        console = Console()
        verbose = getattr(args, "verbose", False)
        bm = BugManager(verbose=verbose)

        action = getattr(args, "action", None)
        if not action:
            logger.error("No bug sub-command specified. Use: list, info, setup, reproduce")
            return

        if action == "list":
            bugs = bm.list_bugs()
            if not bugs:
                console.print("[yellow]No bugs found. Add bug directories under bugs/.[/yellow]")
                return
            table = Table(box=None, show_edge=False, pad_edge=False, header_style="bold underline")
            table.add_column("CVE ID", style="cyan")
            table.add_column("Module(s)", style="magenta")
            table.add_column("Version", style="green")
            table.add_column("Type", style="yellow")
            table.add_column("Description", style="dim")
            for bug in bugs:
                table.add_row(
                    bug["id"],
                    ", ".join(bug["modules"]),
                    bug["version"],
                    bug["type"],
                    bug["description"],
                )
            console.print(table)

        elif action == "info":
            try:
                bug = bm.get_bug_instance(args.cve_id)
            except FileNotFoundError as e:
                logger.error(str(e))
                return

            console.print(f"\n[bold cyan]{bug.cve_id}[/bold cyan]")
            console.print(f"  [dim]Description:[/dim]  {bug.description}")
            console.print(f"  [dim]Version:[/dim]      {bug.version}")
            console.print(f"  [dim]Type:[/dim]         {bug.bug_type}")
            console.print(f"  [dim]Modules:[/dim]      {', '.join(bug.modules)}")
            console.print(f"  [dim]Sanitizers:[/dim]   {', '.join(bug.sanitizers)}")
            console.print(f"  [dim]Config:[/dim]       {bug.httpd_config}")
            console.print(f"  [dim]Directory:[/dim]    {bug.bug_dir}")
            if bug.references:
                console.print("  [dim]References:[/dim]")
                for ref in bug.references:
                    console.print(f"    - {ref}")
            console.print()

        elif action == "setup":
            bm.setup(args.cve_id)

        elif action == "reproduce":
            bm.reproduce(args.cve_id)

        elif action == "clean":
            cve_id = getattr(args, "cve_id", None)
            if cve_id:
                bug = bm.get_bug_instance(cve_id)
                bug.clean()
                console.print(f"[green]Cleaned {bug.cve_id}[/green]")
            else:
                bugs = bm.list_bugs()
                for bug_info in bugs:
                    bug = bm.get_bug_instance(bug_info["id"])
                    bug.clean()
                    console.print(f"[green]Cleaned {bug.cve_id}[/green]")

    def _handle_clean(self, args: argparse.Namespace) -> None:
        import shutil

        work = Config.WORK_DIR

        # Build artifacts (always cleaned)
        build_patterns = [
            "fuzz_harness_*",  # compiled harness binaries
            "*.profraw",
            "*.profdata",
            "introspect.json",
        ]
        build_dirs = [
            ".objects",
            "fuzz-output",
            "modules",
            ".libs",
            ".proto_gen",
            "coverage-report",
            "callgrind-out",
            "introspect-report",
        ]
        build_globs = [
            "fuzz-seeds/grammar_*.txt",  # generated grammar seeds
            "coverage-report*",
            "conf/*",  # generated configs (mime.types is excluded below)
        ]
        # Source files that must survive cleaning
        keep = {work / "conf" / "mime.types"}

        # Full reset (--all)
        all_patterns = [
            "toolchain.config",
        ]
        all_dirs = [
            "toolchain",
            ".test_cache",
            "dev",
            "introspector/build",
        ]
        all_globs = [
            "httpd-*",
        ]

        targets = []

        # Collect build artifacts
        for pat in build_patterns:
            targets.extend(work.glob(pat))
        for d in build_dirs:
            p = work / d
            if p.exists():
                targets.append(p)
        for pat in build_globs:
            targets.extend(work.glob(pat))

        # Collect --all targets
        if getattr(args, "all", False):
            for pat in all_patterns:
                targets.extend(work.glob(pat))
            for d in all_dirs:
                p = work / d
                if p.exists():
                    targets.append(p)
            for pat in all_globs:
                targets.extend(p for p in work.glob(pat) if p.is_dir())

        targets = sorted(set(targets) - keep)

        if not targets:
            logger.info("Nothing to clean.")
            return
        logger.info("Will remove:")
        for t in targets:
            logger.info(f"  {t.relative_to(work)}")

        answer = input("\nProceed? [y/N] ").strip().lower()
        if answer != "y":
            logger.info("Aborted.")
            return

        for t in targets:
            if t.is_dir():
                shutil.rmtree(t)
            else:
                t.unlink()
            logger.info(f"Removed {t.relative_to(work)}")

        # Clean all bug artifacts
        from apatchy.managers.bug_manager import BugManager

        bm = BugManager()
        bugs = bm.list_bugs()
        for bug_info in bugs:
            bug = bm.get_bug_instance(bug_info["id"])
            bug.clean()
            logger.info(f"Cleaned bug artifacts for {bug.cve_id}")

        logger.info("Clean complete.")
