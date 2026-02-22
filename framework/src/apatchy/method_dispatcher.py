"""Command dispatcher that routes CLI sub-commands to the appropriate manager.

The :class:`MethodDispatcher` acts as the glue between the argument parser
(defined in :mod:`apatchy.main`) and the various manager classes that
implement each workflow step (download, configure, build, fuzz, ...).
"""

import argparse
from pathlib import Path
from typing import Optional
from apatchy.utils.logger import get_logger
from apatchy.config import Config
from apatchy.core.downloader import Downloader
from apatchy.managers.config_manager import ConfigManager
from apatchy.managers.build_manager import BuildManager
from apatchy.managers.fuzz_manager import FuzzManager
from apatchy.managers.report_manager import ReportManager
from apatchy.managers.mutator_manager import MutatorManager
from apatchy.managers.toolchain_manager import ToolchainManager
from apatchy.managers.module_manager import ModuleManager
from apatchy.managers.dev_manager import DevManager
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
        self.mutator_manager: Optional[MutatorManager] = None
        self.toolchain_manager: Optional[ToolchainManager] = None

    def dispatch(self, args: argparse.Namespace) -> None:
        """Inspect *args.command* and delegate to the matching handler.

        Parameters
        ----------
        args : argparse.Namespace
            The fully-parsed CLI arguments.  Must contain a ``command``
            attribute that names the top-level sub-command.
        """
        command = args.command
        logger.info(f"Dispatching command: {command}")
        
        if command == "download":
            self._handle_download(args)
        elif command == "configure":
            self._handle_configure(args)
        elif command == "compile":
            self._handle_compile(args)
        elif command == "build":
            self._handle_build(args)
        elif command == "fuzz":
            self._handle_fuzz(args)
        elif command == "triage":
            self._handle_triage(args)
        elif command == "coverage":
            self._handle_coverage(args)
        elif command == "setup":
            self._handle_setup(args)
        elif command == "grammar":
            self._handle_grammar(args)
        elif command == "harness":
            self._handle_harness(args)
        elif command == "mutator":
            self._handle_mutator(args)
        elif command == "module":
            self._handle_module(args)
        elif command == "dev":
            self._handle_dev(args)
        elif command == "docs":
            self._handle_docs(args)
        else:
            logger.error(f"Unknown command: {command}")

    def _handle_download(self, args: argparse.Namespace) -> None:
        self.downloader.download_apache(args.version)

    def _handle_configure(self, args: argparse.Namespace) -> None:
        # We need to know which Apache version we are working with
        # For now, assume default or find unique one in work dir
        # Todo: Add logic to find active httpd dir
        httpd_root = self._get_active_httpd()
        if not httpd_root:
            return

        verbose = getattr(args, 'verbose', False)
        self.config_manager = ConfigManager(build_mode=args.mode, asan=getattr(args, 'asan', False), ubsan=getattr(args, 'ubsan', False), intsan=getattr(args, 'intsan', False), truncsan=getattr(args, 'truncsan', False))
        self.build_manager = BuildManager(httpd_root, self.config_manager, verbose=verbose)
        self.build_manager.configure_httpd()

    def _handle_compile(self, args: argparse.Namespace) -> None:
        httpd_root = self._get_active_httpd()
        if not httpd_root:
            return

        verbose = getattr(args, 'verbose', False)
        self.config_manager = ConfigManager() # Defaults
        self.build_manager = BuildManager(httpd_root, self.config_manager, verbose=verbose)
        self.build_manager.compile_httpd(bear=getattr(args, 'bear', False))

    def _handle_build(self, args: argparse.Namespace) -> None:
        httpd_root = self._get_active_httpd()
        if not httpd_root:
            return

        verbose = getattr(args, 'verbose', False)
        self.config_manager = ConfigManager()
        self.build_manager = BuildManager(httpd_root, self.config_manager, verbose=verbose)
        self.build_manager.build_harness(
            mode=args.engine,
            harness_name=getattr(args, 'harness', None),
            bear=getattr(args, 'bear', False),
        )

    def _handle_fuzz(self, args: argparse.Namespace) -> None:
        role = getattr(args, 'role', None)
        name = getattr(args, 'name', None)

        # --role and --name are AFL-only features
        if (role or name) and args.engine != "afl":
            logger.error("--role and --name are only supported with --engine afl")
            return

        self.config_manager = ConfigManager(engine=args.engine, config_name=args.config)
        self.fuzz_manager = FuzzManager(self.config_manager)

        # The actual ELF binary is in .libs/ (libtool puts a shell wrapper in cwd)
        harness_path = Config.WORK_DIR / ".libs" / f"fuzz_harness_{args.engine}"
        if not harness_path.exists():
            # Fall back to the libtool wrapper (works for non-AFL engines)
            harness_path = Config.WORK_DIR / f"fuzz_harness_{args.engine}"
        if not harness_path.exists():
            logger.error(f"Harness not found: {harness_path}. Run 'apatchy build {args.engine}' first.")
            return

        self.fuzz_manager.start_fuzzer(
            harness_path,
            engine=args.engine,
            mutator=getattr(args, 'mutator', None),
            grammar=getattr(args, 'grammar', None),
            resume=getattr(args, 'resume', False),
            output_dir=getattr(args, 'output_dir', 'afl-output'),
            role=role,
            name=name,
            suppress=getattr(args, 'suppress', None),
        )

    def _handle_triage(self, args: argparse.Namespace) -> None:
        httpd_root = self._get_active_httpd()
        if not httpd_root:
            return
            
        self.config_manager = ConfigManager(config_name=args.config) # Defaults engine/mode
        
        self.report_manager = ReportManager(httpd_root, self.config_manager)
        
        # Find a harness binary for triage. Prefer standalone (reads from
        # stdin) over AFL (expects shared memory forkserver protocol).
        harness_path = None
        for name in ("fuzz_harness_standalone", "fuzz_harness_afl"):
            candidate = Config.WORK_DIR / ".libs" / name
            if candidate.exists():
                harness_path = candidate
                break
            candidate = Config.WORK_DIR / name
            if candidate.exists():
                harness_path = candidate
                break

        if not harness_path:
            logger.error("No harness binary found. Run 'apatchy build standalone' or 'apatchy build afl' first.")
            return

        # We need to tell the config manager which config to use if it's not default?
        # For now, let's update ReportManager to pass args.config to get_httpd_config.
        # I can't do that easily without changing ReportManager again.
        
        # Simpler approach: ConfigManager could have a current_config property.
        
        self.report_manager.triage_crash(
            args.crash_file, harness_path,
            no_color=args.no_color,
            suppress=getattr(args, 'suppress', None),
        )


    def _get_mutator_manager(self) -> MutatorManager:
        if self.mutator_manager is None:
            self.mutator_manager = MutatorManager()
        return self.mutator_manager

    def _get_toolchain_manager(self) -> ToolchainManager:
        if self.toolchain_manager is None:
            self.toolchain_manager = ToolchainManager()
        return self.toolchain_manager

    def _handle_setup(self, args: argparse.Namespace) -> None:
        from rich.console import Console
        from rich.table import Table
        console = Console()
        tm = self._get_toolchain_manager()

        action = getattr(args, "action", None)
        if not action:
            logger.error("No setup sub-command specified. Use: check, afl, llvm")
            return

        standalone = getattr(args, "standalone", False)

        if action == "check":
            deps = tm.check()
            table = Table(title="Dependency Status")
            table.add_column("Category", style="dim")
            table.add_column("Name", style="cyan")
            table.add_column("Status", style="bold")
            table.add_column("Version", style="magenta")
            table.add_column("Path / Hint", style="dim")

            for dep in deps:
                status = "[green]OK[/green]" if dep.found else "[red]MISSING[/red]"
                detail = dep.path if dep.found else dep.install_hint
                table.add_row(dep.category, dep.name, status, dep.version, detail)

            console.print(table)
            found = sum(1 for d in deps if d.found)
            total = len(deps)
            color = "green" if found == total else "yellow"
            console.print(f"\n[{color}]{found}/{total} dependencies satisfied.[/{color}]")
            console.print(f"[dim]Toolchain config: {Config.TOOLCHAIN_CONFIG}[/dim]")

        elif action == "afl":
            tm.setup_afl()
            console.print(f"[dim]Toolchain config: {Config.TOOLCHAIN_CONFIG}[/dim]")

        elif action == "llvm":
            tm.setup_llvm(standalone=standalone)
            console.print(f"[dim]Toolchain config: {Config.TOOLCHAIN_CONFIG}[/dim]")

    def _handle_grammar(self, args: argparse.Namespace) -> None:
        from rich.console import Console
        from rich.table import Table
        console = Console()
        mm = self._get_mutator_manager()

        action = getattr(args, "action", None)
        if not action:
            logger.error("No grammar sub-command specified. Use: setup, build, status, list")
            return

        if action == "setup":
            mm.setup()

        elif action == "build":
            result = mm.build_grammar(args.grammar_name)
            if result:
                console.print(f"[green]Built:[/green] {result}")

        elif action == "status":
            info = mm.status()
            table = Table(title="Grammar Mutator Status")
            table.add_column("Property", style="cyan")
            table.add_column("Value", style="magenta")
            table.add_row("Setup", "yes" if info["setup"] else "no")
            table.add_row("Directory", str(info["grammar_mutator_dir"]))
            built = info["built_grammars"]
            table.add_row("Built grammars", ", ".join(built) if built else "(none)")
            built_cm = info["built_custom_mutators"]
            table.add_row("Built custom mutators", ", ".join(built_cm) if built_cm else "(none)")
            console.print(table)

        elif action == "list":
            grammars = mm.list_grammars()
            if not grammars:
                console.print("[yellow]No grammar files found.[/yellow]")
                return
            table = Table(title="Available Grammars")
            table.add_column("Name", style="cyan")
            for g in grammars:
                table.add_row(g)
            console.print(table)

    def _handle_mutator(self, args: argparse.Namespace) -> None:
        from rich.console import Console
        from rich.table import Table
        console = Console()
        mm = self._get_mutator_manager()

        action = getattr(args, "action", None)
        if not action:
            logger.error("No mutator sub-command specified. Use: build, list")
            return

        if action == "build":
            mm.build_custom_mutator(name=getattr(args, "name", None))

        elif action == "list":
            mutators = mm.list_custom_mutators()
            if not mutators:
                console.print("[yellow]No custom mutator sources found.[/yellow]")
                return
            table = Table(title="Custom Mutators")
            table.add_column("Name", style="cyan")
            table.add_column("Source", style="dim")
            table.add_column("Built", style="green")
            for m in mutators:
                table.add_row(m["name"], m["source"], m["built"] or "(not built)")
            console.print(table)

    def _handle_harness(self, args: argparse.Namespace) -> None:
        from rich.console import Console
        from rich.table import Table
        from apatchy.core.harness import HarnessBuilder
        console = Console()

        action = getattr(args, "action", None)
        if not action:
            logger.error("No harness sub-command specified. Use: list, use")
            return

        if action == "list":
            harnesses = HarnessBuilder.list_harnesses()
            if not harnesses:
                console.print("[yellow]No harness files found.[/yellow]")
                return
            table = Table(title="Available Harnesses")
            table.add_column("Name", style="cyan")
            table.add_column("Description", style="magenta")
            for h in harnesses:
                table.add_row(h["name"], h["description"] or "(no description)")
            console.print(table)

        elif action == "use":
            name = args.name
            try:
                dest = HarnessBuilder.use_harness(name)
                console.print(f"[green]Harness '{name}' copied to {dest}[/green]")
            except FileNotFoundError as e:
                logger.error(str(e))

    def _handle_coverage(self, args: argparse.Namespace) -> None:
        action = getattr(args, "action", None)
        if action == "report":
            httpd_root = self._get_active_httpd()
            if not httpd_root:
                return
            self.config_manager = ConfigManager(build_mode="coverage", config_name=args.config)
            self.report_manager = ReportManager(httpd_root, self.config_manager)
            self.report_manager.generate_coverage(
                afl_dir=args.afl_dir,
                config_name=args.config,
                output_dir=args.output,
                harness_name=getattr(args, "harness", None),
            )
        else:
            logger.error("No coverage sub-command specified. Use: report")

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
            table = Table(title="External Modules")
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
            table = Table(title="Dev Harness Projects")
            table.add_column("Name", style="cyan")
            table.add_column("Path", style="dim")
            table.add_column("Built", style="green")
            table.add_column("CompDB", style="magenta")
            for p in projects:
                table.add_row(p["name"], p["path"], p["built"] or "(not built)", p["compdb"])
            console.print(table)

    def _handle_docs(self, args: argparse.Namespace) -> None:
        import subprocess
        import shutil

        source_dir = Config.PROJECT_ROOT / "docs" / "api"
        build_dir = source_dir / "_build" / "html"

        if not source_dir.exists():
            logger.error(f"Sphinx source directory not found at {source_dir}")
            return

        sphinx = shutil.which("sphinx-build")
        if sphinx is None:
            logger.error("sphinx-build not found. Install with: pip install './framework[docs]'")
            return

        logger.info("Building Sphinx documentation...")
        result = subprocess.run(
            [sphinx, "-b", "html", str(source_dir), str(build_dir)],
            cwd=str(Config.PROJECT_ROOT),
        )
        if result.returncode != 0:
            logger.error("Sphinx build failed")
            return

        index = build_dir / "index.html"
        logger.info(f"Documentation built at {index}")

        if args.serve is not None:
            import http.server
            import functools

            port = args.serve
            handler = functools.partial(http.server.SimpleHTTPRequestHandler, directory=str(build_dir))
            logger.info(f"Serving docs at http://localhost:{port}/ (Ctrl+C to stop)")
            with http.server.HTTPServer(("localhost", port), handler) as server:
                server.serve_forever()

    def _get_active_httpd(self) -> Optional[Path]:
        # reuse logic to find httpd directory
        # For now, use default version
        version = Config.DEFAULT_APACHE_VERSION
        target = Config.get_apache_dir(version)
        if not target.exists():
            # Try finding any httpd-*
            dirs = [d for d in Config.WORK_DIR.glob("httpd-*") if not d.name.endswith(("-cov", "-standalone"))]
            if len(dirs) == 1:
                return dirs[0]
            elif len(dirs) > 1:
                logger.error("Multiple httpd directories found. Please specify (todo).")
                return None
            else:
                logger.error("No httpd directory found. Run 'download' first.")
                return None
        return target
