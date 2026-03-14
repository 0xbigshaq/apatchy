"""Fuzzing session management for AFL++ and LibFuzzer.

This module contains :class:`FuzzManager` which prepares the corpus,
optionally generates grammar-based seeds, and launches the chosen
fuzzing engine.  It also includes :class:`GrammarSeedGenerator` for
expanding a JSON grammar into concrete seed inputs.
"""

import json
import os
import random
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from apatchy.core import toolchain_config
from apatchy.core.process_runner import ProcessRunner
from apatchy.managers.config_manager import ConfigManager
from apatchy.utils.logger import get_logger

logger = get_logger(__name__)


class GrammarSeedGenerator:
    r"""Walk a JSON grammar (keyed by non-terminal symbols) to produce concrete byte strings.

    The grammar must be a dict where each key is a non-terminal symbol (e.g. ``<A>``,
    ``<method>``) and each value is a list of productions. Each production is itself a
    list of tokens that are either non-terminals (present as keys in the dict) or
    terminals (literal strings). The special symbol ``<A>`` is the start symbol and
    must always be present.

    The generator expands the grammar recursively, picking a random production at each
    step. To prevent unbounded recursion on cyclic grammars, expansion stops at
    ``max_depth`` and the shortest available production is chosen as a fallback.

    Args:
        grammar: A dict mapping non-terminal names to lists of token-list productions.
        max_depth: Maximum recursion depth before forcing the shortest production.
            Defaults to 12.

    CLI usage:

    ``GrammarSeedGenerator`` is used automatically when you pass a grammar
    file to the ``fuzz`` command:

    .. code-block:: bash

        # Seeds are generated from the grammar before fuzzing starts
        apatchy fuzz --grammar grammars/http.json

    Example:
        .. code-block:: python

            grammar = {
                "<A>": [["<method>", " / HTTP/1.1\\r\\n\\r\\n"]],
                "<method>": [["GET"], ["POST"], ["HEAD"]],
            }
            gen = GrammarSeedGenerator(grammar)
            seed = gen.generate()  # e.g. b"POST / HTTP/1.1\\r\\n\\r\\n"
    """

    def __init__(self, grammar: Dict[str, List[List[str]]], max_depth: int = 12) -> None:
        self.grammar = grammar
        self.max_depth = max_depth

    def generate(self) -> bytes:
        """Generate a mutated HTTP request by expanding from the ``<A>`` start symbol.

        Returns
        -------
            A raw HTTP request as bytes.
        """
        return self._expand("<A>", 0).encode("latin-1")

    def _expand(self, symbol: str, depth: int) -> str:
        if symbol not in self.grammar:
            # Terminal - return as-is
            return symbol
        if depth >= self.max_depth:
            # Pick the shortest production to avoid infinite recursion
            productions = self.grammar[symbol]
            shortest = min(productions, key=len)
            return "".join(self._expand_terminal(t) for t in shortest)
        productions = self.grammar[symbol]
        chosen = random.choice(productions)
        return "".join(self._expand(t, depth + 1) for t in chosen)

    def _expand_terminal(self, symbol: str) -> str:
        """Expand preferring terminals / shortest paths."""
        if symbol not in self.grammar:
            return symbol
        productions = self.grammar[symbol]
        # Prefer productions with no non-terminals
        for prod in productions:
            if all(t not in self.grammar for t in prod):
                return "".join(prod)
        # Fall back to shortest
        shortest = min(productions, key=len)
        return "".join(shortest)


class FuzzManager:
    """Prepare the corpus and launch a fuzzing session with AFL++ or LibFuzzer.

    ``FuzzManager`` is the main entry point for starting a fuzzing run. It handles:

    * Creating and seeding the input/output corpus directories.
    * Optionally expanding a JSON grammar into concrete seed files before the
      fuzzer starts (via :class:`GrammarSeedGenerator`).
    * Building the ``afl-fuzz`` command line, including parallel-mode flags
      (``-M`` / ``-S``), custom mutator libraries, per-execution timeouts, and
      UBSan options.
    * Migrating a solo AFL++ corpus (``default/``) to a named instance directory
      when switching to parallel mode.
    * Launching LibFuzzer as an alternative engine.

    Args:
        config_manager: A :class:`~apatchy.managers.config_manager.ConfigManager`
            instance used to locate the httpd config file. The config path is
            passed to the harness via the ``FUZZ_CONF`` environment variable so
            Apache's configuration pipeline is active during fuzzing.

    CLI usage:

    .. code-block:: bash

        # Basic fuzzing run
        apatchy fuzz

        # Fuzz with a custom config and grammar seeds
        apatchy fuzz --config bugs/cve_2022_23943/httpd.conf --grammar grammars/http.json

        # Resume a previous session
        apatchy fuzz --resume

        # Parallel mode: start main and secondary instances
        apatchy fuzz --role main --name main01
        apatchy fuzz --role secondary --name sec01

        # Custom mutator with per-execution timeout
        apatchy fuzz --mutator mutators/my_mutator.so --timeout 5

        # UBSan suppression file
        apatchy fuzz --suppress configs/ubsan.supp

    Example:
        .. code-block:: python

            from apatchy.managers.config_manager import ConfigManager
            from apatchy.managers.fuzz_manager import FuzzManager
            from pathlib import Path

            config = ConfigManager()
            fm = FuzzManager(config)

            # Start a solo AFL++ run with a grammar-based corpus
            fm.start_fuzzer(
                harness_path=Path("build/harness"),
                engine="afl",
                grammar="grammars/http.json",
            )

            # Start the main instance of a parallel run, resuming a previous session
            fm.start_fuzzer(
                harness_path=Path("build/harness"),
                engine="afl",
                role="main",
                name="main01",
                resume=True,
            )
    """

    def __init__(self, config_manager: ConfigManager) -> None:
        self.config_manager = config_manager
        self.logger = logger
        self.runner = ProcessRunner()
        self.work_dir = Path(".").resolve()

    def _resolve_preload_modules(self, config_path: Path) -> List[str]:
        """Parse LoadModule directives from the config and return .so paths."""
        modules = []
        for line in config_path.read_text().splitlines():
            stripped = line.strip()
            if stripped.startswith("LoadModule") and not stripped.startswith("#"):
                parts = stripped.split()
                if len(parts) >= 3:
                    so_path = self.work_dir / parts[2]
                    if so_path.exists():
                        modules.append(str(so_path))
                    else:
                        self.logger.warning(f"LoadModule references missing file: {parts[2]}")
        return modules

    def prepare_corpus(self, input_dir: str = "afl-input", output_dir: str = "afl-output") -> Tuple[Path, Path]:
        """Create input/output directories and seed the corpus if empty."""
        input_path = self.work_dir / input_dir
        output_path = self.work_dir / output_dir

        input_path.mkdir(exist_ok=True)
        output_path.mkdir(exist_ok=True)

        # Create seed if empty
        if not any(input_path.iterdir()):
            self.logger.info("Creating seed input...")
            (input_path / "seed1.txt").write_bytes(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")

        return input_path, output_path

    def generate_grammar_seeds(self, grammar_path: Path, input_dir: Path, count: int = 50) -> int:
        """Read a JSON grammar file and generate seed inputs into input_dir.

        Returns the number of seeds written.
        """
        try:
            grammar = json.loads(grammar_path.read_text())
        except (json.JSONDecodeError, OSError) as e:
            self.logger.error(f"Failed to parse grammar {grammar_path}: {e}")
            return 0

        if "<A>" not in grammar:
            self.logger.error("Grammar must have a <A> start symbol")
            return 0

        gen = GrammarSeedGenerator(grammar)
        written = 0
        seen = set()

        for _i in range(count * 3):  # over-generate to deduplicate
            if written >= count:
                break
            data = gen.generate()
            if data in seen:
                continue
            seen.add(data)
            seed_path = input_dir / f"grammar_{written:04d}.txt"
            seed_path.write_bytes(data)
            written += 1

        self.logger.info(f"Generated {written} grammar-based seeds in {input_dir}")
        return written

    def start_fuzzer(
        self,
        harness_path: Path,
        engine: str = "afl",
        mutator: Optional[list[str]] = None,
        grammar: Optional[str] = None,
        resume: bool = False,
        output_dir: str = "afl-output",
        role: Optional[str] = None,
        name: Optional[str] = None,
        suppress: Optional[str] = None,
        timeout: Optional[int] = None,
        debug: bool = False,
    ) -> None:
        """Launch the fuzzing engine with the configured harness and corpus.

        Prepares the corpus, optionally generates grammar-based seeds, and
        then hands off to either :meth:`_start_afl` or :meth:`_start_libfuzzer`.

        Args:
            harness_path: Path to the compiled fuzzing harness binary.
            engine: Fuzzing engine to use. ``"afl"`` (default) or ``"libfuzzer"``.
            mutator: One or more paths to AFL++ custom mutator ``.so`` libraries.
                Multiple libraries are chained with ``:``.
            grammar: Path to a JSON grammar file. If provided and no grammar seeds
                exist yet, seeds are generated before the fuzzer starts.
            resume: If ``True``, sets ``AFL_AUTORESUME=1`` so AFL++ picks up a
                previous session automatically.
            output_dir: Name of the AFL++ output directory relative to the working
                directory. Defaults to ``"afl-output"``.
            role: Parallel-mode role. ``"main"`` maps to AFL's ``-M`` flag,
                ``"secondary"`` maps to ``-S``.
            name: Instance name used with ``-M`` / ``-S``. Auto-derived from
                ``role`` if not given (``"main01"`` / ``"sec01"``).
            suppress: Path to a UBSan suppressions file. Passed via
                ``UBSAN_OPTIONS=suppressions=<path>``.
            timeout: Per-execution timeout in seconds. Converted to milliseconds
                for AFL's ``-t`` flag.
            debug: If ``True``, sets ``AFL_DEBUG_CHILD=1`` to print child output.
        """
        input_dir, out_dir = self.prepare_corpus(output_dir=output_dir)

        # Generate grammar-based seeds before starting the fuzzer (skip if
        # seeds already exist to avoid races with parallel instances).
        if grammar:
            grammar_path = Path(grammar).resolve()
            if not grammar_path.exists():
                self.logger.error(f"Grammar file not found: {grammar_path}")
                return
            if not list(input_dir.glob("grammar_*.txt")):
                self.generate_grammar_seeds(grammar_path, input_dir)
            else:
                self.logger.info(f"Grammar seeds already exist in {input_dir}, skipping generation")

        if engine == "afl":
            self._start_afl(
                harness_path,
                input_dir,
                out_dir,
                mutator=mutator,
                resume=resume,
                role=role,
                name=name,
                suppress=suppress,
                timeout=timeout,
                debug=debug,
            )
        elif engine == "libfuzzer":
            self._start_libfuzzer(harness_path, input_dir)
        else:
            self.logger.error(f"Unknown fuzzing engine: {engine}")

    def _migrate_corpus_for_parallel(self, output_dir: Path, instance_name: str) -> bool:
        """Rename 'default/' to the instance name so a solo run can resume in parallel mode.

        Returns True if migration was performed or not needed, False if the user aborted.
        """
        from rich.console import Console

        console = Console()

        default_dir = output_dir / "default"
        target_dir = output_dir / instance_name

        if not default_dir.exists():
            return True

        if target_dir.exists():
            self.logger.warning(
                f"Both '{default_dir.name}/' and '{target_dir.name}/' exist in {output_dir}. "
                f"Will use '{target_dir.name}/' - the 'default/' corpus will be ignored."
            )
            return True

        # Count queue entries for context
        queue_dir = default_dir / "queue"
        queue_count = sum(1 for _ in queue_dir.iterdir()) if queue_dir.exists() else 0

        console.print()
        console.print(f"  [bold]Existing solo corpus found:[/bold] {default_dir}/")
        console.print(f"  [bold]Queue entries:[/bold] {queue_count}")
        console.print()
        console.print("  AFL++ parallel mode uses named instance directories instead of 'default/'.")
        console.print("  To preserve your corpus, the directory needs to be renamed:")
        console.print(f"    [cyan]{default_dir.name}/[/cyan]  ->  [cyan]{instance_name}/[/cyan]")
        console.print()
        console.print("  [green]\\[y][/green] Rename and continue (corpus is preserved under the new name)")
        console.print("  [red]\\[n][/red] Abort (no changes made, you can back up manually first)")

        answer = console.input("\n  Rename? [y/N] ").strip().lower()

        if answer != "y":
            self.logger.info("Aborted. No changes were made.")
            return False

        default_dir.rename(target_dir)
        self.logger.info(f"Renamed {default_dir.name}/ -> {instance_name}/")
        return True

    def _start_afl(
        self,
        harness: Path,
        input_dir: Path,
        output_dir: Path,
        mutator: Optional[list[str]] = None,
        resume: bool = False,
        role: Optional[str] = None,
        name: Optional[str] = None,
        suppress: Optional[str] = None,
        timeout: Optional[int] = None,
        debug: bool = False,
    ) -> None:
        # Resolve instance name for parallel mode
        if role and not name:
            name = "main01" if role == "main" else "sec01"

        mode_label = f" ({role}: {name})" if role else ""
        self.logger.info(f"Starting AFL++{mode_label}...")

        config_path = self.config_manager.get_httpd_config()

        env = os.environ.copy()
        if config_path:
            env["FUZZ_CONF"] = str(config_path)
            env["FUZZ_ROOT"] = str(self.work_dir)
        else:
            self.logger.info("No httpd config found - harness will run without Apache pipeline")
        env["AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES"] = "1"
        env["AFL_SKIP_CPUFREQ"] = "1"
        if debug:
            env["AFL_DEBUG_CHILD"] = "1"
        if resume:
            env["AFL_AUTORESUME"] = "1"

        # Make UBSan abort on errors so AFL registers them as crashes.
        ubsan_opts = ["halt_on_error=1"]

        # Apply UBSan suppression file if provided.
        if suppress:
            supp_path = Path(suppress).resolve()
            if not supp_path.exists():
                self.logger.error(f"Suppression file not found: {supp_path}")
                return
            self.logger.info(f"Using UBSan suppression file: {supp_path}")
            ubsan_opts.append(f"suppressions={supp_path}")

        existing = env.get("UBSAN_OPTIONS", "")
        combined = ":".join(ubsan_opts)
        env["UBSAN_OPTIONS"] = f"{existing}:{combined}" if existing else combined

        # When switching from solo to parallel, migrate the default/ corpus
        if role == "main" and resume and not self._migrate_corpus_for_parallel(output_dir, name):
            return

        # Custom mutator library (supports multiple, chained with ':')
        if mutator:
            resolved = []
            for m in mutator:
                p = Path(m).resolve()
                if not p.exists():
                    self.logger.error(f"Mutator library not found: {p}")
                    return
                resolved.append(str(p))
            env["AFL_CUSTOM_MUTATOR_LIBRARY"] = ":".join(resolved)
            # env["AFL_CUSTOM_MUTATOR_ONLY"] = "1"  # FIXME: i need to re-think about this hack
            self.logger.info(f"Using custom mutator(s): {', '.join(resolved)}")

        # Preload only dynamically loaded modules referenced by the config
        # so AFL++ instruments them.  Built-in modules are statically linked
        # and don't need preloading.
        if config_path:
            preload = self._resolve_preload_modules(config_path)
            if preload:
                env["AFL_PRELOAD"] = ":".join(preload)

        afl_fuzz = toolchain_config.resolve_tool("afl-fuzz") or "afl-fuzz"
        cmd = [afl_fuzz]

        # Per-execution timeout (converted to milliseconds for AFL's -t)
        if timeout is not None:
            timeout_ms = timeout * 1000
            cmd += ["-t", str(timeout_ms)]
            self.logger.info(f"Per-execution timeout: {timeout}s")

        # Parallel mode flags
        if role == "main":
            cmd += ["-M", name]
        elif role == "secondary":
            cmd += ["-S", name]

        # cmd += ["-x"]
        # cmd += ['-D'] # fuzzing strategy yields
        cmd += [
            "-i",
            str(input_dir),
            "-o",
            str(output_dir),
            "--",
            str(harness),
        ]

        try:
            # Run without capturing output to let AFL show its UI
            self.runner.run_command(cmd, env=env, check=True, capture_output=False)
        except Exception:
            self.logger.error("Failed to start AFL++. Is it installed?")

    def _start_libfuzzer(self, harness: Path, corpus_dir: Path) -> None:
        self.logger.info("Starting LibFuzzer...")
        cmd = [str(harness), str(corpus_dir)]
        self.runner.run_command(cmd)
