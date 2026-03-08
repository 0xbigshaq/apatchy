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
    """Walk a JSON grammar (keyed by non-terminal symbols) to produce concrete byte strings."""

    def __init__(self, grammar: Dict[str, List[List[str]]], max_depth: int = 12) -> None:
        self.grammar = grammar
        self.max_depth = max_depth

    def generate(self) -> bytes:
        """Generate one concrete string from the grammar starting at <A>."""
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
    """Prepare corpus, generate seeds, and launch AFL++ or LibFuzzer."""

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
        """Launch the fuzzing engine with the configured harness and corpus."""
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
