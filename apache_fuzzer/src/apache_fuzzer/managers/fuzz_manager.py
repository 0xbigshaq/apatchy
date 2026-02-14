import json
import random
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from apache_fuzzer.utils.logger import get_logger
from apache_fuzzer.core.process_runner import ProcessRunner
from apache_fuzzer.managers.config_manager import ConfigManager
import os

logger = get_logger(__name__)


class GrammarSeedGenerator:
    """Walks a JSON grammar to produce concrete byte strings."""

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
    def __init__(self, config_manager: ConfigManager) -> None:
        self.config_manager = config_manager
        self.logger = logger
        self.runner = ProcessRunner()
        self.work_dir = Path(".").resolve()

    def prepare_corpus(self, input_dir: str = "afl-input", output_dir: str = "afl-output") -> Tuple[Path, Path]:
        input_path = self.work_dir / input_dir
        output_path = self.work_dir / output_dir

        input_path.mkdir(exist_ok=True)
        output_path.mkdir(exist_ok=True)

        # Create seed if empty
        if not any(input_path.iterdir()):
             self.logger.info("Creating seed input...")
             (input_path / "seed1.txt").write_bytes(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")

        return input_path, output_path

    def generate_grammar_seeds(self, grammar_path: Path, input_dir: Path,
                                count: int = 50) -> int:
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

        for i in range(count * 3):  # over-generate to deduplicate
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

    def start_fuzzer(self, harness_path: Path, engine: str = "afl",
                     mutator: Optional[str] = None, grammar: Optional[str] = None,
                     resume: bool = False, output_dir: str = "afl-output") -> None:
        input_dir, out_dir = self.prepare_corpus(output_dir=output_dir)

        # Generate grammar-based seeds before starting the fuzzer
        if grammar:
            grammar_path = Path(grammar).resolve()
            if not grammar_path.exists():
                self.logger.error(f"Grammar file not found: {grammar_path}")
                return
            self.generate_grammar_seeds(grammar_path, input_dir)

        if engine == "afl":
            self._start_afl(harness_path, input_dir, out_dir, mutator=mutator,
                            resume=resume)
        elif engine == "libfuzzer":
            self._start_libfuzzer(harness_path, input_dir)
        else:
            self.logger.error(f"Unknown fuzzing engine: {engine}")

    def _start_afl(self, harness: Path, input_dir: Path, output_dir: Path,
                   mutator: Optional[str] = None,
                   resume: bool = False) -> None:
        self.logger.info("Starting AFL++...")

        config_path = self.config_manager.get_httpd_config()
        if not config_path:
            self.logger.error("Cannot start fuzzer: httpd config not found")
            return

        env = os.environ.copy()
        env["FUZZ_CONF"] = str(config_path)
        env["FUZZ_ROOT"] = str(self.work_dir)
        env["AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES"] = "1"
        env["AFL_SKIP_CPUFREQ"] = "1"
        if resume:
            env["AFL_AUTORESUME"] = "1"

        # Custom mutator library
        if mutator:
            mutator_path = Path(mutator).resolve()
            if not mutator_path.exists():
                self.logger.error(f"Mutator library not found: {mutator_path}")
                return
            env["AFL_CUSTOM_MUTATOR_LIBRARY"] = str(mutator_path)
            self.logger.info(f"Using custom mutator: {mutator_path}")

        # Set LD_LIBRARY_PATH for APR/APR-Util shared libraries
        httpd_dirs = [d for d in self.work_dir.glob("httpd-*") if not d.name.endswith(("-cov", "-standalone"))]
        if httpd_dirs:
            srclib = httpd_dirs[0] / "srclib"
            crypto_libs = srclib / "apr-util" / "crypto" / ".libs"
            lib_paths = [
                str(srclib / "apr" / ".libs"),
                str(srclib / "apr-util" / ".libs"),
                str(crypto_libs),
            ]
            existing = env.get("LD_LIBRARY_PATH", "")
            env["LD_LIBRARY_PATH"] = ":".join(lib_paths + ([existing] if existing else []))

            # Preload the APR crypto DSO so AFL++ sees its instrumentation
            # before the forkserver starts (avoids "instrumented dlopen()" error).
            crypto_so = crypto_libs / "apr_crypto_openssl-1.so"
            if crypto_so.exists():
                env["AFL_PRELOAD"] = str(crypto_so)
        cmd = [
            "afl-fuzz",
            "-i", str(input_dir),
            "-o", str(output_dir),
            "--",
            str(harness)
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
