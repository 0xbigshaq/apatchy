import os
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Dict, Optional

from apatchy.core.process_runner import ProcessRunner
from apatchy.fuzzers.grammar import generate_seeds
from apatchy.managers.config_manager import ConfigManager
from apatchy.utils.logger import get_logger

logger = get_logger(__name__)


class BaseFuzzer(ABC):
    """Base class for fuzzing engines."""

    DEFAULT_SEED_DIR = "fuzz-seeds"
    DEFAULT_OUTPUT_DIR = "fuzz-output"

    def __init__(self, config_manager: ConfigManager) -> None:
        self.config_manager = config_manager
        self.logger = logger
        self.runner = ProcessRunner()
        self.work_dir = Path(".").resolve()

    def prepare_corpus(
        self,
        seed_dir: Optional[str] = None,
        output_dir: Optional[str] = None,
        grammar: Optional[str] = None,
    ) -> tuple[Path, Path]:
        """Create seed/output directories, generate grammar seeds if needed.

        Returns (seed_path, output_path).
        """
        using_custom_seed_dir = seed_dir is not None
        seed_path = self.work_dir / (seed_dir or self.DEFAULT_SEED_DIR)
        output_path = self.work_dir / (output_dir or self.DEFAULT_OUTPUT_DIR)

        seed_path.mkdir(exist_ok=True)
        output_path.mkdir(exist_ok=True)

        if not using_custom_seed_dir and not any(seed_path.iterdir()):
            self.logger.info("Creating default seed...")
            (seed_path / "seed1.txt").write_bytes(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")

        if grammar:
            grammar_path = Path(grammar).resolve()
            if not grammar_path.exists():
                self.logger.error(f"Grammar file not found: {grammar_path}")
            elif not list(seed_path.glob("grammar_*.txt")):
                generate_seeds(grammar_path, seed_path)
            else:
                self.logger.info(f"Grammar seeds already exist in {seed_path}, skipping generation")

        return seed_path, output_path

    def _build_env(self, suppress: str = None) -> Dict[str, str]:
        """Build base environment with FUZZ_CONF and FUZZ_ROOT."""
        env = os.environ.copy()
        config_path = self.config_manager.get_httpd_config()
        if config_path:
            env["FUZZ_CONF"] = str(config_path)
            env["FUZZ_ROOT"] = str(self.work_dir)
        else:
            self.logger.info("No httpd config found - harness will run without Apache pipeline")

        ubsan_opts = "halt_on_error=1:print_stacktrace=1"
        if suppress:
            ubsan_opts += f":suppressions={suppress}"
        existing = env.get("UBSAN_OPTIONS", "")
        env["UBSAN_OPTIONS"] = f"{existing}:{ubsan_opts}" if existing else ubsan_opts

        return env

    @abstractmethod
    def start(self, harness: Path, seed_dir: Path, output_dir: Path, **kwargs) -> None:
        """Launch the fuzzing engine. Subclasses must implement this."""
        ...
