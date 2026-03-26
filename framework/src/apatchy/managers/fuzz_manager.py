"""Thin factory that picks the right fuzzing engine and launches it."""

from pathlib import Path
from typing import Optional

from apatchy.fuzzers.base import BaseFuzzer
from apatchy.fuzzers.libfuzzer import LibFuzzer
from apatchy.managers.config_manager import ConfigManager
from apatchy.utils.logger import get_logger

logger = get_logger(__name__)

ENGINES = {
    "libfuzzer": LibFuzzer,
}


class FuzzManager:
    """Thin factory that selects and launches the appropriate fuzzing engine.

    ``FuzzManager`` is the main entry point for starting a fuzzing run. It
    delegates all engine-specific logic to
    :class:`~apatchy.fuzzers.libfuzzer.LibFuzzer`, which inherits shared
    corpus preparation and environment setup from
    :class:`~apatchy.fuzzers.base.BaseFuzzer`.

    The workflow is:

    1. Instantiate the engine class matching the ``engine`` argument.
    2. Call :meth:`~apatchy.fuzzers.base.BaseFuzzer.prepare_corpus` to create
       the seed and output directories (``fuzz-seeds/``, ``fuzz-output/``),
       write a default seed if the seed directory is empty, and optionally
       expand a JSON grammar into concrete seed files.
    3. Call :meth:`~apatchy.fuzzers.base.BaseFuzzer.start` on the engine
       instance, forwarding all engine-specific options.

    Args:
        config_manager: A :class:`~apatchy.managers.config_manager.ConfigManager`
            instance used to locate the httpd config file. The config path is
            passed to the harness via the ``FUZZ_CONF`` environment variable so
            Apache's configuration pipeline is active during fuzzing.

    CLI usage:

    .. code-block:: bash

        # Basic LibFuzzer run
        apatchy fuzz --engine libfuzzer

        # LibFuzzer with grammar seeds
        apatchy fuzz --engine libfuzzer --grammar grammars/http.json

        # Resume a previous session
        apatchy fuzz --engine libfuzzer --resume

        # Custom output directory
        apatchy fuzz --engine libfuzzer --output-dir my-output

    Example:
        .. code-block:: python

            from apatchy.managers.config_manager import ConfigManager
            from apatchy.managers.fuzz_manager import FuzzManager

            config = ConfigManager()
            fm = FuzzManager(config)

            fm.start_fuzzer(
                harness_path=Path("fuzz_harness_libfuzzer"),
                engine="libfuzzer",
            )
    """

    def __init__(self, config_manager: ConfigManager) -> None:
        self.config_manager = config_manager

    def start_fuzzer(  # noqa: D102
        self,
        harness_path: Path,
        engine: str = "libfuzzer",
        grammar: Optional[str] = None,
        seed_dir: Optional[str] = None,
        resume: bool = False,
        output_dir: str = BaseFuzzer.DEFAULT_OUTPUT_DIR,
        suppress: Optional[str] = None,
        lsan_supp: Optional[str] = None,
        timeout: Optional[int] = None,
        debug: bool = False,
        workers: int = 1,
        pulse_interval: int = 60,
        verbose: bool = False,
        **kwargs,
    ) -> None:
        engine_cls = ENGINES.get(engine)
        if not engine_cls:
            logger.error(f"Unknown fuzzing engine: {engine}")
            return

        fuzzer = engine_cls(self.config_manager)
        seed_path, out_dir = fuzzer.prepare_corpus(seed_dir=seed_dir, output_dir=output_dir, grammar=grammar)

        fuzzer.start(
            harness_path,
            seed_path,
            out_dir,
            resume=resume,
            suppress=suppress,
            lsan_supp=lsan_supp,
            timeout=timeout,
            debug=debug,
            workers=workers,
            pulse_interval=pulse_interval,
            verbose=verbose,
        )
