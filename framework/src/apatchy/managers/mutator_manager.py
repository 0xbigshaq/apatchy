import subprocess
from pathlib import Path
from typing import Dict, List, Optional

from apatchy.config import Config
from apatchy.core import toolchain_config
from apatchy.utils.logger import get_logger

logger = get_logger(__name__)


class MutatorManager:
    """Build and manage AFL++ grammar mutators and custom mutator libraries.

    ``MutatorManager`` handles two kinds of AFL++ mutator plugins:

    **Grammar mutators** use the
    `AFL++ grammar-mutator <https://github.com/AFLplusplus/grammar-mutator>`_
    project to generate structure-aware inputs from ANTLR-style grammars.
    The workflow is: clone the grammar-mutator repo (:meth:`setup`), then
    compile a ``.so`` for a specific grammar (:meth:`build_grammar`). The
    resulting ``libgrammarmutator-<name>.so`` can be passed to AFL++ via
    ``AFL_CUSTOM_MUTATOR_LIBRARY``.

    **Custom mutators** are simple C source files that implement the AFL++
    custom mutator API. They are compiled into ``.so`` files with
    :meth:`build_custom_mutator` and can be chained with grammar mutators.

    Both types of built ``.so`` files can be passed to the ``fuzz`` command
    via ``--mutator``.

    CLI usage:

    .. code-block:: bash

        # Grammar mutators: setup, build, list, status
        apatchy grammar setup
        apatchy grammar build http
        apatchy grammar list
        apatchy grammar status

        # Custom mutators: build, list
        apatchy mutator build
        apatchy mutator build my_mutator
        apatchy mutator list

        # Use a built mutator in a fuzzing run
        apatchy fuzz --mutator mutators/my_mutator.so

    Example:
        .. code-block:: python

            from apatchy.managers.mutator_manager import MutatorManager

            mm = MutatorManager()

            # Set up the grammar-mutator toolchain
            mm.setup()

            # Build a grammar mutator from grammars/http.json
            so_path = mm.build_grammar("http")

            # Build all custom mutators
            mm.build_custom_mutator()

            # Check what is available
            print(mm.status())
            print(mm.list_grammars())
            print(mm.list_custom_mutators())
    """

    GRAMMAR_MUTATOR_REPO = "https://github.com/AFLplusplus/grammar-mutator"
    ANTLR_JAR_URL = "https://www.antlr.org/download/antlr-4.8-complete.jar"

    def __init__(self) -> None:
        self.work_dir = Config.WORK_DIR
        # grammar-mutator cloned directly (GNUmakefile at root)
        self.grammar_mutator_dir = self.work_dir / "grammar_mutator"
        self.custom_mutators_out = Config.CUSTOM_MUTATORS_DIR

    def setup(self) -> None:
        """Clone grammar-mutator repo and download antlr4 jar."""
        self._check_deps(["git", "make", "g++"])

        if not self.grammar_mutator_dir.exists():
            logger.info("Cloning grammar-mutator repository...")
            subprocess.run(
                ["git", "clone", self.GRAMMAR_MUTATOR_REPO, str(self.grammar_mutator_dir)],
                check=True,
            )
        else:
            logger.info("Using existing grammar-mutator directory...")

        # Download antlr4 jar if missing
        antlr_jar = self.grammar_mutator_dir / "antlr-4.8-complete.jar"
        if not antlr_jar.exists():
            logger.info("Downloading antlr-4.8-complete.jar...")
            subprocess.run(
                ["wget", "-q", self.ANTLR_JAR_URL, "-O", str(antlr_jar)],
                check=True,
            )

        logger.info(f"Grammar mutator ready at {self.grammar_mutator_dir}")
        logger.info("Run 'apatchy grammar build <name>' to build a grammar .so")

    def build_grammar(self, grammar_name: str) -> Optional[Path]:
        """Build libgrammarmutator-<name>.so for the given grammar."""
        if not self.grammar_mutator_dir.exists() or not any(self.grammar_mutator_dir.iterdir()):
            logger.error("Grammar mutator not set up. Run 'apatchy grammar setup' first.")
            return None

        grammar_file = self._resolve_grammar_file(grammar_name)
        if grammar_file is None:
            logger.error(f"Grammar file not found for '{grammar_name}'.")
            return None

        logger.info(f"Building grammar mutator for '{grammar_name}' from {grammar_file}...")

        cmd = [
            "make",
            f"GRAMMAR_FILE={grammar_file}",
            f"GRAMMAR_FILENAME={grammar_name}",
        ]

        try:
            subprocess.run(cmd, cwd=self.grammar_mutator_dir, check=True)
        except subprocess.CalledProcessError:
            logger.error("Grammar mutator build failed.")
            return None

        # The .so may be at the root or nested (e.g. inside custom_mutators/grammar_mutator/)
        for so_path in self.grammar_mutator_dir.rglob(f"libgrammarmutator-{grammar_name}.so"):
            logger.info(f"Built: {so_path}")
            return so_path

        # Some versions output without the name suffix
        for so_path in self.grammar_mutator_dir.rglob("libgrammarmutator.so"):
            logger.info(f"Built: {so_path}")
            return so_path

        logger.error("Build completed but .so not found.")
        return None

    def status(self) -> Dict[str, object]:
        """Return a dict describing what's set up and what's been built."""
        src_ready = (
            self.grammar_mutator_dir.exists() and any(self.grammar_mutator_dir.iterdir())
            if self.grammar_mutator_dir.exists()
            else False
        )
        info: Dict[str, object] = {
            "setup": src_ready,
            "grammar_mutator_dir": str(self.grammar_mutator_dir),
            "built_grammars": [],
            "built_custom_mutators": [],
        }
        if src_ready:
            info["built_grammars"] = [
                p.stem.replace("libgrammarmutator-", "")
                for p in self.grammar_mutator_dir.rglob("libgrammarmutator-*.so")
            ]
        if self.custom_mutators_out.exists():
            info["built_custom_mutators"] = [p.stem for p in self.custom_mutators_out.glob("*.so")]
        return info

    def list_grammars(self) -> List[str]:
        """List available grammar JSON files (bundled + work-dir)."""
        found: Dict[str, Path] = {}
        # Bundled grammars
        for p in Config.GRAMMARS_DIR.glob("*.json"):
            found[p.stem] = p
        # Work-dir grammars (skip build artifacts)
        skip = {"compile_commands"}
        for p in self.work_dir.glob("*.json"):
            if p.stem not in skip:
                found[p.stem] = p
        return sorted(found.keys())

    def build_custom_mutator(self, name: Optional[str] = None) -> None:
        """Compile .c sources from bundled custom_mutators/ into .so files."""
        self.custom_mutators_out.mkdir(exist_ok=True)

        sources: List[Path] = []
        if name:
            src = Config.CUSTOM_MUTATORS_DIR / f"{name}.c"
            if not src.exists():
                logger.error(f"Custom mutator source not found: {src}")
                return
            sources.append(src)
        else:
            sources = list(Config.CUSTOM_MUTATORS_DIR.glob("*.c"))

        if not sources:
            logger.error("No custom mutator .c sources found.")
            return

        cc = toolchain_config.resolve_tool("clang") or toolchain_config.resolve_tool("gcc")
        if not cc:
            logger.error("No C compiler (clang/gcc) found in PATH.")
            return

        for src in sources:
            out = self.custom_mutators_out / f"{src.stem}.so"
            logger.info(f"Compiling {src.name} -> {out.name}")
            try:
                subprocess.run(
                    [cc, "-shared", "-fPIC", "-O3", "-o", str(out), str(src)],
                    check=True,
                )
                logger.info(f"Built: {out}")
            except subprocess.CalledProcessError:
                logger.error(f"Failed to compile {src.name}")

    def list_custom_mutators(self) -> List[Dict[str, str]]:
        """List available .c sources and whether a .so has been built."""
        results: List[Dict[str, str]] = []
        for src in sorted(Config.CUSTOM_MUTATORS_DIR.glob("*.c")):
            built_path = self.custom_mutators_out / f"{src.stem}.so"
            results.append(
                {
                    "name": src.stem,
                    "source": str(src),
                    "built": str(built_path) if built_path.exists() else "",
                }
            )
        return results

    def _resolve_grammar_file(self, name: str) -> Optional[Path]:
        """Resolve a grammar name or path to a .json file."""
        # Bundled grammars/<name>.json
        bundled = Config.GRAMMARS_DIR / f"{name}.json"
        if bundled.exists():
            return bundled.resolve()

        # User-supplied path
        path = Path(name)
        if path.exists():
            return path.resolve()

        return None

    @staticmethod
    def _check_deps(programs: List[str]) -> None:
        missing = [p for p in programs if not toolchain_config.resolve_tool(p)]
        if missing:
            logger.warning(f"Missing dependencies: {', '.join(missing)}")
            logger.warning("Grammar mutator build may fail without these.")
