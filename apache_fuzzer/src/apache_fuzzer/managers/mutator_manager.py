import os
import shutil
import subprocess
from pathlib import Path
from typing import Dict, List, Optional

from apache_fuzzer.config import Config
from apache_fuzzer.utils.logger import get_logger

logger = get_logger(__name__)


class MutatorManager:
    """Manages AFL++ grammar mutators and simple custom mutators."""

    # The grammar-mutator repo is a submodule of AFL++ at:
    #   AFLplusplus/custom_mutators/grammar_mutator/grammar_mutator/
    # It contains GNUmakefile and takes GRAMMAR_FILE=<path> to build
    # a per-grammar libgrammarmutator-<name>.so.
    GRAMMAR_MUTATOR_REPO = "https://github.com/AFLplusplus/grammar-mutator"
    ANTLR_JAR_URL = "https://www.antlr.org/download/antlr-4.8-complete.jar"

    def __init__(self) -> None:
        self.work_dir = Config.WORK_DIR
        self.aflpp_dir = self.work_dir / "grammar_mutator"
        # The inner grammar_mutator submodule dir (where GNUmakefile lives)
        self.grammar_mutator_src = (
            self.aflpp_dir / "custom_mutators" / "grammar_mutator" / "grammar_mutator"
        )
        self.custom_mutators_out = self.work_dir / "custom_mutators"


    def setup(self) -> None:
        """Clone AFL++, init grammar_mutator submodule, download antlr4 jar."""
        self._check_deps(["git", "make", "g++"])

        # 1. Clone AFL++
        if not self.aflpp_dir.exists():
            logger.info("Cloning AFLplusplus repository...")
            subprocess.run(
                ["git", "clone", Config.AFLPP_REPO_URL, str(self.aflpp_dir)],
                check=True,
            )
        else:
            logger.info("Using existing AFLplusplus directory...")

        # 2. Init grammar_mutator submodule
        gm_wrapper = self.aflpp_dir / "custom_mutators" / "grammar_mutator"
        if not gm_wrapper.exists():
            logger.error("custom_mutators/grammar_mutator not found in AFL++ source.")
            return

        version_file = gm_wrapper / "GRAMMAR_VERSION"
        grammar_version = version_file.read_text().strip() if version_file.exists() else "main"

        if not any(self.grammar_mutator_src.iterdir()) if self.grammar_mutator_src.exists() else True:
            logger.info("Initializing grammar_mutator submodule...")
            # Try submodule init first
            result = subprocess.run(
                ["git", "submodule", "update", "--init",
                 "custom_mutators/grammar_mutator/grammar_mutator"],
                cwd=self.aflpp_dir, capture_output=True, text=True,
            )
            # If submodule init failed (e.g. shallow clone), clone directly
            if result.returncode != 0 or not any(self.grammar_mutator_src.iterdir()):
                logger.info(f"Cloning grammar-mutator repo (version {grammar_version})...")
                if self.grammar_mutator_src.exists():
                    shutil.rmtree(self.grammar_mutator_src)
                subprocess.run(
                    ["git", "clone", self.GRAMMAR_MUTATOR_REPO,
                     str(self.grammar_mutator_src)],
                    check=True,
                )
                subprocess.run(
                    ["git", "checkout", grammar_version],
                    cwd=self.grammar_mutator_src, check=True,
                )

        # 3. Download antlr4 jar if missing
        antlr_jar = self.grammar_mutator_src / "antlr-4.8-complete.jar"
        if not antlr_jar.exists():
            logger.info("Downloading antlr-4.8-complete.jar...")
            subprocess.run(
                ["wget", "-q", self.ANTLR_JAR_URL, "-O", str(antlr_jar)],
                check=True,
            )

        logger.info(f"Grammar mutator ready at {self.grammar_mutator_src}")
        logger.info("Run 'fuzzer grammar build <name>' to build a grammar .so")

    def build_grammar(self, grammar_name: str) -> Optional[Path]:
        """Build libgrammarmutator-<name>.so for the given grammar."""
        if not self.grammar_mutator_src.exists() or not any(self.grammar_mutator_src.iterdir()):
            logger.error("Grammar mutator not set up. Run 'fuzzer grammar setup' first.")
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
            subprocess.run(cmd, cwd=self.grammar_mutator_src, check=True)
        except subprocess.CalledProcessError:
            logger.error("Grammar mutator build failed.")
            return None

        so_path = self.grammar_mutator_src / f"libgrammarmutator-{grammar_name}.so"
        if so_path.exists():
            logger.info(f"Built: {so_path}")
            return so_path

        # Some versions output without the name suffix
        fallback = self.grammar_mutator_src / "libgrammarmutator.so"
        if fallback.exists():
            logger.info(f"Built: {fallback}")
            return fallback

        logger.error("Build completed but .so not found.")
        return None

    def status(self) -> Dict[str, object]:
        """Return a dict describing what's set up and what's been built."""
        src_ready = self.grammar_mutator_src.exists() and any(self.grammar_mutator_src.iterdir()) if self.grammar_mutator_src.exists() else False
        info: Dict[str, object] = {
            "setup": src_ready,
            "grammar_mutator_dir": str(self.grammar_mutator_src),
            "built_grammars": [],
            "built_custom_mutators": [],
        }
        if src_ready:
            info["built_grammars"] = [
                p.stem.replace("libgrammarmutator-", "")
                for p in self.grammar_mutator_src.glob("libgrammarmutator-*.so")
            ]
        if self.custom_mutators_out.exists():
            info["built_custom_mutators"] = [
                p.stem for p in self.custom_mutators_out.glob("*.so")
            ]
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

        cc = shutil.which("clang") or shutil.which("gcc")
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
            results.append({
                "name": src.stem,
                "source": str(src),
                "built": str(built_path) if built_path.exists() else "",
            })
        return results


    def _resolve_grammar_file(self, name: str) -> Optional[Path]:
        """Resolve a grammar name to a .json file path."""
        # 1. Bundled grammars/<name>.json
        bundled = Config.GRAMMARS_DIR / f"{name}.json"
        if bundled.exists():
            return bundled.resolve()

        # Literal path
        literal = Path(name)
        if literal.exists():
            return literal.resolve()

        # 3. WORK_DIR/<name>.json
        work = self.work_dir / f"{name}.json"
        if work.exists():
            return work.resolve()

        return None

    @staticmethod
    def _check_deps(programs: List[str]) -> None:
        missing = [p for p in programs if not shutil.which(p)]
        if missing:
            logger.warning(f"Missing dependencies: {', '.join(missing)}")
            logger.warning("Grammar mutator build may fail without these.")
