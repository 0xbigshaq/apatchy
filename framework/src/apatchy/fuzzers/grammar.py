import json
import random
from pathlib import Path
from typing import Dict, List

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
    """

    def __init__(self, grammar: Dict[str, List[List[str]]], max_depth: int = 12) -> None:
        self.grammar = grammar
        self.max_depth = max_depth

    def generate(self) -> bytes:
        """Generate a mutated HTTP request by expanding from the ``<A>`` start symbol."""
        return self._expand("<A>", 0).encode("latin-1")

    def _expand(self, symbol: str, depth: int) -> str:
        if symbol not in self.grammar:
            return symbol
        if depth >= self.max_depth:
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
        for prod in productions:
            if all(t not in self.grammar for t in prod):
                return "".join(prod)
        shortest = min(productions, key=len)
        return "".join(shortest)


def generate_seeds(grammar_path: Path, seed_dir: Path, count: int = 50) -> int:
    """Read a JSON grammar file and generate seed inputs into seed_dir.

    Returns the number of seeds written.
    """
    try:
        grammar = json.loads(grammar_path.read_text())
    except (json.JSONDecodeError, OSError) as e:
        logger.error(f"Failed to parse grammar {grammar_path}: {e}")
        return 0

    if "<A>" not in grammar:
        logger.error("Grammar must have a <A> start symbol")
        return 0

    gen = GrammarSeedGenerator(grammar)
    written = 0
    seen = set()

    for _i in range(count * 3):
        if written >= count:
            break
        data = gen.generate()
        if data in seen:
            continue
        seen.add(data)
        seed_path = seed_dir / f"grammar_{written:04d}.txt"
        seed_path.write_bytes(data)
        written += 1

    logger.info(f"Generated {written} grammar-based seeds in {seed_dir}")
    return written
