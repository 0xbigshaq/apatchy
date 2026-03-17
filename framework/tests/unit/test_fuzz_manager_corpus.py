"""Tests for BaseFuzzer corpus preparation."""

from apatchy.fuzzers.libfuzzer import LibFuzzer
from apatchy.fuzzers.grammar import generate_seeds
from apatchy.managers.config_manager import ConfigManager


def _make_fuzzer(work_dir):
    """Create a LibFuzzer with work_dir overridden."""
    cm = ConfigManager()
    fuzzer = LibFuzzer(cm)
    fuzzer.work_dir = work_dir
    return fuzzer


def test_prepare_corpus_creates_dirs(tmp_path):
    """prepare_corpus() creates input and output directories."""
    fuzzer = _make_fuzzer(tmp_path)
    seed_path, output_path = fuzzer.prepare_corpus(
        seed_dir=str(tmp_path / "input"),
        output_dir=str(tmp_path / "output"),
    )
    assert seed_path.exists()
    assert output_path.exists()
    assert seed_path.is_dir()
    assert output_path.is_dir()


def test_prepare_corpus_writes_default_seed(tmp_path):
    """prepare_corpus() writes a default HTTP seed file."""
    fuzzer = _make_fuzzer(tmp_path)
    seed_path, _ = fuzzer.prepare_corpus(
        seed_dir="corpus-in",
        output_dir="corpus-out",
    )
    seeds = list(seed_path.iterdir())
    assert len(seeds) == 1
    assert seeds[0].name == "seed1.txt"
    content = seeds[0].read_bytes()
    assert b"GET / HTTP/1.1" in content


def test_prepare_corpus_skips_seed_if_not_empty(tmp_path):
    """prepare_corpus() skips seed creation when input dir has files."""
    fuzzer = _make_fuzzer(tmp_path)

    seed_dir = tmp_path / "corpus-in"
    seed_dir.mkdir()
    (seed_dir / "existing_seed.txt").write_bytes(b"POST /foo")

    seed_path, _ = fuzzer.prepare_corpus(
        seed_dir="corpus-in",
        output_dir="corpus-out",
    )
    seeds = list(seed_path.iterdir())
    assert len(seeds) == 1
    assert seeds[0].name == "existing_seed.txt"


def test_prepare_corpus_idempotent(tmp_path):
    """Calling prepare_corpus() twice is a no-op."""
    fuzzer = _make_fuzzer(tmp_path)
    p1, _ = fuzzer.prepare_corpus(seed_dir="in", output_dir="out")
    p2, _ = fuzzer.prepare_corpus(seed_dir="in", output_dir="out")
    assert p1 == p2
    assert len(list(p1.iterdir())) == 1


def test_generate_grammar_seeds(tmp_path):
    """generate_seeds() writes grammar-based seed files."""
    grammar = {
        "<A>": [["GET"], ["POST"]],
    }
    grammar_file = tmp_path / "test.json"
    import json

    grammar_file.write_text(json.dumps(grammar))

    seed_dir = tmp_path / "seeds"
    seed_dir.mkdir()

    written = generate_seeds(grammar_file, seed_dir, count=5)
    assert written > 0
    assert written <= 5
    files = list(seed_dir.glob("grammar_*.txt"))
    assert len(files) == written


def test_generate_grammar_seeds_deduplicates(tmp_path):
    """generate_seeds() deduplicates identical outputs."""
    grammar = {
        "<A>": [["only_one"]],
    }
    grammar_file = tmp_path / "single.json"
    import json

    grammar_file.write_text(json.dumps(grammar))

    seed_dir = tmp_path / "seeds"
    seed_dir.mkdir()

    written = generate_seeds(grammar_file, seed_dir, count=10)
    assert written == 1


def test_generate_grammar_seeds_missing_start(tmp_path):
    """generate_seeds() returns 0 when grammar has no <A> symbol."""
    grammar = {
        "<B>": [["hello"]],
    }
    grammar_file = tmp_path / "nostartjson"
    import json

    grammar_file.write_text(json.dumps(grammar))

    seed_dir = tmp_path / "seeds"
    seed_dir.mkdir()

    written = generate_seeds(grammar_file, seed_dir)
    assert written == 0


def test_generate_grammar_seeds_bad_json(tmp_path):
    """generate_seeds() returns 0 for invalid JSON."""
    grammar_file = tmp_path / "bad.json"
    grammar_file.write_text("not valid json {{{")

    seed_dir = tmp_path / "seeds"
    seed_dir.mkdir()

    written = generate_seeds(grammar_file, seed_dir)
    assert written == 0
