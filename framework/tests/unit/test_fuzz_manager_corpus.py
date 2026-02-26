"""Tests for FuzzManager corpus preparation."""


from apatchy.managers.config_manager import ConfigManager
from apatchy.managers.fuzz_manager import FuzzManager


def _make_fuzz_manager(work_dir):
    """Create a FuzzManager with work_dir overridden."""
    cm = ConfigManager()
    fm = FuzzManager(cm)
    fm.work_dir = work_dir
    return fm


def test_prepare_corpus_creates_dirs(tmp_path):
    """prepare_corpus() creates input and output directories."""
    fm = _make_fuzz_manager(tmp_path)
    input_path, output_path = fm.prepare_corpus(
        input_dir=str(tmp_path / "input"),
        output_dir=str(tmp_path / "output"),
    )
    assert input_path.exists()
    assert output_path.exists()
    assert input_path.is_dir()
    assert output_path.is_dir()


def test_prepare_corpus_writes_default_seed(tmp_path):
    """prepare_corpus() writes a default HTTP seed file."""
    fm = _make_fuzz_manager(tmp_path)
    input_path, _ = fm.prepare_corpus(
        input_dir="corpus-in",
        output_dir="corpus-out",
    )
    seeds = list(input_path.iterdir())
    assert len(seeds) == 1
    assert seeds[0].name == "seed1.txt"
    content = seeds[0].read_bytes()
    assert b"GET / HTTP/1.1" in content


def test_prepare_corpus_skips_seed_if_not_empty(tmp_path):
    """prepare_corpus() skips seed creation when input dir has files."""
    fm = _make_fuzz_manager(tmp_path)

    input_dir = tmp_path / "corpus-in"
    input_dir.mkdir()
    (input_dir / "existing_seed.txt").write_bytes(b"POST /foo")

    input_path, _ = fm.prepare_corpus(
        input_dir="corpus-in",
        output_dir="corpus-out",
    )
    seeds = list(input_path.iterdir())
    assert len(seeds) == 1
    assert seeds[0].name == "existing_seed.txt"


def test_prepare_corpus_idempotent(tmp_path):
    """Calling prepare_corpus() twice is a no-op."""
    fm = _make_fuzz_manager(tmp_path)
    p1, _ = fm.prepare_corpus(input_dir="in", output_dir="out")
    p2, _ = fm.prepare_corpus(input_dir="in", output_dir="out")
    assert p1 == p2
    assert len(list(p1.iterdir())) == 1


def test_generate_grammar_seeds(tmp_path):
    """generate_grammar_seeds() writes grammar-based seed files."""
    fm = _make_fuzz_manager(tmp_path)

    grammar = {
        "<A>": [["GET"], ["POST"]],
    }
    grammar_file = tmp_path / "test.json"
    import json
    grammar_file.write_text(json.dumps(grammar))

    input_dir = tmp_path / "seeds"
    input_dir.mkdir()

    written = fm.generate_grammar_seeds(grammar_file, input_dir, count=5)
    assert written > 0
    assert written <= 5
    files = list(input_dir.glob("grammar_*.txt"))
    assert len(files) == written


def test_generate_grammar_seeds_deduplicates(tmp_path):
    """generate_grammar_seeds() deduplicates identical outputs."""
    fm = _make_fuzz_manager(tmp_path)

    grammar = {
        "<A>": [["only_one"]],
    }
    grammar_file = tmp_path / "single.json"
    import json
    grammar_file.write_text(json.dumps(grammar))

    input_dir = tmp_path / "seeds"
    input_dir.mkdir()

    written = fm.generate_grammar_seeds(grammar_file, input_dir, count=10)
    assert written == 1


def test_generate_grammar_seeds_missing_start(tmp_path):
    """generate_grammar_seeds() returns 0 when grammar has no <A> symbol."""
    fm = _make_fuzz_manager(tmp_path)

    grammar = {
        "<B>": [["hello"]],
    }
    grammar_file = tmp_path / "nostartjson"
    import json
    grammar_file.write_text(json.dumps(grammar))

    input_dir = tmp_path / "seeds"
    input_dir.mkdir()

    written = fm.generate_grammar_seeds(grammar_file, input_dir)
    assert written == 0


def test_generate_grammar_seeds_bad_json(tmp_path):
    """generate_grammar_seeds() returns 0 for invalid JSON."""
    fm = _make_fuzz_manager(tmp_path)

    grammar_file = tmp_path / "bad.json"
    grammar_file.write_text("not valid json {{{")

    input_dir = tmp_path / "seeds"
    input_dir.mkdir()

    written = fm.generate_grammar_seeds(grammar_file, input_dir)
    assert written == 0
