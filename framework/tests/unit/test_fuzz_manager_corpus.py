"""Tests for FuzzManager corpus preparation."""

from pathlib import Path
from unittest.mock import MagicMock

from apatchy.managers.fuzz_manager import FuzzManager
from apatchy.managers.config_manager import ConfigManager


def _make_fuzz_manager(work_dir):
    """Create a FuzzManager with work_dir overridden."""
    cm = ConfigManager()
    fm = FuzzManager(cm)
    fm.work_dir = work_dir
    return fm


def test_prepare_corpus_creates_dirs(tmp_path):
    fm = _make_fuzz_manager(tmp_path)
    input_path, output_path = fm.prepare_corpus(
        input_dir=str(tmp_path / "input"),
        output_dir=str(tmp_path / "output"),
    )
    # prepare_corpus uses self.work_dir / input_dir, but we passed absolute paths
    # as the dir names - let's check the actual paths it creates
    assert input_path.exists()
    assert output_path.exists()
    assert input_path.is_dir()
    assert output_path.is_dir()


def test_prepare_corpus_writes_default_seed(tmp_path):
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
    fm = _make_fuzz_manager(tmp_path)

    # Pre-create input dir with a file
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
    fm = _make_fuzz_manager(tmp_path)
    p1, _ = fm.prepare_corpus(input_dir="in", output_dir="out")
    p2, _ = fm.prepare_corpus(input_dir="in", output_dir="out")
    assert p1 == p2
    # Still only one seed
    assert len(list(p1.iterdir())) == 1


def test_generate_grammar_seeds(tmp_path):
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
    fm = _make_fuzz_manager(tmp_path)

    # Grammar with only one possible output
    grammar = {
        "<A>": [["only_one"]],
    }
    grammar_file = tmp_path / "single.json"
    import json
    grammar_file.write_text(json.dumps(grammar))

    input_dir = tmp_path / "seeds"
    input_dir.mkdir()

    written = fm.generate_grammar_seeds(grammar_file, input_dir, count=10)
    # Can only produce 1 unique seed
    assert written == 1


def test_generate_grammar_seeds_missing_start(tmp_path):
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
    fm = _make_fuzz_manager(tmp_path)

    grammar_file = tmp_path / "bad.json"
    grammar_file.write_text("not valid json {{{")

    input_dir = tmp_path / "seeds"
    input_dir.mkdir()

    written = fm.generate_grammar_seeds(grammar_file, input_dir)
    assert written == 0
