"""Tests for apatchy.managers.fuzz_manager.GrammarSeedGenerator."""

from apatchy.managers.fuzz_manager import GrammarSeedGenerator


def test_simple_terminal(sample_grammar):
    """Simple grammar expands to 'greeting target' pair."""
    gen = GrammarSeedGenerator(sample_grammar)
    result = gen.generate()
    assert isinstance(result, bytes)
    text = result.decode("latin-1")
    assert text.split()[0] in ("hello", "hi")
    assert text.split()[1] in ("world", "there")


def test_deterministic_with_seed(sample_grammar):
    """Same random seed produces same output."""
    import random
    random.seed(42)
    gen = GrammarSeedGenerator(sample_grammar)
    r1 = gen.generate()

    random.seed(42)
    gen2 = GrammarSeedGenerator(sample_grammar)
    r2 = gen2.generate()

    assert r1 == r2


def test_generates_bytes(sample_grammar):
    """generate() returns bytes, not str."""
    gen = GrammarSeedGenerator(sample_grammar)
    result = gen.generate()
    assert isinstance(result, bytes)


def test_deduplication(sample_grammar):
    """Multiple generations produce varied output (not all identical)."""
    gen = GrammarSeedGenerator(sample_grammar)
    results = {gen.generate() for _ in range(20)}
    assert len(results) > 1


def test_recursive_grammar_bounded():
    """Recursive grammar terminates via max_depth."""
    grammar = {
        "<A>": [["<A>", "x"], ["y"]],
    }
    gen = GrammarSeedGenerator(grammar, max_depth=5)
    result = gen.generate()
    assert isinstance(result, bytes)
    assert b"y" in result or b"x" in result


def test_max_depth_produces_terminal():
    """At max depth, the shortest production is chosen."""
    grammar = {
        "<A>": [["<B>", "<B>", "<B>"], ["done"]],
        "<B>": [["<A>"]],
    }
    gen = GrammarSeedGenerator(grammar, max_depth=2)
    result = gen.generate()
    assert isinstance(result, bytes)


def test_single_terminal_grammar():
    """Grammar with one terminal produces that terminal."""
    grammar = {
        "<A>": [["hello"]],
    }
    gen = GrammarSeedGenerator(grammar)
    assert gen.generate() == b"hello"


def test_multi_production_grammar():
    """Grammar with multiple productions covers all of them."""
    grammar = {
        "<A>": [["GET"], ["POST"], ["HEAD"]],
    }
    gen = GrammarSeedGenerator(grammar)
    results = {gen.generate() for _ in range(30)}
    assert results.issubset({b"GET", b"POST", b"HEAD"})
    assert len(results) > 1


def test_concatenation():
    """Multi-symbol production concatenates terminals."""
    grammar = {
        "<A>": [["a", "b", "c"]],
    }
    gen = GrammarSeedGenerator(grammar)
    assert gen.generate() == b"abc"


def test_empty_grammar_no_start():
    """Missing <A> start symbol is treated as a terminal."""
    grammar = {
        "<B>": [["hello"]],
    }
    gen = GrammarSeedGenerator(grammar)
    result = gen.generate()
    assert result == b"<A>"
