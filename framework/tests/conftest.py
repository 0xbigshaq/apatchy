
import pytest


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_protocol(item, nextitem):
    """Swap the nodeid to the docstring label for the duration of the test run.

    The swap happens after collection (so VSCode sees original nodeids)
    but before any terminal output for the test (so -v shows docstrings).
    The original nodeid is restored after the test finishes.
    """
    original = item._nodeid
    doc = getattr(item.function, "__doc__", None)
    if doc:
        label = doc.strip().split("\n")[0]
        params = ""
        if "[" in original:
            params = " " + original[original.rindex("["):]
        item._nodeid = original.split("::")[0] + " :: " + label + params
    yield
    item._nodeid = original


@pytest.fixture(scope="session")
def sample_grammar():
    """Minimal grammar dict for GrammarSeedGenerator tests."""
    return {
        "<A>": [["<greeting>", " ", "<target>"]],
        "<greeting>": [["hello"], ["hi"]],
        "<target>": [["world"], ["there"]],
    }


@pytest.fixture(scope="session")
def project_root():
    """Path to the framework/ root."""
    from pathlib import Path
    return Path(__file__).parent.parent
