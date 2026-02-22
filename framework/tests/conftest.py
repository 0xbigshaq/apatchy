import json

import pytest


def pytest_itemcollected(item):
    """Use the test's docstring as the display name in -v output."""
    doc = getattr(item.function, "__doc__", None)
    if doc:
        label = doc.strip().split("\n")[0]
        # Preserve parametrize suffix like [2.4.62]
        params = ""
        if "[" in item.nodeid:
            params = " " + item.nodeid[item.nodeid.rindex("["):]
        item._nodeid = item.nodeid.split("::")[0] + " :: " + label + params


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
