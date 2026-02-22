import json

import pytest


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
