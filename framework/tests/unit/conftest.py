import pytest


def pytest_collection_modifyitems(items):
    """Auto-apply the 'unit' marker to every test in the unit/ directory."""
    for item in items:
        if "/unit/" in str(item.fspath):
            item.add_marker(pytest.mark.unit)
