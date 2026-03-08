"""Logging helper that configures Rich-based console output.

All modules should obtain their logger via :func:`get_logger` to ensure
consistent formatting across the framework.
"""

import logging

from rich.logging import RichHandler


def get_logger(name: str) -> logging.Logger:
    """Return a :class:`logging.Logger` configured with :class:`~rich.logging.RichHandler`.

    Parameters
    ----------
    name : str
        Logger name, typically ``__name__`` of the calling module.
    """
    logging.basicConfig(
        level="INFO", format="%(message)s", datefmt="[%X]", handlers=[RichHandler(rich_tracebacks=False)]
    )
    return logging.getLogger(name)
