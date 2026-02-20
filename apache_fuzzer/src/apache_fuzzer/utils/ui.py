"""Rich-powered terminal output helpers.

The :class:`UI` class provides static convenience methods for printing
colour-coded messages (success, error, info, warning) without having to
import Rich directly in every module.
"""

from rich.console import Console
from rich.table import Table
from rich import print as rprint

console = Console()


class UI:
    """Static helpers for formatted terminal output using Rich markup."""
    @staticmethod
    def print_header(title: str) -> None:
        rprint(f"[bold blue]==== {title} ====[/bold blue]")

    @staticmethod
    def print_success(msg: str) -> None:
        rprint(f"[green][+] {msg}[/green]")

    @staticmethod
    def print_error(msg: str) -> None:
        rprint(f"[bold red][!] {msg}[/bold red]")

    @staticmethod
    def print_info(msg: str) -> None:
        rprint(f"[cyan][*] {msg}[/cyan]")

    @staticmethod
    def print_warning(msg: str) -> None:
        rprint(f"[yellow][~] {msg}[/yellow]")
