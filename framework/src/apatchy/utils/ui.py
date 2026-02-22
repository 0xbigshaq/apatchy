"""Rich-powered terminal output helpers.

The :class:`UI` class provides static convenience methods for printing
colour-coded messages (success, error, info, warning) without having to
import Rich directly in every module.

:func:`run_stream_panel` renders subprocess output in a scrolling Rich
panel (used by build commands when ``--verbose`` is not set).
"""

import re
import subprocess
import time
from collections import deque
from typing import Dict, List, Optional, Tuple, Union

from rich.box import Box
from rich.console import Console, Group
from rich.live import Live
from rich.markup import escape
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table
from rich import print as rprint

console = Console()

_ANSI_RE = re.compile(r'\x1b\[[0-9;]*[A-Za-z]')

# All-spaces box - Panel keeps its fixed height but draws no visible border.
_EMPTY_BOX = Box("    \n    \n    \n    \n    \n    \n    \n    \n")


def run_stream_panel(
    command: Union[str, List[str]],
    cwd: Optional[str] = None,
    env: Optional[Dict[str, str]] = None,
    label: str = "Building...",
    height: int = 10,
) -> Tuple[int, str]:
    """Run *command* while showing the last *height* output lines in a panel.

    Returns ``(returncode, full_output)`` so the caller can inspect or
    re-raise on failure.
    """
    log_buffer: deque = deque(maxlen=height)
    full_output: list = []
    start_time = time.monotonic()

    spinner = Progress(SpinnerColumn(), TextColumn("{task.description}"))
    task_id = spinner.add_task(f"[yellow]{label}")

    def _render():
        elapsed = time.monotonic() - start_time
        mins, secs = divmod(int(elapsed), 60)
        spinner.update(task_id, description=f"[yellow]{label} [dim]({mins}:{secs:02d})[/dim]")
        log_content = "\n".join(log_buffer) if log_buffer else "[dim]Waiting for output...[/dim]"
        return Group(spinner, Panel(log_content, box=_EMPTY_BOX, height=height + 2))

    with Live(_render(), refresh_per_second=12, console=console) as live:
        with subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            cwd=str(cwd) if cwd else None,
            env=env,
        ) as proc:
            for line in proc.stdout:
                clean = line.rstrip()
                full_output.append(clean)
                if clean:
                    stripped = _ANSI_RE.sub("", clean)
                    ts = time.strftime("%H:%M:%S")
                    log_buffer.append(f"[dim]{ts}[/dim] {escape(stripped)}")
                    live.update(_render())
            returncode = proc.wait()

    elapsed = time.monotonic() - start_time
    mins, secs = divmod(int(elapsed), 60)
    time_str = f"{mins}m {secs}s" if mins else f"{secs}s"

    if returncode == 0:
        rprint(f"[green][+][/green] {label} [dim]({time_str})[/dim]")
    else:
        rprint(f"[red][!][/red] {label} failed [dim](exit code {returncode})[/dim]")

    return returncode, "\n".join(full_output)


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
