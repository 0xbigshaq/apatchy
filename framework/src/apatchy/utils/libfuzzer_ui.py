import re
import subprocess
import time
from collections import deque
from typing import Dict, List, Optional, Union

from rich.console import Console, Group
from rich.live import Live
from rich.markup import escape
from rich.panel import Panel
from rich.table import Table

from apatchy.utils.ui import _ANSI_RE, _EMPTY_BOX

_STATUS_RE = re.compile(
    r"#(\d+)\s+(\w+)\s+"
    r"cov:\s*(\d+)\s+"
    r"ft:\s*(\d+)\s+"
    r"corp:\s*(\d+)/(\S+)\s+"
    r"lim:\s*(\d+)\s+"
    r"exec/s:\s*(\d+)\s+"
    r"rss:\s*(\d+Mb)\s+"
    r"L:\s*(\S+)\s+"
    r"MS:\s*\d+\s+(.*)"
)


def _fmt_duration(seconds: float) -> str:
    s = int(seconds)
    days, s = divmod(s, 86400)
    hrs, s = divmod(s, 3600)
    mins, secs = divmod(s, 60)
    parts = []
    if days:
        parts.append(f"{days}d")
    if hrs or days:
        parts.append(f"{hrs}h")
    parts.append(f"{mins}m")
    parts.append(f"{secs}s")
    return " ".join(parts)


def _fmt_num(n: str) -> str:
    try:
        return f"{int(n):,}"
    except ValueError:
        return n


class LibFuzzerUI:
    MAX_WIDTH = 90

    def __init__(self, log_height: int = 8, max_width: int = MAX_WIDTH):
        self.console = Console()
        self.log_height = log_height
        self.max_width = max_width
        self.log_buffer: deque = deque(maxlen=log_height)
        self.start_time = 0.0
        self.last_new_time = 0.0
        self.last_crash_time = 0.0
        self.stats = {
            "run": "0",
            "event": "INIT",
            "cov": "0",
            "ft": "0",
            "corp_n": "0",
            "corp_size": "0b",
            "limit": "0",
            "exec_s": "0",
            "rss": "0Mb",
            "length": "0/0",
            "strategy": "-",
            "crashes": "0",
        }

    def run(self, command: Union[str, List[str]], env: Optional[Dict[str, str]] = None) -> int:
        self.start_time = time.monotonic()

        with Live(self._render(), refresh_per_second=8, console=self.console) as live, subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            env=env,
        ) as proc:
            for line in proc.stdout:
                clean = line.rstrip()
                if not clean:
                    continue
                stripped = _ANSI_RE.sub("", clean)
                self._parse_line(stripped)
                ts = time.strftime("%H:%M:%S")
                self.log_buffer.append(f"[dim]{ts}[/dim] {escape(stripped)}")
                live.update(self._render())
            returncode = proc.wait()

        elapsed = time.monotonic() - self.start_time
        mins, secs = divmod(int(elapsed), 60)
        time_str = f"{mins}m {secs}s" if mins else f"{secs}s"

        if returncode == 0:
            self.console.print(f"[green][+][/green] LibFuzzer finished [dim]({time_str})[/dim]")
        elif returncode == 77:
            self.console.print(f"[yellow][~][/yellow] LibFuzzer stopped [dim]({time_str})[/dim]")
        else:
            self.console.print(f"[red][!][/red] LibFuzzer exited [dim](code {returncode}, {time_str})[/dim]")

        return returncode

    def _parse_line(self, line: str) -> None:
        m = _STATUS_RE.match(line)
        if m:
            self.stats["run"] = m.group(1)
            self.stats["event"] = m.group(2)
            self.stats["cov"] = m.group(3)
            self.stats["ft"] = m.group(4)
            self.stats["corp_n"] = m.group(5)
            self.stats["corp_size"] = m.group(6)
            self.stats["limit"] = m.group(7)
            self.stats["exec_s"] = m.group(8)
            self.stats["rss"] = m.group(9)
            self.stats["length"] = m.group(10)
            self.stats["strategy"] = m.group(11).rstrip("-").strip()
            if self.stats["event"] == "NEW":
                self.last_new_time = time.monotonic()
            return

        if "Test unit written to" in line:
            self.last_crash_time = time.monotonic()
            try:
                self.stats["crashes"] = str(int(self.stats["crashes"]) + 1)
            except ValueError:
                self.stats["crashes"] = "1"

    def _render(self) -> Group:
        now = time.monotonic()
        s = self.stats
        event = s["event"]

        # Event color
        if event == "NEW":
            event_tag = f"[green]{event}[/green]"
        elif event == "REDUCE":
            event_tag = f"[yellow]{event}[/yellow]"
        else:
            event_tag = event

        # Crash count styling
        crashes = _fmt_num(s["crashes"])
        if int(s.get("crashes", "0") or "0") > 0:
            crashes = f"[bold red]{crashes}[/bold red]"
        else:
            crashes = f"[green]{crashes}[/green]"

        # Timing
        run_time = _fmt_duration(now - self.start_time)
        last_new = _fmt_duration(now - self.last_new_time) + " ago" if self.last_new_time > 0 else "n/a"
        last_crash = _fmt_duration(now - self.last_crash_time) + " ago" if self.last_crash_time > 0 else "none yet"

        # Stats table (two columns side by side)
        table = Table(
            show_header=False,
            box=None,
            padding=(0, 2),
            expand=True,
        )
        table.add_column("label_l", style="dim", width=16, justify="right")
        table.add_column("value_l", width=22)
        table.add_column("label_r", style="dim", width=14, justify="right")
        table.add_column("value_r", width=22)

        table.add_row("run time", run_time, "total execs", f"[bold]{_fmt_num(s['run'])}[/bold]")
        table.add_row("last new cov", last_new, "exec/sec", _fmt_num(s["exec_s"]))
        table.add_row("last crash", last_crash, "corpus", f"{_fmt_num(s['corp_n'])} ({s['corp_size']})")
        table.add_row(
            "edges", f"[green]{_fmt_num(s['cov'])}[/green]", "features", f"[green]{_fmt_num(s['ft'])}[/green]"
        )
        table.add_row("mutator", s["strategy"], "crashes", crashes)
        table.add_row("rss", s["rss"], "input limit", _fmt_num(s["limit"]))

        title = f"[bold cyan]apatchy libfuzzer[/bold cyan]  {event_tag}  [dim]{run_time}[/dim]"
        stats_panel = Panel(
            table, title=title, title_align="left", border_style="cyan", width=min(self.max_width, self.console.width)
        )

        # Log panel
        log_content = "\n".join(self.log_buffer) if self.log_buffer else "[dim]waiting for output...[/dim]"
        panel_width = min(self.max_width, self.console.width)
        log_panel = Panel(log_content, box=_EMPTY_BOX, height=self.log_height + 2, width=panel_width)

        return Group(stats_panel, log_panel)
