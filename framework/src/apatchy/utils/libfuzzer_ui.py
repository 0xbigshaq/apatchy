import re
import subprocess
import time
from collections import deque
from pathlib import Path
from typing import Dict, List, Optional, Union

import psutil
from rich.console import Console, Group
from rich.live import Live
from rich.markup import escape
from rich.panel import Panel
from rich.table import Table

from apatchy.utils.stats_exporter import StatsExporter
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

_FORK_RE = re.compile(
    r"#(\d+):\s+"
    r"cov:\s*(\d+)\s+"
    r"ft:\s*(\d+)\s+"
    r"corp:\s*(\d+)\s+"
    r"exec/s:\s*(\d+)\s+"
    r"oom/timeout/crash:\s*(\d+)/(\d+)/(\d+)\s+"
    r"time:\s*(\d+)s\s+"
    r"job:\s*(\d+)"
)

_NEW_FUNC_RE = re.compile(r"NEW_FUNC.*? in (\S+)\s+(\S+)")


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


def _get_descendant_procs(pid: int) -> List[psutil.Process]:
    try:
        parent = psutil.Process(pid)
        return parent.children(recursive=True)
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return []


def _proc_rss_mb(pid: int) -> int:
    total = 0
    for p in _get_descendant_procs(pid):
        try:
            total += p.memory_info().rss
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return total // (1024 * 1024)


_SYNC_BEGIN = "\033[?2026h"
_SYNC_END = "\033[?2026l"


class SyncConsole(Console):  # noqa: D101
    def _write_buffer(self) -> None:
        if self.file and hasattr(self.file, "isatty") and self.file.isatty():
            self.file.write(_SYNC_BEGIN)
            super()._write_buffer()
            self.file.write(_SYNC_END)
            self.file.flush()
        else:
            super()._write_buffer()


class LibFuzzerUI:  # noqa: D101
    MAX_WIDTH = 90

    def __init__(
        self,
        log_height: int = 8,
        max_width: int = MAX_WIDTH,
        crashes_dir: Optional[Path] = None,
        output_dir: Optional[Path] = None,
        workers: int = 1,
        pulse_interval: int = 60,
    ):
        self.console = SyncConsole()
        self.log_height = log_height
        self.max_width = max_width
        self.crashes_dir = crashes_dir
        self.log_buffer: deque = deque(maxlen=log_height)
        self.start_time = 0.0
        self.last_new_time = 0.0
        self.last_crash_time = 0.0
        self._proc_pid: Optional[int] = None
        self._last_proc_poll = 0.0
        self._sys_cpu_pcts: List[int] = []
        self.stats: Dict[str, Optional[str]] = {
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
        }
        self.exporter: Optional[StatsExporter] = None
        if output_dir:
            self.exporter = StatsExporter(
                output_dir=output_dir,
                workers=workers,
                pulse_interval=pulse_interval,
                crash_counter=self._count_crashes,
            )

    def run(self, command: Union[str, List[str]], env: Optional[Dict[str, str]] = None) -> int:  # noqa: D102
        self.start_time = time.monotonic()
        returncode = 0

        with Live(self._render(), refresh_per_second=8, console=self.console) as live:
            live.get_renderable = self._render
            while True:
                with subprocess.Popen(
                    command,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    env=env,
                ) as proc:
                    self._proc_pid = proc.pid
                    for line in proc.stdout:
                        clean = line.rstrip()
                        if not clean:
                            continue
                        stripped = _ANSI_RE.sub("", clean)
                        self._parse_line(stripped)
                        if self.exporter:
                            self.exporter.maybe_pulse(self.stats)
                        ts = time.strftime("%H:%M:%S")
                        self.log_buffer.append(f"[dim]{ts}[/dim] {escape(stripped)}")
                    returncode = proc.wait()

                # code 1 = crash found; restart to keep fuzzing the corpus
                if returncode == 1:
                    ts = time.strftime("%H:%M:%S")
                    self.log_buffer.append(f"[dim]{ts}[/dim] [yellow][~] crash saved, restarting...[/yellow]")
                    continue

                break

        if self.exporter:
            self.exporter.final_flush(self.stats)

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
                if self.exporter and self.stats["strategy"]:
                    self.exporter.record_mutators(self.stats["strategy"])
            self._poll_system_stats()
            return

        fm = _FORK_RE.match(line)
        if fm:
            self.stats["run"] = fm.group(1)
            self.stats["event"] = f"job {fm.group(10)}"
            self.stats["cov"] = fm.group(2)
            self.stats["ft"] = fm.group(3)
            self.stats["corp_n"] = fm.group(4)
            elapsed = time.monotonic() - self.start_time
            self.stats["exec_s"] = str(int(int(fm.group(1)) / elapsed)) if elapsed > 0 else fm.group(5)
            self.stats["worker_exec_s"] = fm.group(5)
            ooms, timeouts, crashes = fm.group(6), fm.group(7), fm.group(8)
            self.stats["strategy"] = f"oom:{ooms} tout:{timeouts} crash:{crashes}"
            self._poll_system_stats(poll_rss=True)
            old_cov = getattr(self, "_last_cov", 0)
            new_cov = int(fm.group(2))
            if new_cov > old_cov:
                self.last_new_time = time.monotonic()
            self._last_cov = new_cov
            return

        nf = _NEW_FUNC_RE.search(line)
        if nf:
            func_name = nf.group(1)
            raw_path = nf.group(2)
            parts = raw_path.split("/")
            for i, part in enumerate(parts):
                if part.startswith("httpd-"):
                    raw_path = "/".join(parts[i + 1 :])
                    break
            self.stats["last_func"] = f"{func_name}  ({raw_path})"
            if self.exporter:
                self.exporter.record_event("last_func", self.stats["last_func"])
            return

        if "Test unit written to" in line:
            self.last_crash_time = time.monotonic()
            crash_path = line.split("Test unit written to")[-1].strip().rstrip(";").strip()
            crash_name = Path(crash_path).name if crash_path else "unknown"
            if self.exporter:
                self.exporter.record_event("crash", crash_name)

    def _poll_system_stats(self, poll_rss: bool = False) -> None:
        now = time.monotonic()
        if now - self._last_proc_poll < 2.0:
            return
        self._last_proc_poll = now
        if poll_rss and self._proc_pid:
            rss_mb = _proc_rss_mb(self._proc_pid)
            if rss_mb > 0:
                self.stats["rss"] = f"{rss_mb}Mb"
        self._sys_cpu_pcts = [int(p) for p in psutil.cpu_percent(percpu=True)]

    def _count_crashes(self) -> int:
        if self.crashes_dir and self.crashes_dir.exists():
            return sum(1 for f in self.crashes_dir.iterdir() if f.is_file())
        return 0

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

        # Crash count from disk (deduplicates by hash automatically)
        n_crashes = self._count_crashes()
        crashes = _fmt_num(str(n_crashes))
        crashes = f"[bold red]{crashes}[/bold red]" if n_crashes > 0 else f"[green]{crashes}[/green]"

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
        worker_exec_s = s.get("worker_exec_s")
        if worker_exec_s:
            exec_label = "exec/s (all)"
            exec_val = _fmt_num(s["exec_s"])
        else:
            exec_label = "exec/sec"
            exec_val = _fmt_num(s["exec_s"])

        table.add_row("last new cov", last_new, exec_label, exec_val)
        table.add_row("last crash", last_crash, "corpus", f"{_fmt_num(s['corp_n'])} ({s['corp_size']})")
        table.add_row(
            "edges", f"[green]{_fmt_num(s['cov'])}[/green]", "features", f"[green]{_fmt_num(s['ft'])}[/green]"
        )
        table.add_row("mutator", s["strategy"], "crashes", crashes)
        if worker_exec_s:
            table.add_row("rss", s["rss"], "exec/s (worker)", _fmt_num(worker_exec_s))
        else:
            table.add_row("rss", s["rss"], "input limit", _fmt_num(s["limit"]))

        extras = []
        if self._sys_cpu_pcts:
            bar = ""
            for pct in self._sys_cpu_pcts:
                if pct >= 70:
                    bar += "[red]|[/red]"
                elif pct >= 30:
                    bar += "[yellow]|[/yellow]"
                else:
                    bar += "[green].[/green]"
            avg = sum(self._sys_cpu_pcts) // len(self._sys_cpu_pcts)
            extras.append(f"  [dim]cpu[/dim]  {bar}  [dim]avg[/dim] {avg}%")

        last_func = s.get("last_func")
        if last_func:
            extras.append(f"  [dim]last func[/dim]  [cyan]{last_func}[/cyan]")

        panel_body = Group(table, *extras) if extras else table

        title = f"[bold cyan]apatchy libfuzzer[/bold cyan]  {event_tag}  [dim]{run_time}[/dim]"
        stats_panel = Panel(
            panel_body,
            title=title,
            title_align="left",
            border_style="cyan",
            width=min(self.max_width, self.console.width),
        )

        # Log panel
        log_content = "\n".join(self.log_buffer) if self.log_buffer else ""
        log_panel = Panel(log_content, box=_EMPTY_BOX, height=self.log_height + 2)

        return Group(stats_panel, log_panel)
