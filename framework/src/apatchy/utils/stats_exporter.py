import json
import time
from pathlib import Path
from typing import Callable, List, Optional

from apatchy.fuzzers.types import FuzzerEvent, FuzzerPulse, FuzzerSession

STATS_FILENAME = "stat.json"


class StatsExporter:  # noqa: D101
    def __init__(
        self,
        output_dir: Path,
        workers: int,
        pulse_interval: int = 60,
        crash_counter: Optional[Callable[[], int]] = None,
    ):
        self.stat_path = output_dir / STATS_FILENAME
        self.pulse_interval = pulse_interval
        self.crash_counter = crash_counter
        self.last_pulse_time = 0.0
        self.session: FuzzerSession = {
            "start_time": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "workers": workers,
            "pulses": [],
            "events": [],
            "mutators": {},
        }

    def maybe_pulse(self, stats: dict) -> None:  # noqa: D102
        now = time.monotonic()
        if self.last_pulse_time and (now - self.last_pulse_time) < self.pulse_interval:
            return
        self.last_pulse_time = now
        self._capture_pulse(stats)
        self._flush()

    KNOWN_MUTATORS = {
        "EraseBytes",
        "InsertByte",
        "InsertRepeatedBytes",
        "ChangeByte",
        "ChangeBit",
        "ShuffleBytes",
        "ChangeASCIIInt",
        "ChangeBinInt",
        "CopyPart",
        "CrossOver",
        "ManualDict",
        "PersAutoDict",
        "CMP",
        "Custom",
        "CustomCrossOver",
    }

    def record_mutators(self, strategy: str) -> None:  # noqa: D102
        for name in strategy.split("-"):
            name = name.strip()
            if name in self.KNOWN_MUTATORS:
                self.session["mutators"][name] = self.session["mutators"].get(name, 0) + 1

    def record_event(self, event_type: str, value: str) -> None:  # noqa: D102
        if event_type == "last_func" and any(e["value"] == value for e in self.session["events"]):
            return
        event: FuzzerEvent = {
            "type": event_type,
            "time": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "value": value,
        }
        self.session["events"].append(event)

    def final_flush(self, stats: dict) -> None:  # noqa: D102
        self._capture_pulse(stats)
        self._flush()

    def _capture_pulse(self, stats: dict) -> None:
        worker_exec_s_raw = stats.get("worker_exec_s")
        effective_exec_s = int(stats.get("exec_s", 0))
        pulse: FuzzerPulse = {
            "time": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "edges": int(stats.get("cov", 0)),
            "features": int(stats.get("ft", 0)),
            "corpus": int(stats.get("corp_n", 0)),
            "corpus_size": stats.get("corp_size", "0b"),
            "total_execs": int(stats.get("run", 0)),
            "exec_s": effective_exec_s,
            "worker_exec_s": int(worker_exec_s_raw) if worker_exec_s_raw else None,
            "rss": stats.get("rss", "0Mb"),
            "crashes": self.crash_counter() if self.crash_counter else 0,
        }
        self.session["pulses"].append(pulse)

    def _flush(self) -> None:
        sessions = self._load_existing()
        if sessions and sessions[-1].get("start_time") == self.session["start_time"]:
            sessions[-1] = self.session
        else:
            sessions.append(self.session)
        self.stat_path.write_text(json.dumps(sessions, indent=2))

    def _load_existing(self) -> List[FuzzerSession]:
        if not self.stat_path.exists():
            return []
        try:
            data = json.loads(self.stat_path.read_text())
            if isinstance(data, list):
                return data
        except (json.JSONDecodeError, OSError):
            pass
        return []
