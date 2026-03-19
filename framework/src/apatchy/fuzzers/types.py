from typing import Dict, List, Optional, TypedDict


class FuzzerPulse(TypedDict):  # noqa: D101
    time: str
    edges: int
    features: int
    corpus: int
    corpus_size: str
    total_execs: int
    exec_s: int
    worker_exec_s: Optional[int]
    rss: str
    crashes: int


class FuzzerEvent(TypedDict):  # noqa: D101
    type: str
    time: str
    value: str


class FuzzerSession(TypedDict):  # noqa: D101
    start_time: str
    workers: int
    pulses: List[FuzzerPulse]
    events: List[FuzzerEvent]
    mutators: Dict[str, int]
