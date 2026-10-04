"""The run trace — the full ordered record of one scan.

This is the artifact CI uploads and the dashboard replays, so it is self-contained and
versioned. `Step` captures one node's work; `Trace` is the whole run plus its findings.
"""
import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class Step:
    """One node's turn in the loop."""
    node: str
    summary: str
    data: dict = field(default_factory=dict)
    at: str = field(default_factory=_now)


@dataclass
class Trace:
    run_id: str
    target: str
    started: str = field(default_factory=_now)
    steps: list = field(default_factory=list)       # list[Step]
    findings: list = field(default_factory=list)     # list[Finding]
    schema_version: int = 1

    def step(self, node: str, summary: str, **data) -> None:
        self.steps.append(Step(node=node, summary=summary, data=data))

    def to_dict(self) -> dict:
        return asdict(self)

    def save(self, path) -> None:
        from pathlib import Path
        Path(path).write_text(json.dumps(self.to_dict(), indent=2), encoding="utf-8")
