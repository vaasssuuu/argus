"""Data contracts for one attack attempt and its verdict.

`Attempt` is what the execute node produces (what was tried, and what came back).
`Finding` is what the oracle produces (the verdict, with the evidence that justifies it).
Both are plain dataclasses — `dataclasses.asdict` turns them into JSON for the trace/dashboard.
"""
from dataclasses import dataclass, field

CONFIRMED = "confirmed"
FALSE_POSITIVE = "false_positive"


@dataclass
class Attempt:
    """One cross-principal access the agent executed against the target."""
    endpoint: str      # template, e.g. "GET /api/invoices/{id}"
    resource: str      # manifest resource key, e.g. "invoices"
    attacker: str      # principal alias who sent the request, e.g. "alice"
    victim: str        # principal alias who owns the target object, e.g. "bob"
    object_id: str     # the id that was swapped in, e.g. "inv_2001"
    request: dict      # {method, url, headers} — token redacted
    status: int        # HTTP status returned
    body_text: str     # response body as text (what the oracle inspects)


@dataclass
class Finding:
    """The oracle's verdict on one Attempt, with the evidence that produced it."""
    id: str
    endpoint: str
    attacker: str
    victim: str
    verdict: str                       # CONFIRMED | FALSE_POSITIVE
    checks: list = field(default_factory=list)   # names of checks that fired
    reason: str = ""                   # one-line human explanation
    request: dict = field(default_factory=dict)
    response: dict = field(default_factory=dict)  # {status, body_excerpt}
    remediation: str | None = None     # set only for confirmed findings
    schema_version: int = 1
