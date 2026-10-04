"""The LangGraph state — one TypedDict threaded through the loop (D22).

`trace` and the `findings` list are accumulators the nodes mutate in place; the rest are
plain values each node reads and updates. `total=False` so nodes return partial updates.
"""
from typing import TypedDict

from agent.schemas.trace import Trace


class ScanState(TypedDict, total=False):
    principals: dict        # alias -> {"id":..., "token":...}  (the agent's two test sessions)
    inventory: dict         # recon output: {"templates": {resource: endpoint}, "owned": {alias: {resource: [ids]}}}
    candidates: list        # [{endpoint, resource, attacker, victim, object_id}]
    cursor: int             # which candidate we're on
    current_poc: dict       # {method, path, headers} for candidates[cursor]
    current_attempt: object # Attempt produced by execute, consumed by classify
    findings: list          # [Finding]
    trace: Trace
