"""End-to-end pipeline check WITHOUT Docker or the real LLM.

- The runner is replaced by the target's own Flask test client (exercises the real app logic
  in-process; the Docker sandbox is verified separately in runner/docker_runner.py).
- The LLM is replaced by a deterministic stand-in that enumerates candidates from the recon
  inventory and writes the obvious PoC — so the whole graph runs reproducibly and for free.

Asserts the loop produces at least one CONFIRMED and one FALSE_POSITIVE, and that every trap
endpoint is rejected.
"""
import json
import uuid

from agent.graph import build_graph
from agent.oracle.differential import load_manifest
from agent.schemas.finding import CONFIRMED, FALSE_POSITIVE
from agent.schemas.trace import Trace
from target.app import app

MANIFEST = load_manifest()
PRINCIPALS = {a: {"id": p["id"], "token": p["token"]} for a, p in MANIFEST["principals"].items()}


class InProcessRunner:
    """Routes PoCs at the real target in-process (no Docker)."""
    def __init__(self):
        self.c = app.test_client()

    def run_poc(self, poc):
        r = self.c.open(poc["path"], method=poc.get("method", "GET"),
                        headers=poc.get("headers", {}))
        return {"status": r.status_code, "body": r.get_data(as_text=True)}


class FakeLLM:
    """Deterministic stand-in for deepseek-flash: real reasoning shape, zero cost."""
    def chat(self, system, user, json_mode=False):
        try:
            data = json.loads(user)
        except json.JSONDecodeError:
            return "Enforce an ownership check: confirm the object's owner is the caller."
        if "templates" in data:  # candidate generation
            out = [{"endpoint": ep, "resource": res, "attacker": a, "victim": v, "object_id": oid}
                   for a in data["users"] for v in data["users"] if a != v
                   for res, ids in data["owned"][v].items() if (ep := data["templates"].get(res))
                   for oid in ids]
            return json.dumps({"candidates": out})
        # poc synthesis
        return json.dumps({"method": "GET", "path": data["path_template"].replace("{id}", data["object_id"]),
                           "headers": {"Authorization": "Bearer " + data["attacker_token"]}})


def _run():
    graph = build_graph(FakeLLM(), InProcessRunner(), MANIFEST)
    trace = Trace(run_id=uuid.uuid4().hex[:8], target="test-client")
    final = graph.invoke({"principals": PRINCIPALS, "findings": [], "cursor": 0, "trace": trace},
                         {"recursion_limit": 200})
    return final["findings"]


def test_loop_confirms_and_rejects():
    findings = _run()
    assert any(f.verdict == CONFIRMED for f in findings), "expected at least one confirmed IDOR"
    assert any(f.verdict == FALSE_POSITIVE for f in findings), "expected at least one rejection"


def test_no_trap_is_ever_confirmed():
    trap_eps = {f"{e['method']} {e['path']}" for e in MANIFEST["endpoints"] if e["label"] == "trap"}
    assert not [f for f in _run() if f.verdict == CONFIRMED and f.endpoint in trap_eps]


def test_confirmed_findings_get_remediation():
    for f in _run():
        if f.verdict == CONFIRMED:
            assert f.remediation, "confirmed finding should carry a remediation suggestion"
