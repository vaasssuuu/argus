"""argus scan — run the validation loop against the bundled target and emit a trace.

    uv run python -m cli.argus scan

Brings up the sandboxed target, runs recon → candidates → PoC → execute → oracle → remediate,
prints each verdict, and writes the full run trace to traces/.
"""
import argparse
import uuid
from dataclasses import asdict
from pathlib import Path

from agent.graph import build_graph
from agent.llm.client import LLM
from agent.oracle.differential import load_manifest
from agent.schemas.finding import CONFIRMED
from agent.schemas.trace import Trace
from runner.docker_runner import DockerRunner

ROOT = Path(__file__).resolve().parents[1]


def scan() -> Path:
    manifest = load_manifest()
    principals = {a: {"id": p["id"], "token": p["token"]} for a, p in manifest["principals"].items()}
    trace = Trace(run_id=uuid.uuid4().hex[:8], target="bundled: argus-target")

    with DockerRunner() as runner:
        graph = build_graph(LLM(), runner, manifest)
        final = graph.invoke(
            {"principals": principals, "findings": [], "cursor": 0, "trace": trace},
            {"recursion_limit": 100},
        )

    findings = final["findings"]
    trace.findings = [asdict(f) for f in findings]
    out = ROOT / "traces" / f"run-{trace.run_id}.json"
    trace.save(out)

    confirmed = sum(f.verdict == CONFIRMED for f in findings)
    print(f"\nArgus — {len(findings)} candidate(s) adjudicated: "
          f"{confirmed} confirmed, {len(findings) - confirmed} rejected\n")
    for f in findings:
        mark = "CONFIRMED" if f.verdict == CONFIRMED else "rejected "
        print(f"  [{mark}] {f.endpoint}  {f.attacker}->{f.victim}  — {f.reason}")
    print(f"\ntrace: {out}")
    return out


def main():
    ap = argparse.ArgumentParser(prog="argus")
    ap.add_argument("command", choices=["scan"], help="what to run")
    scan() if ap.parse_args().command == "scan" else None


if __name__ == "__main__":
    main()
