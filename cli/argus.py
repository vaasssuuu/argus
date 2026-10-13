"""argus — autonomous IDOR / broken-access-control validation.

    argus eval                          # precision/recall benchmark (no Docker, no API key)
    argus eval --json                   # same, as machine-readable JSON on stdout
    argus scan                          # run the loop in the sandbox, emit a trace
    argus scan --provider gemini        # pick the LLM provider (deepseek|openai|gemini)
    argus scan --model gemini-2.0-flash # override the model
    argus scan --json                   # print the findings as JSON (for piping / CI)

`scan` brings up the sandboxed target and runs recon -> candidates -> PoC -> execute -> oracle
-> remediate, printing each verdict and writing the full trace to traces/.
"""
import argparse
import json
import sys
import uuid
from dataclasses import asdict
from pathlib import Path

from agent.schemas.finding import CONFIRMED
from agent.schemas.trace import Trace

ROOT = Path(__file__).resolve().parents[1]


def scan(provider=None, model=None, as_json=False) -> Path:
    # Imported lazily so `argus eval` needs neither Docker nor the LLM deps at import time.
    from agent.graph import build_graph
    from agent.llm.client import LLM
    from agent.oracle.differential import load_manifest
    from runner.docker_runner import DockerRunner

    manifest = load_manifest()
    principals = {a: {"id": p["id"], "token": p["token"]} for a, p in manifest["principals"].items()}
    trace = Trace(run_id=uuid.uuid4().hex[:8], target="bundled: argus-target")
    llm = LLM(provider=provider, model=model)

    with DockerRunner() as runner:
        graph = build_graph(llm, runner, manifest)
        final = graph.invoke(
            {"principals": principals, "findings": [], "cursor": 0, "trace": trace},
            {"recursion_limit": 100},
        )

    findings = final["findings"]
    trace.findings = [asdict(f) for f in findings]
    out = ROOT / "traces" / f"run-{trace.run_id}.json"
    trace.save(out)

    confirmed = sum(f.verdict == CONFIRMED for f in findings)
    if as_json:
        print(_as_json(trace.run_id, trace.target, trace.findings, confirmed, out,
                       provider=llm.provider, model=llm.model))
    else:
        print(f"\nArgus [{llm.provider}:{llm.model}] - {len(findings)} adjudicated: "
              f"{confirmed} confirmed, {len(findings) - confirmed} rejected\n")
        for f in findings:
            mark = "CONFIRMED" if f.verdict == CONFIRMED else "rejected "
            print(f"  [{mark}] {f.endpoint}  {f.attacker}->{f.victim}  {f.reason}")
        print(f"\ntrace: {out}")
    return out


def _as_json(run_id, target, findings, confirmed, trace_path, **extra) -> str:
    """Machine-readable scan result: run metadata, a summary, and the serialized findings."""
    return json.dumps({
        "run_id": run_id,
        "target": target,
        **extra,
        "summary": {"adjudicated": len(findings), "confirmed": confirmed,
                    "rejected": len(findings) - confirmed},
        "findings": findings,
        "trace": str(trace_path),
    }, indent=2)


def _scan_byo(args) -> None:
    if not args.spec:
        sys.exit("error: --spec is required with --target-image")
    if not args.i_own_this:
        sys.exit("Refusing to run. Argus executes real exploits against the target.\n"
                 "Point it ONLY at systems you own or are explicitly authorized to test,\n"
                 "then pass --i-own-this to attest that.")
    from agent.byo import scan_byo

    trace, findings = scan_byo(args.spec, args.target_image, args.port,
                               provider=args.provider, model=args.model)
    out = ROOT / "traces" / f"byo-{trace.run_id}.json"
    trace.save(out)
    confirmed = sum(f.verdict == CONFIRMED for f in findings)
    if args.json:
        print(_as_json(trace.run_id, trace.target, [asdict(f) for f in findings], confirmed, out,
                       target_image=args.target_image))
    else:
        print(f"\nArgus [byo:{args.target_image}] - {len(findings)} adjudicated: "
              f"{confirmed} confirmed, {len(findings) - confirmed} rejected\n")
        for f in findings:
            mark = "CONFIRMED" if f.verdict == CONFIRMED else "rejected "
            print(f"  [{mark}] {f.endpoint}  {f.attacker}->{f.victim}  {f.reason}")
        print(f"\ntrace: {out}")


def main():
    ap = argparse.ArgumentParser(prog="argus", description="Prove IDOR / BAC findings, don't guess.")
    sub = ap.add_subparsers(dest="command", required=True)

    s = sub.add_parser("scan", help="run the validation loop in the sandbox and emit a trace")
    s.add_argument("--provider", choices=["deepseek", "openai", "gemini"],
                   help="LLM provider (default: env ARGUS_PROVIDER or deepseek)")
    s.add_argument("--model", help="model id override")
    s.add_argument("--target-image", help="scan YOUR OWN containerized app instead of the bundled target")
    s.add_argument("--port", type=int, default=8080, help="port your app's container listens on")
    s.add_argument("--spec", help="target spec (accounts + object owners) for --target-image")
    s.add_argument("--i-own-this", action="store_true",
                   help="attest you own / are authorized to test the target (required for --target-image)")
    s.add_argument("--json", action="store_true", help="print findings as JSON instead of text")

    e = sub.add_parser("eval", help="run the precision/recall benchmark (no Docker, no API key)")
    e.add_argument("--json", action="store_true", help="print the full report as JSON instead of the table")

    args = ap.parse_args()
    if args.command == "scan":
        from runner.docker_runner import DockerUnavailable
        try:
            if args.target_image:
                _scan_byo(args)
            else:
                scan(provider=args.provider, model=args.model, as_json=args.json)
        except DockerUnavailable as e:
            sys.exit(f"\nArgus needs Docker for `scan`.\n{e}")
    elif args.command == "eval":
        from evals.harness import _print, run
        report = run()
        print(json.dumps(report, indent=2)) if args.json else _print(report)


if __name__ == "__main__":
    main()
