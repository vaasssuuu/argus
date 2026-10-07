"""Eval harness — the headline number, measured across every bundled target.

For each target it deterministically enumerates every cross-principal access on the object
endpoints (from that target's ground-truth manifest), executes each against the real app, and
scores the oracle's *behavioural* verdict ("did attacker A actually receive victim B's data?")
against the hidden labels. The oracle never sees the labels while deciding; they only score.
Running across two different apps makes the precision/recall far harder to dismiss as a toy.

    uv run python -m evals.harness

Prints a per-target + overall confusion matrix and writes evals/report.json.
"""
import json
from pathlib import Path

from agent.oracle.differential import behavioral_verdict, load_manifest
from agent.schemas.finding import Attempt
from target.app import app as saas_app
from target2.app import app as clinic_app

ROOT = Path(__file__).resolve().parents[1]

TARGETS = [
    ("saas",   saas_app,   ROOT / "target" / "ground_truth.yaml"),
    ("clinic", clinic_app, ROOT / "target2" / "ground_truth.yaml"),
]


def _cases(manifest):
    """Every (endpoint, attacker→victim, victim-owned object) on a labelled object endpoint."""
    users = manifest["principals"]
    for e in manifest["endpoints"]:
        objs = manifest.get("objects", {}).get(e["resource"])
        if e["label"] not in ("vulnerable", "trap") or not objs:
            continue
        for attacker in users:
            for victim in users:
                if attacker == victim:
                    continue
                for oid, meta in objs.items():
                    if meta["owner"] == victim:
                        yield e, attacker, victim, oid


def _score(name, app, manifest_path):
    manifest = load_manifest(manifest_path)
    users = manifest["principals"]
    client = app.test_client()
    counts = {"TP": 0, "FP": 0, "FN": 0, "TN": 0}
    rows = []
    for e, attacker, victim, oid in _cases(manifest):
        path = e["path"].replace("{id}", oid)
        r = client.open(path, method=e["method"],
                        headers={"Authorization": f"Bearer {users[attacker]['token']}"})
        attempt = Attempt(
            endpoint=f"{e['method']} {e['path']}", resource=e["resource"],
            attacker=attacker, victim=victim, object_id=oid,
            request={"method": e["method"], "path": path},
            status=r.status_code, body_text=r.get_data(as_text=True),
        )
        confirmed, _checks, _reason = behavioral_verdict(attempt, manifest)
        vuln = e["label"] == "vulnerable"
        outcome = ("TP" if confirmed and vuln else "FP" if confirmed else "FN" if vuln else "TN")
        counts[outcome] += 1
        rows.append({"target": name, "outcome": outcome, "label": e["label"], "endpoint": e["path"],
                     "attack": f"{attacker}->{victim}", "object_id": oid,
                     "verdict": "confirmed" if confirmed else "rejected", "status": r.status_code})
    return counts, rows


def _metrics(c):
    tp, fp, fn, tn = c["TP"], c["FP"], c["FN"], c["TN"]
    n = tp + fp + fn + tn
    return {
        "precision": tp / (tp + fp) if tp + fp else 1.0,
        "recall": tp / (tp + fn) if tp + fn else 1.0,
        "accuracy": (tp + tn) / n if n else 1.0,
        "confusion": c, "n_cases": n,
    }


def run(write=True) -> dict:
    overall = {"TP": 0, "FP": 0, "FN": 0, "TN": 0}
    per_target, rows = {}, []
    for name, app, manifest_path in TARGETS:
        counts, r = _score(name, app, manifest_path)
        per_target[name] = _metrics(counts)
        for k in overall:
            overall[k] += counts[k]
        rows += r
    report = {"metrics": _metrics(overall), "per_target": per_target, "cases": rows}
    if write:
        (ROOT / "evals" / "report.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    return report


def _print(report):
    m = report["metrics"]
    c = m["confusion"]
    print(f"\nArgus eval — {m['n_cases']} cross-principal cases across {len(report['per_target'])} targets\n")
    for name, tm in report["per_target"].items():
        tc = tm["confusion"]
        print(f"  [{name:<7}] {tm['n_cases']:>2} cases   TP={tc['TP']} FP={tc['FP']} FN={tc['FN']} TN={tc['TN']}"
              f"   P={tm['precision']:.2f} R={tm['recall']:.2f}")
    print(f"\n  OVERALL   {m['n_cases']} cases   TP={c['TP']} FP={c['FP']} FN={c['FN']} TN={c['TN']}"
          f"   precision={m['precision']:.2f}  recall={m['recall']:.2f}  accuracy={m['accuracy']:.2f}\n")


if __name__ == "__main__":
    _print(run())
