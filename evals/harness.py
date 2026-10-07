"""Eval harness — the headline number.

Deterministically enumerates every cross-principal access on the target's object endpoints
(from the ground-truth manifest), executes each against the real app, and scores the oracle's
*behavioural* verdict — "did attacker A actually receive victim B's data?" — against the hidden
labels. The oracle never sees the labels while deciding; they are used only to score here. So
the precision / recall below is earned by detection, not read off an answer key.

    uv run python -m evals.harness

Prints a confusion matrix + precision / recall / accuracy and writes evals/report.json.
"""
import json
from pathlib import Path

from agent.oracle.differential import behavioral_verdict, load_manifest
from agent.schemas.finding import Attempt
from target.app import app

ROOT = Path(__file__).resolve().parents[1]


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


def run(write=True) -> dict:
    manifest = load_manifest()
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
        actually_vulnerable = e["label"] == "vulnerable"
        outcome = ("TP" if confirmed and actually_vulnerable else
                   "FP" if confirmed else
                   "FN" if actually_vulnerable else "TN")
        counts[outcome] += 1
        rows.append({"outcome": outcome, "label": e["label"], "endpoint": e["path"],
                     "attack": f"{attacker}->{victim}", "object_id": oid,
                     "verdict": "confirmed" if confirmed else "rejected", "status": r.status_code})

    tp, fp, fn, tn = counts["TP"], counts["FP"], counts["FN"], counts["TN"]
    metrics = {
        "precision": tp / (tp + fp) if tp + fp else 1.0,
        "recall": tp / (tp + fn) if tp + fn else 1.0,
        "accuracy": (tp + tn) / sum(counts.values()) if sum(counts.values()) else 1.0,
        "confusion": counts, "n_cases": sum(counts.values()),
    }
    report = {"metrics": metrics, "cases": rows}
    if write:
        (ROOT / "evals" / "report.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    return report


def _print(report):
    m = report["metrics"]
    c = m["confusion"]
    print(f"\nArgus eval — {m['n_cases']} cross-principal cases on the bundled target\n")
    for row in report["cases"]:
        tick = "OK " if row["outcome"] in ("TP", "TN") else "!! "
        print(f"  {tick}[{row['outcome']}] {row['label']:<10} {row['attack']:<13} "
              f"{row['endpoint']:<28} -> {row['verdict']} (HTTP {row['status']})")
    print(f"\n  confusion:  TP={c['TP']}  FP={c['FP']}  FN={c['FN']}  TN={c['TN']}")
    print(f"  precision={m['precision']:.2f}  recall={m['recall']:.2f}  accuracy={m['accuracy']:.2f}\n")


if __name__ == "__main__":
    _print(run())
