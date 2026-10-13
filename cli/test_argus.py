"""Locks the --json output contract: valid JSON, stable keys, and a summary that
matches the findings (so anything piping `argus scan --json` / `argus eval --json`
into CI can rely on the shape)."""
import json

from cli.argus import _as_json

FINDINGS = [
    {"id": "f1", "endpoint": "GET /api/invoices/{id}", "verdict": "confirmed"},
    {"id": "f2", "endpoint": "GET /api/messages/{id}", "verdict": "false_positive"},
]


def test_as_json_is_valid_and_has_stable_keys():
    d = json.loads(_as_json("run1", "bundled", FINDINGS, 1, "traces/run1.json"))
    assert set(d) >= {"run_id", "target", "summary", "findings", "trace"}
    assert d["run_id"] == "run1" and d["trace"] == "traces/run1.json"
    assert d["findings"] == FINDINGS


def test_summary_counts_match_findings():
    d = json.loads(_as_json("r", "t", FINDINGS, confirmed=1, trace_path="x"))
    assert d["summary"] == {"adjudicated": 2, "confirmed": 1, "rejected": 1}


def test_extra_metadata_is_merged_in():
    d = json.loads(_as_json("r", "t", [], 0, "x", provider="gemini", model="flash"))
    assert d["provider"] == "gemini" and d["model"] == "flash"
    assert d["summary"]["adjudicated"] == 0
