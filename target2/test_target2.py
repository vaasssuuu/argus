"""MedVault self-checks: the vulnerable surface leaks, the traps hold, and the manifest
matches what the app serves."""
import pathlib

import yaml

from target2 import seed_data as db
from target2.app import app

GT = yaml.safe_load((pathlib.Path(__file__).parent / "ground_truth.yaml").read_text())
ALICE = {"Authorization": "Bearer tok_med_alice_a1"}
client = app.test_client()


def test_auth_required():
    assert client.get("/api/records/5001").status_code == 401


def test_vulnerable_idor_leaks_cross_principal():
    r = client.get("/api/records/5002", headers=ALICE)  # Alice reads Bob's record
    assert r.status_code == 200
    assert "BO-REC-5002" in r.get_data(as_text=True)


def test_trap_denies_cross_principal():
    assert client.get("/api/appointments/3002", headers=ALICE).status_code == 403


def test_trap_allows_own():
    r = client.get("/api/appointments/3001", headers=ALICE)
    assert r.status_code == 200 and "AL-APT-3001" in r.get_data(as_text=True)


def test_manifest_secrets_match_seed_data():
    maps = {"records": db.RECORDS, "prescriptions": db.PRESCRIPTIONS, "labs": db.LABS,
            "appointments": db.APPOINTMENTS, "billing": db.BILLING, "messages": db.MESSAGES}
    for rtype, objs in GT["objects"].items():
        for oid, meta in objs.items():
            assert maps[rtype][oid]["secret"] == meta["secret"], f"{rtype}/{oid} secret drift"
