"""Target self-checks: the vulnerable surface really leaks, the traps really hold, and the
manifest matches what the app serves. This is the ground the oracle will stand on."""
import pathlib

import yaml

from target import seed_data as db
from target.app import app

GT = yaml.safe_load((pathlib.Path(__file__).parent / "ground_truth.yaml").read_text())
ALICE = {"Authorization": "Bearer tok_alice_3f9a"}
BOB = {"Authorization": "Bearer tok_bob_7c2e"}
client = app.test_client()


def test_auth_required():
    assert client.get("/api/invoices/inv_1001").status_code == 401


def test_vulnerable_idor_leaks_cross_principal():
    # Alice reads Bob's invoice — no ownership check, so his secret leaks.
    r = client.get("/api/invoices/inv_2001", headers=ALICE)
    assert r.status_code == 200
    assert "BOB-INV-9c2e" in r.get_data(as_text=True)


def test_trap_denies_cross_principal():
    # Alice reads Bob's order — ownership enforced, must be denied.
    assert client.get("/api/orders/ord_2001", headers=ALICE).status_code == 403


def test_trap_allows_own():
    r = client.get("/api/orders/ord_1001", headers=ALICE)
    assert r.status_code == 200
    assert "ALICE-ORD-9b3d" in r.get_data(as_text=True)


def test_manifest_secrets_match_seed_data():
    maps = {"invoices": db.INVOICES, "documents": db.DOCUMENTS, "messages": db.MESSAGES,
            "profiles": db.PROFILES, "orders": db.ORDERS, "settings": db.SETTINGS}
    for rtype, objs in GT["objects"].items():
        for oid, meta in objs.items():
            assert maps[rtype][oid]["secret"] == meta["secret"], f"{rtype}/{oid} secret drift"
