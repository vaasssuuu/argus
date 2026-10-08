"""Oracle self-checks: it confirms a real IDOR, rejects the trap, and never confirms on
weak evidence. Every branch of the verdict is exercised against the real manifest."""
from agent.oracle.differential import classify, differential_verdict, load_manifest
from agent.schemas.finding import CONFIRMED, FALSE_POSITIVE, Attempt

M = load_manifest()


def _attempt(endpoint, resource, attacker, victim, oid, status, body):
    return Attempt(endpoint=endpoint, resource=resource, attacker=attacker, victim=victim,
                   object_id=oid, request={"method": endpoint.split()[0], "url": f"/{oid}"},
                   status=status, body_text=body)


def test_confirms_real_idor():
    f = classify(_attempt("GET /api/invoices/{id}", "invoices", "alice", "bob",
                          "inv_2001", 200, '{"secret":"BOB-INV-9c2e"}'), M)
    assert f.verdict == CONFIRMED
    assert set(f.checks) == {"status_2xx", "victim_content_present",
                             "ground_truth_cross_boundary", "cross_principal"}


def test_rejects_trap_denied():
    f = classify(_attempt("GET /api/orders/{id}", "orders", "alice", "bob",
                          "ord_2001", 403, '{"error":"forbidden"}'), M)
    assert f.verdict == FALSE_POSITIVE and "denied" in f.reason


def test_rejects_2xx_without_leak():
    f = classify(_attempt("GET /api/invoices/{id}", "invoices", "alice", "bob",
                          "inv_2001", 200, '{"note":"nothing identifying here"}'), M)
    assert f.verdict == FALSE_POSITIVE and "no leak" in f.reason


def test_ground_truth_backstops_a_buggy_looking_trap():
    # Even if a trap endpoint *behaved* like a leak (2xx + victim secret), the manifest
    # says it's authorized — the oracle must still refuse to confirm.
    f = classify(_attempt("GET /api/orders/{id}", "orders", "alice", "bob",
                          "ord_2001", 200, '{"secret":"BOB-ORD-7e52"}'), M)
    assert f.verdict == FALSE_POSITIVE and "trap" in f.reason


def test_rejects_same_principal():
    f = classify(_attempt("GET /api/invoices/{id}", "invoices", "alice", "alice",
                          "inv_1001", 200, '{"secret":"ALICE-INV-7a3f"}'), M)
    assert f.verdict == FALSE_POSITIVE and "same principal" in f.reason


# ── manifest-free differential oracle (bring-your-own-target) ─────────────────────────────
def _diff(attacker, victim, a, o):
    return differential_verdict(attacker=attacker, victim=victim, endpoint="GET /api/x/{id}",
                                object_id="42", resp_attacker=a, resp_owner=o, request={})


def test_differential_confirms_when_attacker_sees_owner_view():
    f = _diff("alice", "bob", {"status": 200, "body": '{"id":42,"data":"bob"}'},
              {"status": 200, "body": '{"id":42,"data":"bob"}'})
    assert f.verdict == CONFIRMED and "matches_owner_view" in f.checks


def test_differential_rejects_denied():
    f = _diff("alice", "bob", {"status": 403, "body": "forbidden"},
              {"status": 200, "body": '{"id":42,"data":"bob"}'})
    assert f.verdict == FALSE_POSITIVE and "denied" in f.reason


def test_differential_rejects_when_response_differs():
    f = _diff("alice", "bob", {"status": 200, "body": '{"id":42,"data":"alice-own"}'},
              {"status": 200, "body": '{"id":42,"data":"bob"}'})
    assert f.verdict == FALSE_POSITIVE and "did not match" in f.reason


def test_differential_rejects_same_principal():
    f = _diff("alice", "alice", {"status": 200, "body": "same"}, {"status": 200, "body": "same"})
    assert f.verdict == FALSE_POSITIVE and "same principal" in f.reason
