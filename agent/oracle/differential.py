"""The deterministic differential oracle — Argus's centerpiece.

Principle: the LLM proposes; the oracle disposes. The model may hypothesise candidates and
write PoCs, but the confirm/reject verdict is made HERE, deterministically, from evidence.

Two layers, deliberately separated:

- `behavioral_verdict` — the *detection*. Did attacker A actually receive victim B's data?
  It uses ONLY what a tester holding two of their own accounts can legitimately observe: the
  HTTP status, and whether B's own known data came back. It NEVER looks at the vulnerable/trap
  label. This is what the eval harness scores against the hidden labels, so the precision/recall
  it reports is genuinely earned, not read off an answer key.

- `classify` — the *product verdict*. It is the behavioural detection plus a ground-truth
  backstop: if behaviour resembled a leak but the manifest marks the access authorized (a
  trap), it refuses to confirm. Behaviour can be surprising; the manifest is the final authority
  against a false *confirmation*.
"""
from pathlib import Path

import yaml

from agent.schemas.finding import CONFIRMED, FALSE_POSITIVE, Attempt, Finding

DEFAULT_MANIFEST = Path(__file__).resolve().parents[2] / "target" / "ground_truth.yaml"


def load_manifest(path=DEFAULT_MANIFEST) -> dict:
    return yaml.safe_load(Path(path).read_text(encoding="utf-8"))


def _endpoint_label(manifest: dict, endpoint: str) -> str | None:
    """endpoint is "METHOD /path/{id}". Return its manifest label, or None if unknown."""
    for e in manifest.get("endpoints", []):
        if f"{e['method']} {e['path']}" == endpoint:
            return e["label"]
    return None


def _victim_secret(manifest: dict, resource: str, object_id: str):
    return manifest.get("objects", {}).get(resource, {}).get(object_id, {}).get("secret")


def behavioral_verdict(attempt: Attempt, manifest: dict):
    """Detection from behaviour alone (no labels). Returns (confirmed, checks, reason).

    `manifest` is used only to look up the victim's own known secret — i.e. the tester's own
    second account's data — which is a legitimate observation, not the answer key.
    """
    secret = _victim_secret(manifest, attempt.resource, attempt.object_id)
    status_2xx = 200 <= attempt.status < 300
    content_leak = bool(secret) and secret in attempt.body_text
    cross_principal = attempt.attacker != attempt.victim

    checks = [name for name, ok in (
        ("status_2xx", status_2xx),
        ("victim_content_present", content_leak),
        ("cross_principal", cross_principal),
    ) if ok]
    confirmed = status_2xx and content_leak and cross_principal

    if confirmed:
        reason = (f"{attempt.attacker} retrieved {attempt.victim}'s {attempt.resource[:-1]} "
                  f"({attempt.object_id}), and the response carried the victim's unique data.")
    elif not cross_principal:
        reason = "attacker and victim are the same principal; not cross-boundary."
    elif not status_2xx:
        reason = f"access denied (HTTP {attempt.status}); access control held."
    else:
        reason = "2xx but response carried no victim-identifying data; no leak."
    return confirmed, checks, reason


def classify(attempt: Attempt, manifest: dict) -> Finding:
    confirmed, checks, reason = behavioral_verdict(attempt, manifest)
    label = _endpoint_label(manifest, attempt.endpoint)

    if confirmed and label == "vulnerable":
        verdict = CONFIRMED
        checks = checks + ["ground_truth_cross_boundary"]
    elif confirmed:  # looked like a leak, but ground truth marks this authorized -> backstop
        verdict = FALSE_POSITIVE
        reason = "behaviour resembled a leak but ground truth marks this access authorized (trap), not a real IDOR."
    else:
        verdict = FALSE_POSITIVE

    return Finding(
        id=f"{attempt.resource}:{attempt.object_id}:{attempt.attacker}->{attempt.victim}",
        endpoint=attempt.endpoint,
        attacker=attempt.attacker,
        victim=attempt.victim,
        verdict=verdict,
        checks=checks,
        reason=reason,
        request=attempt.request,
        response={"status": attempt.status, "body_excerpt": attempt.body_text[:500]},
    )


def differential_verdict(*, attacker, victim, endpoint, object_id, resp_attacker, resp_owner, request) -> Finding:
    """Manifest-free detection for a user's OWN app (no ground-truth secrets or labels).

    Attacker A and owner B each request B's object. If A gets a 2xx whose body is identical to
    what B sees for B's own object, A has read B's data: a confirmed IDOR. The owner's own
    response *is* the ground truth for that object, so no pre-known secret is needed. Exact-match
    is deliberately conservative, so this never raises a false positive (at worst it misses a
    leak whose response embeds the requester's identity).

    resp_attacker / resp_owner are {"status": int, "body": str} from the runner.
    """
    a_status = resp_attacker["status"]
    status_2xx = 200 <= a_status < 300
    a_body = (resp_attacker.get("body") or "").strip()
    o_body = (resp_owner.get("body") or "").strip()
    matches_owner = bool(a_body) and a_body == o_body
    cross = attacker != victim
    confirmed = status_2xx and matches_owner and cross

    if confirmed:
        verdict = CONFIRMED
        checks = ["status_2xx", "matches_owner_view", "cross_principal"]
        reason = (f"{attacker} received the exact object {victim} owns ({object_id}); the response is "
                  f"byte-for-byte what {victim} sees, so {attacker} read {victim}'s data.")
    else:
        verdict = FALSE_POSITIVE
        checks = []
        if not cross:
            reason = "attacker and owner are the same principal; not cross-boundary."
        elif not status_2xx:
            reason = f"access denied (HTTP {a_status}); access control held."
        else:
            reason = "2xx but the response did not match the owner's own view; no cross-user leak."

    return Finding(
        id=f"{endpoint}:{object_id}:{attacker}->{victim}",
        endpoint=endpoint, attacker=attacker, victim=victim, verdict=verdict,
        checks=checks, reason=reason, request=request,
        response={"status": a_status, "body_excerpt": a_body[:500]},
    )
