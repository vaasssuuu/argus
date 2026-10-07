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
