"""The deterministic differential oracle — Argus's centerpiece.

Principle: the LLM proposes; the oracle disposes. The model may hypothesise candidates and
write PoCs, but the confirm/reject verdict is made HERE, deterministically, from evidence.
The LLM never grades its own homework.

An IDOR is CONFIRMED only when ALL of these hold for an attempt where attacker != victim:
  1. status      — the attacker got a 2xx they should not have,
  2. content     — the response contains the victim's unique secret (proof it's the victim's
                   object, not the attacker's own data or an empty body), and
  3. ground_truth— the manifest marks this endpoint a real cross-boundary (`vulnerable`),
                   not an authorized-by-design access (a `trap`).
Anything else is a FALSE_POSITIVE, and the reason names the check that held the line.
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


def classify(attempt: Attempt, manifest: dict) -> Finding:
    secret = manifest.get("objects", {}).get(attempt.resource, {}).get(attempt.object_id, {}).get("secret")
    label = _endpoint_label(manifest, attempt.endpoint)

    status_2xx = 200 <= attempt.status < 300
    content_leak = bool(secret) and secret in attempt.body_text
    gt_vulnerable = label == "vulnerable"
    cross_principal = attempt.attacker != attempt.victim

    checks = [name for name, ok in (
        ("status_2xx", status_2xx),
        ("victim_content_present", content_leak),
        ("ground_truth_cross_boundary", gt_vulnerable),
        ("cross_principal", cross_principal),
    ) if ok]

    if status_2xx and content_leak and gt_vulnerable and cross_principal:
        verdict, reason = CONFIRMED, (
            f"{attempt.attacker} retrieved {attempt.victim}'s {attempt.resource[:-1]} "
            f"({attempt.object_id}) — response carried the victim's unique data."
        )
    elif not cross_principal:
        verdict, reason = FALSE_POSITIVE, "attacker and victim are the same principal; not cross-boundary."
    elif not status_2xx:
        verdict, reason = FALSE_POSITIVE, f"access denied (HTTP {attempt.status}); access control held."
    elif not content_leak:
        verdict, reason = FALSE_POSITIVE, "2xx but response carried no victim-identifying data; no leak."
    else:  # behaviour looked like a leak, but ground truth says this access is authorized
        verdict, reason = FALSE_POSITIVE, "authorized by ground truth (trap), not a real IDOR."

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
