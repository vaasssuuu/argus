"""Bring-your-own-target scan.

Tests a user's OWN app (one they are authorized to test) for IDOR, with no ground-truth
manifest. The user supplies a small spec (two or more test accounts + which objects each owns);
Argus runs their container on the egress-locked sandbox network and, for every cross-account
pair, has the attacker and the owner each request the owner's object. The differential oracle
(agent/oracle/differential.differential_verdict) confirms a leak only when the attacker gets
byte-for-byte what the owner sees. No secrets needed, no false positives.
"""
import uuid
from dataclasses import asdict
from pathlib import Path

import yaml

from agent.oracle.differential import differential_verdict
from agent.schemas.finding import CONFIRMED
from agent.schemas.trace import Trace


def load_spec(path) -> dict:
    return yaml.safe_load(Path(path).read_text(encoding="utf-8"))


def _candidates(spec):
    principals = spec["principals"]
    for obj in spec["objects"]:
        victim = obj["owner"]
        for attacker in principals:
            if attacker != victim:
                yield obj["endpoint"], str(obj["id"]), attacker, victim


def scan_byo(spec_path, image, port, *, remediate=True, provider=None, model=None):
    spec = load_spec(spec_path)
    principals = spec["principals"]
    trace = Trace(run_id=uuid.uuid4().hex[:8], target=f"byo: {image}")
    findings = []

    from runner.docker_runner import DockerRunner  # lazy: only scan needs Docker
    with DockerRunner(target_image=image, target_port=port, build_target=False) as runner:
        trace.step("recon", f"spec: {len(principals)} accounts, {len(spec['objects'])} objects")
        for endpoint, oid, attacker, victim in _candidates(spec):
            method, template = endpoint.split(" ", 1)
            path = template.replace("{id}", oid)
            hdr = principals[attacker]["headers"]
            resp_a = runner.run_poc({"method": method, "path": path, "headers": hdr})
            resp_o = runner.run_poc({"method": method, "path": path,
                                     "headers": principals[victim]["headers"]})
            f = differential_verdict(
                attacker=attacker, victim=victim, endpoint=endpoint, object_id=oid,
                resp_attacker=resp_a, resp_owner=resp_o,
                request={"method": method, "path": path, "headers": {"Authorization": "<redacted>"}},
            )
            findings.append(f)
            trace.step("classify", f"{f.verdict}: {f.reason}", finding_id=f.id)

    confirmed = [f for f in findings if f.verdict == CONFIRMED]
    if remediate and confirmed:
        _remediate(confirmed, provider, model, trace)
    trace.findings = [asdict(f) for f in findings]
    return trace, findings


def _remediate(confirmed, provider, model, trace) -> None:
    """Best-effort fix text: use the LLM if a key is configured, else a generic note."""
    try:
        from agent.llm.client import LLM
        from agent.nodes.remediate import SYS
        llm = LLM(provider=provider, model=model)
        for f in confirmed:
            f.remediation = llm.chat(SYS, f"Endpoint {f.endpoint}: {f.reason}").strip()
        trace.step("remediate", f"fix suggestions for {len(confirmed)} confirmed finding(s)")
    except Exception as e:
        for f in confirmed:
            f.remediation = ("Enforce an ownership check: load the object, verify its owner matches "
                             "the authenticated user, and deny with 403/404 otherwise.")
        trace.step("remediate", f"generic fix note (no LLM: {type(e).__name__})")


if __name__ == "__main__":
    # Self-check: run the BYO flow against the bundled image as a stand-in user app.
    from runner.docker_runner import build_images
    build_images()
    spec = Path(__file__).resolve().parents[1] / "examples" / "byo-target-spec.yaml"
    _trace, findings = scan_byo(str(spec), "argus-target", 5000, remediate=False)
    for f in findings:
        print(f"  [{f.verdict:<14}] {f.endpoint:<26} {f.attacker}->{f.victim}  {f.reason}")
