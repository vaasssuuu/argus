"""Execute — run the current PoC in the sandbox runner and record the attempt.

This is the only node that touches the target with an exploit, and it does so only through the
runner (egress-contained). The token is redacted in the stored request; the oracle reads the
raw body next."""
from agent.schemas.finding import Attempt


def execute(state, *, runner):
    c = state["candidates"][state["cursor"]]
    poc = state["current_poc"]
    resp = runner.run_poc(poc)

    attempt = Attempt(
        endpoint=c["endpoint"], resource=c["resource"],
        attacker=c["attacker"], victim=c["victim"], object_id=c["object_id"],
        request={"method": poc["method"], "path": poc["path"],
                 "headers": {"Authorization": "Bearer <redacted>"}},
        status=resp["status"], body_text=resp["body"],
    )
    state["trace"].step("execute", f"{c['attacker']}→{c['victim']} {c['endpoint']} → {resp['status']}",
                        status=resp["status"])
    return {"current_attempt": attempt}
