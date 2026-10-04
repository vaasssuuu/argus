"""PoC synthesis — the LLM writes the exploit request for the current candidate.

The model proposes {method, path, headers}; we then enforce the two security-critical
invariants ourselves: the path must target the victim's object id, and the request must carry
the *attacker's* token. If the model's output doesn't hold them, we use the correct request and
note the correction — we never execute an incorrect exploit.
"""
import json

SYS = (
    "You write ONE HTTP request that performs a single access test. Return JSON "
    '{"method":str,"path":str,"headers":{"Authorization":"Bearer <token>"}}. Use the attacker '
    "token to request the victim's object id at the given endpoint. No prose."
)


def poc_synthesis(state, *, llm):
    c = state["candidates"][state["cursor"]]
    template = c["endpoint"].split(" ", 1)[1]          # "/api/invoices/{id}"
    want_path = template.replace("{id}", c["object_id"])
    token = state["principals"][c["attacker"]]["token"]

    raw = llm.chat(SYS, json.dumps({"endpoint": c["endpoint"], "path_template": template,
                                    "object_id": c["object_id"], "attacker_token": token}),
                   json_mode=True)
    try:
        poc = json.loads(raw)
        valid = poc.get("path") == want_path and \
            poc.get("headers", {}).get("Authorization") == f"Bearer {token}"
    except (json.JSONDecodeError, AttributeError):
        valid = False
    if not valid:  # enforce correctness regardless of model output
        poc = {"method": "GET", "path": want_path, "headers": {"Authorization": f"Bearer {token}"}}

    poc.setdefault("method", "GET")
    state["trace"].step("poc_synthesis", f"{c['attacker']}→{c['victim']} {poc['method']} {poc['path']}"
                        + ("" if valid else "  (corrected)"))
    return {"current_poc": poc}
