"""Candidate generation — the LLM proposes cross-user access tests from the recon inventory.

The model sees endpoints, resources, owned ids and user aliases — never the labels or the
secrets. It proposes *hypotheses* (one user reading another's object); it does NOT judge
exploitability. We validate every candidate against the inventory and drop anything invented.
"""
import json

SYS = (
    "You are an IDOR / broken-access-control recon assistant. You are given an API's object "
    "endpoints, which object ids each test user owns, and the user aliases. Propose concrete "
    "cross-user access tests: one user requesting another user's object by its id. Return JSON "
    '{"candidates":[{"endpoint":str,"resource":str,"attacker":alias,"victim":alias,"object_id":id}]}. '
    "Use ONLY the given endpoints, resources, ids and aliases. Propose a test for every object "
    "endpoint, in both directions. Do NOT decide whether it is vulnerable."
)


def candidates(state, *, llm):
    inv = state["inventory"]
    users = list(state["principals"])
    raw = llm.chat(SYS, json.dumps({"templates": inv["templates"], "owned": inv["owned"],
                                    "users": users}), json_mode=True)
    proposed = json.loads(raw).get("candidates", [])

    valid = [c for c in proposed if _ok(c, inv, users)]
    state["trace"].step("candidates", f"{len(valid)} valid candidate(s) "
                        f"({len(proposed) - len(valid)} dropped as invalid)", candidates=valid)
    return {"candidates": valid, "cursor": 0}


def _ok(c, inv, users):
    try:
        return (c["attacker"] in users and c["victim"] in users and c["attacker"] != c["victim"]
                and inv["templates"].get(c["resource"]) == c["endpoint"]
                and c["object_id"] in inv["owned"][c["victim"]].get(c["resource"], []))
    except (KeyError, TypeError):
        return False
