"""Recon — crawl the target from each principal's /api/me hub to learn the endpoint surface
and which object ids each user owns. All traffic goes through the sandbox runner, so even
recon is egress-contained. No LLM here: this is deterministic observation."""
import json


def recon(state, *, runner):
    templates, owned = {}, {}
    for alias, p in state["principals"].items():
        resp = runner.run_poc({"method": "GET", "path": "/api/me",
                               "headers": {"Authorization": f"Bearer {p['token']}"}})
        me = json.loads(resp["body"])
        owned[alias] = {}
        for resource, items in me.get("resources", {}).items():
            ids = [it["id"] for it in items if "id" in it]
            owned[alias][resource] = ids
            for it in items:  # derive "GET /api/invoices/{id}" from a concrete href
                templates[resource] = "GET " + it["href"].replace(it["id"], "{id}")

    inventory = {"templates": templates, "owned": owned}
    state["trace"].step("recon", f"{len(templates)} object endpoints, "
                        f"{sum(len(v) for o in owned.values() for v in o.values())} owned ids",
                        **inventory)
    return {"inventory": inventory}
