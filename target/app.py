"""Argus target — a deliberately-vulnerable Flask app (IDOR / BAC demo surface).

This app is meant to be READABLE: for every handler you can see at a glance whether it
checks ownership. Handlers marked VULNERABLE omit that check on purpose. Handlers marked
TRAP enforce it (they take an object id and look like IDOR, but are correctly authorized).
SAFE handlers have no cross-principal boundary. The labels live in `ground_truth.yaml` —
the app never serves them, and the agent must reach its verdicts from behaviour alone.

Auth: static bearer tokens (seed_data.PRINCIPALS). Simplest thing that proves the point —
no sessions, no OAuth; the vulnerability class under test is authorization, not auth.
"""
import os

from flask import Flask, abort, jsonify, request
from werkzeug.exceptions import HTTPException

from target import seed_data as db

app = Flask(__name__)


def current_user():
    """Resolve the bearer token to a principal, or 401."""
    token = request.headers.get("Authorization", "").removeprefix("Bearer ").strip()
    user = db.PRINCIPALS.get(token)
    if user is None:
        abort(401, "missing or invalid bearer token")
    return user


def _obj(mapping, oid):
    """Fetch an object by id or 404 (empty/None -> 404, never a false hit)."""
    obj = mapping.get(oid)
    if obj is None:
        abort(404)
    return obj


@app.errorhandler(HTTPException)
def _json_error(e):
    return jsonify(error=e.name.lower().replace(" ", "_"), status=e.code), e.code


# ── SAFE ──────────────────────────────────────────────────────────────────────────────
@app.get("/api/health")
def health():
    return jsonify(status="ok")  # no auth, no object reference


@app.get("/api/me")
def me():
    user = current_user()  # caller's own identity + a hub of THEIR OWN resources (recon seed)
    owned = lambda m, tmpl: [{"id": i, "href": tmpl.format(id=i)}
                             for i, o in m.items() if o.get("owner") == user["id"]]
    return jsonify({**user, "resources": {
        "invoices":  owned(db.INVOICES,  "/api/invoices/{id}"),
        "documents": owned(db.DOCUMENTS, "/api/documents/{id}"),
        "messages":  owned(db.MESSAGES,  "/api/messages/{id}"),
        "orders":    owned(db.ORDERS,    "/api/orders/{id}"),
        "settings":  owned(db.SETTINGS,  "/api/settings/{id}"),
        "profiles":  [{"id": user["id"], "href": f"/api/users/{user['id']}/profile"}],
    }})


@app.get("/api/invoices")
def list_invoices():
    user = current_user()
    return jsonify({k: v for k, v in db.INVOICES.items() if v["owner"] == user["id"]})  # scoped


@app.get("/api/announcements/<oid>")
def get_announcement(oid):
    current_user()
    return jsonify(_obj(db.ANNOUNCEMENTS, oid))  # public resource; no owner boundary


# ── VULNERABLE (IDOR: ownership check is missing on purpose) ────────────────────────────
@app.get("/api/invoices/<oid>")
def get_invoice(oid):
    current_user()
    return jsonify(_obj(db.INVOICES, oid))  # VULNERABLE: returns any invoice, any owner


@app.get("/api/documents/<oid>")
def get_document(oid):
    current_user()
    return jsonify(_obj(db.DOCUMENTS, oid))  # VULNERABLE


@app.get("/api/messages/<oid>")
def get_message(oid):
    current_user()
    return jsonify(_obj(db.MESSAGES, oid))  # VULNERABLE


# ── TRAP (looks like IDOR, but ownership IS enforced) ───────────────────────────────────
@app.get("/api/users/<uid>/profile")
def get_profile(uid):
    user = current_user()
    if uid != user["id"]:
        abort(403)  # TRAP: enforced
    return jsonify(_obj(db.PROFILES, uid))


@app.get("/api/orders/<oid>")
def get_order(oid):
    user = current_user()
    obj = _obj(db.ORDERS, oid)
    if obj["owner"] != user["id"]:
        abort(403)  # TRAP: enforced
    return jsonify(obj)


@app.get("/api/settings/<oid>")
def get_settings(oid):
    user = current_user()
    obj = _obj(db.SETTINGS, oid)
    if obj["owner"] != user["id"]:
        abort(403)  # TRAP: enforced
    return jsonify(obj)


if __name__ == "__main__":
    app.run(host=os.environ.get("HOST", "127.0.0.1"), port=int(os.environ.get("PORT", "5000")))
