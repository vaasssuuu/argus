"""MedVault (target2) — a deliberately-vulnerable patient-records API.

Same readable contract as the primary target (static bearer tokens, a /api/me hub, an
object-id endpoint per resource), different domain and a numeric/enumerable id scheme. Handlers
marked VULNERABLE omit the ownership check on purpose; TRAP handlers enforce it; SAFE handlers
have no cross-principal boundary. Labels live only in ground_truth.yaml.
"""
import os

from flask import Flask, abort, jsonify, request
from werkzeug.exceptions import HTTPException

from target2 import seed_data as db

app = Flask(__name__)


def current_user():
    token = request.headers.get("Authorization", "").removeprefix("Bearer ").strip()
    user = db.PRINCIPALS.get(token)
    if user is None:
        abort(401, "missing or invalid bearer token")
    return user


def _obj(mapping, oid):
    obj = mapping.get(oid)
    if obj is None:
        abort(404)
    return obj


@app.errorhandler(HTTPException)
def _json_error(e):
    return jsonify(error=e.name.lower().replace(" ", "_"), status=e.code), e.code


# ── SAFE ────────────────────────────────────────────────────────────────────────────────
@app.get("/api/health")
def health():
    return jsonify(status="ok")


@app.get("/api/me")
def me():
    user = current_user()
    owned = lambda m, tmpl: [{"id": i, "href": tmpl.format(id=i)}
                             for i, o in m.items() if o.get("owner") == user["id"]]
    return jsonify({**user, "resources": {
        "records":       owned(db.RECORDS,       "/api/records/{id}"),
        "prescriptions": owned(db.PRESCRIPTIONS, "/api/prescriptions/{id}"),
        "labs":          owned(db.LABS,          "/api/labs/{id}"),
        "appointments":  owned(db.APPOINTMENTS,  "/api/appointments/{id}"),
        "billing":       owned(db.BILLING,       "/api/billing/{id}"),
        "messages":      owned(db.MESSAGES,      "/api/messages/{id}"),
    }})


@app.get("/api/announcements/<oid>")
def get_announcement(oid):
    current_user()
    return jsonify(_obj(db.ANNOUNCEMENTS, oid))  # public resource; no owner boundary


# ── VULNERABLE (IDOR: no ownership check) ───────────────────────────────────────────────
@app.get("/api/records/<oid>")
def get_record(oid):
    current_user()
    return jsonify(_obj(db.RECORDS, oid))  # VULNERABLE


@app.get("/api/prescriptions/<oid>")
def get_prescription(oid):
    current_user()
    return jsonify(_obj(db.PRESCRIPTIONS, oid))  # VULNERABLE


@app.get("/api/labs/<oid>")
def get_lab(oid):
    current_user()
    return jsonify(_obj(db.LABS, oid))  # VULNERABLE


# ── TRAP (ownership enforced) ───────────────────────────────────────────────────────────
@app.get("/api/appointments/<oid>")
def get_appointment(oid):
    user = current_user()
    obj = _obj(db.APPOINTMENTS, oid)
    if obj["owner"] != user["id"]:
        abort(403)  # TRAP
    return jsonify(obj)


@app.get("/api/billing/<oid>")
def get_billing(oid):
    user = current_user()
    obj = _obj(db.BILLING, oid)
    if obj["owner"] != user["id"]:
        abort(403)  # TRAP
    return jsonify(obj)


@app.get("/api/messages/<oid>")
def get_message(oid):
    user = current_user()
    obj = _obj(db.MESSAGES, oid)
    if obj["owner"] != user["id"]:
        abort(403)  # TRAP
    return jsonify(obj)


if __name__ == "__main__":
    app.run(host=os.environ.get("HOST", "127.0.0.1"), port=int(os.environ.get("PORT", "5001")))
