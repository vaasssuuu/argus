"""In-memory seed data for the target app.

Each principal owns resources that carry a UNIQUE `secret`. The oracle proves an IDOR by
confirming that principal A received a resource containing principal B's secret. These
secrets are mirrored in `ground_truth.yaml` (the oracle's answer key); a test asserts the
two stay in sync. The app owns this data; the manifest owns the verdict labels.
"""

# bearer token -> principal identity (what /api/me returns; note: no secret in here)
PRINCIPALS = {
    "tok_alice_3f9a": {"id": "u_alice", "name": "Alice Okafor", "role": "user"},
    "tok_bob_7c2e":   {"id": "u_bob",   "name": "Bob Nakamura", "role": "user"},
}

# object_id -> resource. `owner` is the principal id; `secret` is the oracle's content evidence.
INVOICES = {
    "inv_1001": {"owner": "u_alice", "secret": "ALICE-INV-7a3f", "amount": 420.00,  "customer": "Northwind Ltd"},
    "inv_2001": {"owner": "u_bob",   "secret": "BOB-INV-9c2e",   "amount": 1375.50, "customer": "Globex Inc"},
}
DOCUMENTS = {
    "doc_1001": {"owner": "u_alice", "secret": "ALICE-DOC-11b8", "title": "Q3 strategy"},
    "doc_2001": {"owner": "u_bob",   "secret": "BOB-DOC-55d4",   "title": "Vendor contract"},
}
MESSAGES = {
    "msg_1001": {"owner": "u_alice", "secret": "ALICE-MSG-2e71", "body": "lunch at 1?"},
    "msg_2001": {"owner": "u_bob",   "secret": "BOB-MSG-8a09",   "body": "sent the wire"},
}

# trap resources: the handlers DO enforce ownership (they look like IDOR but are not)
PROFILES = {
    "u_alice": {"owner": "u_alice", "secret": "ALICE-PRO-4d2c", "email": "alice@argus.test"},
    "u_bob":   {"owner": "u_bob",   "secret": "BOB-PRO-6f1a",   "email": "bob@argus.test"},
}
ORDERS = {
    "ord_1001": {"owner": "u_alice", "secret": "ALICE-ORD-9b3d", "item": "Keyboard"},
    "ord_2001": {"owner": "u_bob",   "secret": "BOB-ORD-7e52",   "item": "Monitor"},
}
SETTINGS = {
    "set_1001": {"owner": "u_alice", "secret": "ALICE-SET-1c4e", "theme": "dark"},
    "set_2001": {"owner": "u_bob",   "secret": "BOB-SET-3a8f",   "theme": "light"},
}

# safe: public resource, no owner boundary at all
ANNOUNCEMENTS = {
    "ann_1": {"secret": "PUBLIC-ANN-0000", "title": "Scheduled maintenance"},
    "ann_2": {"secret": "PUBLIC-ANN-0001", "title": "New feature launch"},
}
