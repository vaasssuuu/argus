"""In-memory seed data for MedVault (target2).

Three patients, numeric (enumerable) object ids. Each owned object carries a UNIQUE secret
the oracle uses as content evidence; secrets are mirrored in ground_truth.yaml (a test checks
they stay in sync). `owner` here is the principal id; the manifest records the alias.
"""

# bearer token -> principal (what /api/me returns; no secret in here)
PRINCIPALS = {
    "tok_med_alice_a1": {"id": "pat_alice", "name": "Alice Romero", "role": "patient"},
    "tok_med_bob_b2":   {"id": "pat_bob",   "name": "Bob Mensah",   "role": "patient"},
    "tok_med_carol_c3": {"id": "pat_carol", "name": "Carol Singh",  "role": "patient"},
}

# object_id -> resource. `secret` = oracle content evidence.
RECORDS = {
    "5001": {"owner": "pat_alice", "secret": "AL-REC-5001", "diagnosis": "Hypertension"},
    "5002": {"owner": "pat_bob",   "secret": "BO-REC-5002", "diagnosis": "Asthma"},
    "5003": {"owner": "pat_carol", "secret": "CA-REC-5003", "diagnosis": "Migraine"},
}
PRESCRIPTIONS = {
    "7001": {"owner": "pat_alice", "secret": "AL-RX-7001", "drug": "Lisinopril"},
    "7002": {"owner": "pat_bob",   "secret": "BO-RX-7002", "drug": "Albuterol"},
    "7003": {"owner": "pat_carol", "secret": "CA-RX-7003", "drug": "Sumatriptan"},
}
LABS = {
    "9001": {"owner": "pat_alice", "secret": "AL-LAB-9001", "panel": "Lipid"},
    "9002": {"owner": "pat_bob",   "secret": "BO-LAB-9002", "panel": "Spirometry"},
    "9003": {"owner": "pat_carol", "secret": "CA-LAB-9003", "panel": "MRI"},
}

# trap resources (ownership enforced in the handlers)
APPOINTMENTS = {
    "3001": {"owner": "pat_alice", "secret": "AL-APT-3001", "when": "2026-11-02"},
    "3002": {"owner": "pat_bob",   "secret": "BO-APT-3002", "when": "2026-11-05"},
    "3003": {"owner": "pat_carol", "secret": "CA-APT-3003", "when": "2026-11-09"},
}
BILLING = {
    "4001": {"owner": "pat_alice", "secret": "AL-BILL-4001", "amount": 240.0},
    "4002": {"owner": "pat_bob",   "secret": "BO-BILL-4002", "amount": 90.0},
    "4003": {"owner": "pat_carol", "secret": "CA-BILL-4003", "amount": 510.0},
}
MESSAGES = {
    "6001": {"owner": "pat_alice", "secret": "AL-MSG-6001", "body": "lab ready"},
    "6002": {"owner": "pat_bob",   "secret": "BO-MSG-6002", "body": "refill ok"},
    "6003": {"owner": "pat_carol", "secret": "CA-MSG-6003", "body": "see you soon"},
}

# safe: public, no owner boundary
ANNOUNCEMENTS = {
    "ann_a": {"secret": "PUB-ANN-A", "title": "Flu shots available"},
    "ann_b": {"secret": "PUB-ANN-B", "title": "Portal maintenance Sunday"},
}
