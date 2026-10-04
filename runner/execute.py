"""Sandbox-side PoC executor — runs INSIDE the runner container.

That container is attached only to the internal Docker network, so the only host this can
reach is the authorized target. Reads the PoC from the POC env var, performs the request with
stdlib urllib (no deps -> tiny image), and prints {status, body} as JSON to stdout, where the
host-side runner reads it over Docker's control channel (not over the restricted network).
"""
import json
import os
import urllib.error
import urllib.request

poc = json.loads(os.environ["POC"])
url = os.environ.get("TARGET_BASE_URL", "http://argus-target:5000") + poc["path"]
req = urllib.request.Request(url, method=poc.get("method", "GET"), headers=poc.get("headers", {}))

try:
    with urllib.request.urlopen(req, timeout=10) as r:
        status, body = r.status, r.read().decode("utf-8", "replace")
except urllib.error.HTTPError as e:  # 4xx/5xx still carry a status + body we want
    status, body = e.code, e.read().decode("utf-8", "replace")

print(json.dumps({"status": status, "body": body}))
