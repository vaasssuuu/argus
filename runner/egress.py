"""The egress guardrail — Argus's one security line that never bends.

The PoC sandbox must be able to reach ONLY the authorized target. We enforce that at the
network layer: a Docker network created `--internal` has no gateway to the host or the
internet. Membership in that network IS the allowlist — the target lives there, nothing else
does, and there is no route out. `egress_blocked()` proves it empirically by trying to reach
the public internet from inside the network and confirming the attempt fails.
"""
import subprocess

NETWORK = "argus-net"
RUNNER_IMAGE = "argus-runner"


def ensure_network() -> None:
    present = subprocess.run(["docker", "network", "inspect", NETWORK],
                             capture_output=True).returncode == 0
    if not present:
        subprocess.run(["docker", "network", "create", "--internal", NETWORK],
                       check=True, capture_output=True)


def remove_network() -> None:
    subprocess.run(["docker", "network", "rm", NETWORK], capture_output=True)


def egress_blocked() -> bool:
    """True when a container on NETWORK cannot reach the public internet (guardrail holds)."""
    r = subprocess.run(
        ["docker", "run", "--rm", "--network", NETWORK, RUNNER_IMAGE, "python", "-c",
         "import urllib.request; urllib.request.urlopen('https://example.com', timeout=8)"],
        capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=60,
    )
    return r.returncode != 0  # non-zero exit = the outbound call failed = egress denied
