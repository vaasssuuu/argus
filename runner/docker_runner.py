"""Host-side runner. Orchestrates the sandbox: ensures the internal network, builds the two
images, starts the target on that network, and runs each PoC in a throwaway container attached
only to that network. The host reads results over Docker's control channel (stdout) — never
over the restricted network — so reaching the target is never in the agent's hands, only the
sandbox's.
"""
import json
import shutil
import subprocess
import tempfile
import time
from pathlib import Path

from runner import egress

TARGET_IMAGE = "argus-target"
TARGET_NAME = "argus-target"  # also the DNS name the sandbox uses on the network
TARGET_BASE = "http://argus-target:5000"


def _run(args):
    # utf-8/replace: docker build output isn't decodable as Windows cp1252 (the default).
    return subprocess.run(args, capture_output=True, text=True, encoding="utf-8", errors="replace")


def _build_context() -> Path:
    """Assemble a minimal Docker build context from the installed package files.

    Works both in-repo and when pip-installed: target/ and runner/ are located via their
    packages (not a repo root) and copied into a small temp dir, so the build context stays
    tiny instead of becoming the whole site-packages tree."""
    import runner
    import target

    ctx = Path(tempfile.mkdtemp(prefix="argus-ctx-"))
    shutil.copytree(Path(target.__file__).parent, ctx / "target",
                    ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "test_*.py"))
    runner_dir = Path(runner.__file__).parent
    (ctx / "runner").mkdir()
    shutil.copy(runner_dir / "execute.py", ctx / "runner" / "execute.py")
    shutil.copy(runner_dir / "sandbox.Dockerfile", ctx / "runner" / "sandbox.Dockerfile")
    return ctx


def build_images() -> None:
    ctx = _build_context()
    try:
        _run(["docker", "build", "-f", str(ctx / "target" / "Dockerfile"),
              "-t", TARGET_IMAGE, str(ctx)]).check_returncode()
        _run(["docker", "build", "-f", str(ctx / "runner" / "sandbox.Dockerfile"),
              "-t", egress.RUNNER_IMAGE, str(ctx)]).check_returncode()
    finally:
        shutil.rmtree(ctx, ignore_errors=True)


class DockerRunner:
    """Context manager: brings the sandbox up on enter, tears the target down on exit."""

    def __enter__(self):
        build_images()
        egress.ensure_network()
        _run(["docker", "rm", "-f", TARGET_NAME])  # clear any stale instance
        _run(["docker", "run", "-d", "--name", TARGET_NAME,
              "--network", egress.NETWORK, TARGET_IMAGE]).check_returncode()
        self._wait_ready()
        return self

    def _wait_ready(self, tries=30) -> None:
        for _ in range(tries):
            try:
                if self.run_poc({"method": "GET", "path": "/api/health"})["status"] == 200:
                    return
            except Exception:
                pass
            time.sleep(0.5)
        raise RuntimeError("target did not become ready in the sandbox")

    def run_poc(self, poc: dict) -> dict:
        r = _run(["docker", "run", "--rm", "--network", egress.NETWORK,
                  "-e", "POC=" + json.dumps(poc),
                  "-e", "TARGET_BASE_URL=" + TARGET_BASE,
                  egress.RUNNER_IMAGE, "python", "/app/execute.py"])
        r.check_returncode()
        return json.loads(r.stdout)

    def __exit__(self, *exc):
        _run(["docker", "rm", "-f", TARGET_NAME])


if __name__ == "__main__":
    # Self-check: proves the sandbox reaches the target, the IDOR fires, the trap holds, and
    # the egress guardrail blocks the open internet.
    alice = {"Authorization": "Bearer tok_alice_3f9a"}
    with DockerRunner() as r:
        print("egress blocked (guardrail holds):", egress.egress_blocked())
        print("IDOR  alice->bob invoice:", r.run_poc(
            {"method": "GET", "path": "/api/invoices/inv_2001", "headers": alice}))
        print("TRAP  alice->bob order:  ", r.run_poc(
            {"method": "GET", "path": "/api/orders/ord_2001", "headers": alice}))
