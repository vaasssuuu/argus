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


class DockerUnavailable(RuntimeError):
    """Docker can't be used: not installed, the daemon is down, or a needed image is missing.

    Carries a message meant to be shown to the user as-is (not a stack trace)."""


def ensure_docker() -> None:
    """Fail early with a human-readable message if the Docker daemon isn't reachable."""
    try:
        reachable = _run(["docker", "info"]).returncode == 0
    except FileNotFoundError:
        raise DockerUnavailable(
            "Docker does not appear to be installed (the `docker` command was not found).\n"
            "Install Docker Desktop (https://docs.docker.com/get-docker/), start it, then retry.\n"
            "Tip: `argus eval` runs the benchmark with no Docker and no API key.")
    if not reachable:
        raise DockerUnavailable(
            "Docker is installed but not running (could not reach the Docker daemon).\n"
            "Start Docker Desktop, wait until it reports 'running', then retry.\n"
            "Tip: `argus eval` runs the benchmark with no Docker and no API key.")


def ensure_image(image: str) -> None:
    """Fail early with a human-readable message if a required local image is missing."""
    if _run(["docker", "image", "inspect", image]).returncode != 0:
        raise DockerUnavailable(
            f"Docker image '{image}' was not found locally.\n"
            f"Build or pull it first (e.g. `docker build -t {image} .`), then retry.")


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


def _docker_build(dockerfile, image, ctx) -> None:
    _run(["docker", "build", "-f", str(dockerfile), "-t", image, str(ctx)]).check_returncode()


def build_images() -> None:
    """Build the bundled target + the runner image (used by the self-check / bundled scan)."""
    ensure_docker()
    ctx = _build_context()
    try:
        _docker_build(ctx / "target" / "Dockerfile", TARGET_IMAGE, ctx)
        _docker_build(ctx / "runner" / "sandbox.Dockerfile", egress.RUNNER_IMAGE, ctx)
    finally:
        shutil.rmtree(ctx, ignore_errors=True)


class DockerRunner:
    """Context manager: brings the sandbox up on enter, tears the target down on exit.

    Defaults to the bundled target. For a user's own app, pass `target_image` (an image that
    already exists locally) + the `target_port` it listens on, with `build_target=False` to skip
    building the bundled app. Either way the target runs on the egress-locked internal network,
    so the sandbox can reach it and nothing else."""

    def __init__(self, target_image: str = TARGET_IMAGE, target_port: int = 5000,
                 build_target: bool = True):
        self.target_image = target_image
        self.target_port = target_port
        self.build_target = build_target
        self.target_base = f"http://{TARGET_NAME}:{target_port}"

    def __enter__(self):
        ensure_docker()
        if not self.build_target:          # user's own image must already exist locally
            ensure_image(self.target_image)
        ctx = _build_context()
        try:
            _docker_build(ctx / "runner" / "sandbox.Dockerfile", egress.RUNNER_IMAGE, ctx)
            if self.build_target:
                _docker_build(ctx / "target" / "Dockerfile", TARGET_IMAGE, ctx)
        finally:
            shutil.rmtree(ctx, ignore_errors=True)
        egress.ensure_network()
        _run(["docker", "rm", "-f", TARGET_NAME])  # clear any stale instance
        _run(["docker", "run", "-d", "--name", TARGET_NAME,
              "--network", egress.NETWORK, self.target_image]).check_returncode()
        self._wait_ready()
        return self

    def _wait_ready(self, tries=40) -> None:
        # Any HTTP response means the server is up (a user's app may have no /api/health).
        for _ in range(tries):
            try:
                if "status" in self.run_poc({"method": "GET", "path": "/"}):
                    return
            except Exception:
                pass
            time.sleep(0.5)
        raise RuntimeError("target did not become ready in the sandbox")

    def run_poc(self, poc: dict) -> dict:
        r = _run(["docker", "run", "--rm", "--network", egress.NETWORK,
                  "-e", "POC=" + json.dumps(poc),
                  "-e", "TARGET_BASE_URL=" + self.target_base,
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
