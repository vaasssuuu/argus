"""Docker preflight: `scan` must fail with a clear, human message (not a stack trace)
when Docker is missing, the daemon is down, or a required image isn't present locally."""
import pytest

from runner import docker_runner as dr


class _Done:
    def __init__(self, rc): self.returncode = rc


def test_daemon_down_raises_friendly(monkeypatch):
    monkeypatch.setattr(dr, "_run", lambda args: _Done(1))
    with pytest.raises(dr.DockerUnavailable) as e:
        dr.ensure_docker()
    assert "not running" in str(e.value)


def test_not_installed_raises_friendly(monkeypatch):
    def missing(args): raise FileNotFoundError
    monkeypatch.setattr(dr, "_run", missing)
    with pytest.raises(dr.DockerUnavailable) as e:
        dr.ensure_docker()
    assert "not found" in str(e.value)


def test_docker_ok_does_not_raise(monkeypatch):
    monkeypatch.setattr(dr, "_run", lambda args: _Done(0))
    dr.ensure_docker()  # must not raise


def test_missing_image_raises_friendly(monkeypatch):
    monkeypatch.setattr(dr, "_run", lambda args: _Done(1))
    with pytest.raises(dr.DockerUnavailable) as e:
        dr.ensure_image("ghost:latest")
    assert "ghost:latest" in str(e.value)
