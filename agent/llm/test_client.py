"""LLM client self-checks — offline, via an injected transport (no API call, no spend)."""
from types import SimpleNamespace

from agent.llm.client import LLM


def _fake(content):
    captured = {}

    def create(**kw):
        captured.update(kw)
        return SimpleNamespace(choices=[SimpleNamespace(message=SimpleNamespace(content=content))])

    return create, captured


def test_chat_wires_model_messages_and_determinism():
    create, captured = _fake("pong")
    out = LLM(create=create).chat("be terse", "ping")
    assert out == "pong"
    assert captured["model"]  # resolved from env/default (deepseek-flash)
    assert captured["messages"][0] == {"role": "system", "content": "be terse"}
    assert captured["messages"][1] == {"role": "user", "content": "ping"}
    assert captured["temperature"] == 0
    assert "response_format" not in captured


def test_json_mode_requests_json_object():
    create, captured = _fake("{}")
    LLM(create=create).chat("s", "u", json_mode=True)
    assert captured["response_format"] == {"type": "json_object"}
