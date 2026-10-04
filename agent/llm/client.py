"""Provider-agnostic LLM call site.

DeepSeek is OpenAI-compatible, so the "provider" is just a base_url + model string read from
the environment — swap providers by changing `.env`, never this code. The LLM only ever
*proposes* (candidates, PoCs, remediation text); it never renders a verdict (that's the
oracle). Temperature is 0 so proposals — and therefore captured traces — are reproducible.
"""
import os
from pathlib import Path

from openai import OpenAI

ENV_FILE = Path(__file__).resolve().parents[2] / ".env"


def _load_env(path=ENV_FILE) -> None:
    """Minimal .env loader (stdlib; no python-dotenv). Full-line `#` comments only."""
    if not path.exists():
        return
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        os.environ.setdefault(key.strip(), value.strip())


class LLM:
    def __init__(self, create=None):
        _load_env()
        self.model = os.environ.get("DEEPSEEK_MODEL", "deepseek-flash")
        # `create` is injectable so tests (and a future provider) avoid a live call.
        if create is None:
            client = OpenAI(
                api_key=os.environ["DEEPSEEK_API_KEY"],
                base_url=os.environ.get("DEEPSEEK_BASE_URL", "https://api.deepseek.com"),
            )
            create = lambda **kw: client.chat.completions.create(**kw)
        self._create = create

    def chat(self, system: str, user: str, json_mode: bool = False) -> str:
        kw = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "temperature": 0,
        }
        if json_mode:
            kw["response_format"] = {"type": "json_object"}
        return self._create(**kw).choices[0].message.content
