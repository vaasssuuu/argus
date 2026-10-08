"""Provider-agnostic LLM call site.

DeepSeek, OpenAI and Gemini all speak the OpenAI API, so switching providers is config, not
code: pick a provider and the client uses that provider's base URL, default model, and key env
var. Override the model with ARGUS_MODEL (or the CLI's --model). The LLM only ever *proposes*
(candidates, PoCs, remediation); it never renders a verdict (that's the oracle). Temperature 0
keeps proposals, and the captured traces, reproducible.
"""
import os
from pathlib import Path

from openai import OpenAI

ENV_FILE = Path(__file__).resolve().parents[2] / ".env"

# provider -> OpenAI-compatible endpoint, a safe default model, and the key env var.
PROVIDERS = {
    "deepseek": {"base_url": "https://api.deepseek.com",
                 "model": "deepseek-flash", "key_env": "DEEPSEEK_API_KEY"},
    "openai":   {"base_url": "https://api.openai.com/v1",
                 "model": "gpt-4o-mini", "key_env": "OPENAI_API_KEY"},
    "gemini":   {"base_url": "https://generativelanguage.googleapis.com/v1beta/openai/",
                 "model": "gemini-2.0-flash", "key_env": "GEMINI_API_KEY"},
}


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
    def __init__(self, provider=None, model=None, create=None):
        _load_env()
        provider = provider or os.environ.get("ARGUS_PROVIDER", "deepseek")
        if provider not in PROVIDERS:
            raise ValueError(f"unknown provider '{provider}'; choose from {list(PROVIDERS)}")
        cfg = PROVIDERS[provider]
        self.provider = provider
        self.model = model or os.environ.get("ARGUS_MODEL") or cfg["model"]
        # `create` is injectable so tests (and a future provider) avoid a live call.
        if create is None:
            api_key = os.environ.get(cfg["key_env"])
            if not api_key:
                raise RuntimeError(f"missing {cfg['key_env']} for provider '{provider}' "
                                   f"(set it in .env or the environment)")
            client = OpenAI(api_key=api_key,
                            base_url=os.environ.get("ARGUS_BASE_URL", cfg["base_url"]))
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
