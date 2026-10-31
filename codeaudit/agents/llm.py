"""One small client for every LLM provider, using only the standard library (urllib).

  anthropic   Claude Messages API             ANTHROPIC_API_KEY
  openai      OpenAI Chat Completions         OPENAI_API_KEY   (+ OPENAI_BASE_URL for any compatible server)
  gemini      Google Gemini (OpenAI-compatible endpoint)   GEMINI_API_KEY
  groq        Groq (OpenAI-compatible)        GROQ_API_KEY
  openrouter  OpenRouter (OpenAI-compatible)  OPENROUTER_API_KEY
  ollama      local models, no key            OLLAMA_HOST (default http://localhost:11434)
  offline     no LLM: deterministic heuristic agents
  auto        first of the above that is configured, else offline

Answers are cached on disk (same prompt -> same answer): re-runs are free and demos are repeatable.
"""
from __future__ import annotations
import hashlib
import json
import os
import re
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path

PROVIDERS = {
    "anthropic": {"style": "anthropic", "base": "https://api.anthropic.com/v1", "key_env": "ANTHROPIC_API_KEY",
                  "fast": "claude-haiku-5-5", "smart": "claude-sonnet-5-5"},
    "openai": {"style": "openai", "base": "https://api.openai.com/v1", "key_env": "OPENAI_API_KEY",
               "fast": "gpt-4.1-mini", "smart": "gpt-4.1"},
    "gemini": {"style": "openai", "base": "https://generativelanguage.googleapis.com/v1beta/openai",
               "key_env": "GEMINI_API_KEY", "fast": "gemini-2.5-flash", "smart": "gemini-2.5-pro"},
    "groq": {"style": "openai", "base": "https://api.groq.com/openai/v1", "key_env": "GROQ_API_KEY",
             "fast": "llama-3.3-70b-versatile", "smart": "llama-3.3-70b-versatile"},
    "openrouter": {"style": "openai", "base": "https://openrouter.ai/api/v1", "key_env": "OPENROUTER_API_KEY",
                   "fast": "anthropic/claude-haiku-5-5", "smart": "anthropic/claude-sonnet-5-5"},
    "ollama": {"style": "openai", "base": None, "key_env": None,
               "fast": "qwen2.5-coder:7b", "smart": "qwen2.5-coder:7b"},
    "offline": {"style": "offline"},
}


class LLMError(RuntimeError):
    pass


@dataclass
class Reply:
    text: str
    raw: object          # provider-native assistant content (kept intact for multi-turn)


def _ollama_base() -> str:
    host = os.getenv("OLLAMA_HOST", "http://localhost:11434").rstrip("/")
    if not host.startswith("http"):
        host = "http://" + host
    return host + "/v1"


def _ollama_models(timeout: float = 0.6) -> list[str]:
    try:
        url = _ollama_base()[:-3] + "/api/tags"
        with urllib.request.urlopen(url, timeout=timeout) as r:
            return [m["name"] for m in json.loads(r.read()).get("models", [])]
    except Exception:
        return []


def detect_provider() -> str:
    for name in ("anthropic", "openai", "gemini", "groq", "openrouter"):
        env = PROVIDERS[name]["key_env"]
        if os.getenv(env) or (name == "gemini" and os.getenv("GOOGLE_API_KEY")):
            return name
    if _ollama_models():
        return "ollama"
    return "offline"


def available_providers() -> list[dict]:
    rows = []
    for name, p in PROVIDERS.items():
        if name == "offline":
            ok, note = True, "always available (heuristic agents)"
        elif name == "ollama":
            models = _ollama_models()
            ok, note = bool(models), (f"models: {', '.join(models[:4])}" if models else "not running")
        else:
            ok = bool(os.getenv(p["key_env"]) or (name == "gemini" and os.getenv("GOOGLE_API_KEY")))
            note = f"{p['key_env']} {'set' if ok else 'not set'}"
        rows.append({"name": name, "available": ok, "note": note,
                     "fast": p.get("fast"), "smart": p.get("smart")})
    return rows


class LLM:
    def __init__(self, provider: str = "auto", model: str | None = None, smart_model: str | None = None,
                 base_url: str | None = None, api_key: str | None = None,
                 cache_dir: str | None = None, timeout: int = 120, use_cache: bool = True,
                 retry_wait: float = 1.5):
        provider = (provider or "auto").lower()
        if provider == "auto":
            provider = detect_provider()
        if provider not in PROVIDERS:
            raise LLMError(f"unknown provider '{provider}'. Choose: {', '.join(PROVIDERS)}, auto")
        self.provider = provider
        cfg = PROVIDERS[provider]
        self.style = cfg["style"]
        self.offline = self.style == "offline"
        self.calls = self.cache_hits = self.input_tokens = self.output_tokens = self.errors = 0
        self.timeout = timeout
        self.retry_wait = retry_wait
        self.use_cache = use_cache
        self.cache_dir = Path(cache_dir or os.getenv("CODEAUDIT_CACHE", ".codeaudit_cache"))
        if self.offline:
            self.model = self.smart_model = "heuristic"
            return
        env_model = os.getenv("CODEAUDIT_MODEL")
        self.model = model or env_model or cfg["fast"]
        self.smart_model = smart_model or os.getenv("CODEAUDIT_SMART_MODEL") or model or env_model or cfg["smart"]
        if provider == "ollama":
            self.base = (base_url or _ollama_base()).rstrip("/")
            self.api_key = api_key or "ollama"
            have = _ollama_models()
            if have and self.model not in have and not (model or env_model):
                self.model = self.smart_model = have[0]          # use whatever model is pulled
        else:
            self.base = (base_url or os.getenv(f"{provider.upper()}_BASE_URL") or cfg["base"]).rstrip("/")
            self.api_key = api_key or os.getenv(cfg["key_env"]) or (
                os.getenv("GOOGLE_API_KEY") if provider == "gemini" else None)
            if not self.api_key:
                raise LLMError(f"{cfg['key_env']} is not set")

    @property
    def label(self) -> str:
        return "offline (heuristic agents)" if self.offline else f"{self.provider} · {self.model}"

    # ------------------------------------------------------------------ http
    def _post(self, url: str, headers: dict, body: dict) -> dict:
        data = json.dumps(body).encode()
        last = None
        for attempt in range(3):
            req = urllib.request.Request(url, data=data, method="POST",
                                         headers={"content-type": "application/json", **headers})
            try:
                with urllib.request.urlopen(req, timeout=self.timeout) as r:
                    return json.loads(r.read())
            except urllib.error.HTTPError as e:
                msg = e.read().decode(errors="replace")[:400]
                last = LLMError(f"HTTP {e.code} from {self.provider}: {msg}")
                if e.code == 400 and "max_tokens" in msg and "max_completion_tokens" in msg:
                    body["max_completion_tokens"] = body.pop("max_tokens", 2000)
                    data = json.dumps(body).encode()
                    continue
                if e.code not in (408, 409, 429, 500, 502, 503, 504, 529):
                    raise last
            except (urllib.error.URLError, TimeoutError, ConnectionError) as e:
                last = LLMError(f"cannot reach {self.provider} at {url}: {e}")
            time.sleep(self.retry_wait * (attempt + 1))
        raise last

    def _call(self, system: str, messages: list[dict], model: str, max_tokens: int) -> Reply:
        if self.style == "anthropic":
            out = self._post(f"{self.base}/messages",
                             {"x-api-key": self.api_key, "anthropic-version": "2023-06-01"},
                             {"model": model, "max_tokens": max_tokens, "system": system,
                              "messages": messages})
            blocks = out.get("content", [])
            text = "".join(b.get("text", "") for b in blocks if b.get("type") == "text")
            u = out.get("usage", {})
            self.input_tokens += u.get("input_tokens", 0) or 0
            self.output_tokens += u.get("output_tokens", 0) or 0
            return Reply(text, blocks)
        msgs = [{"role": "system", "content": system}] + [
            {"role": m["role"], "content": m["content"] if isinstance(m["content"], str)
             else "".join(b.get("text", "") for b in m["content"] if isinstance(b, dict))}
            for m in messages]
        out = self._post(f"{self.base}/chat/completions", {"authorization": f"Bearer {self.api_key}"},
                         {"model": model, "messages": msgs, "max_tokens": max_tokens})
        try:
            text = out["choices"][0]["message"].get("content") or ""
        except (KeyError, IndexError):
            raise LLMError(f"unexpected response from {self.provider}: {str(out)[:300]}")
        u = out.get("usage") or {}
        self.input_tokens += u.get("prompt_tokens", 0) or 0
        self.output_tokens += u.get("completion_tokens", 0) or 0
        text = re.sub(r"<think>.*?</think>", "", text, flags=re.S)       # reasoning models (deepseek/qwq)
        return Reply(text, text)

    # ------------------------------------------------------------------ public
    def chat(self, system: str, messages: list[dict], smart: bool = False, max_tokens: int = 4000) -> Reply:
        if self.offline:
            raise LLMError("offline mode has no LLM")
        model = self.smart_model if smart else self.model
        key = hashlib.sha256(json.dumps([self.provider, model, system, messages], sort_keys=True,
                                        default=str).encode()).hexdigest()[:32]
        path = self.cache_dir / f"{key}.json"
        if self.use_cache and path.exists():
            self.cache_hits += 1
            d = json.loads(path.read_text(encoding="utf-8"))
            return Reply(d["text"], d["raw"])
        try:
            rep = self._call(system, messages, model, max_tokens)
        except LLMError:
            self.errors += 1
            raise
        self.calls += 1
        if self.use_cache:
            self.cache_dir.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps({"model": model, "text": rep.text, "raw": rep.raw}), encoding="utf-8")
        return rep

    def ask(self, system: str, user: str, smart: bool = False, max_tokens: int = 4000) -> str:
        return self.chat(system, [{"role": "user", "content": user}], smart, max_tokens).text

    def ask_json(self, system: str, user: str, smart: bool = False, max_tokens: int = 4000) -> dict:
        sys_j = system + "\n\nRespond with ONLY one JSON object. No prose before or after it."
        text = self.ask(sys_j, user, smart, max_tokens)
        try:
            return parse_json(text)
        except (ValueError, json.JSONDecodeError):
            fix = self.chat(sys_j, [{"role": "user", "content": user},
                                    {"role": "assistant", "content": text},
                                    {"role": "user", "content": "That was not valid JSON. Reply with only the JSON object."}],
                            smart, max_tokens).text
            return parse_json(fix)

    def usage(self) -> dict:
        return {"provider": self.provider, "model": self.model, "smart_model": self.smart_model,
                "api_calls": self.calls, "cache_hits": self.cache_hits, "errors": self.errors,
                "input_tokens": self.input_tokens, "output_tokens": self.output_tokens}


def parse_json(text: str) -> dict:
    text = re.sub(r"^```(?:json)?\s*|\s*```$", "", text.strip())
    try:
        out = json.loads(text)
        if isinstance(out, dict):
            return out
    except json.JSONDecodeError:
        pass
    start = text.find("{")
    while start != -1:                                   # first balanced {...} that parses
        depth, in_str, esc = 0, False, False
        for i in range(start, len(text)):
            ch = text[i]
            if in_str:
                if esc:
                    esc = False
                elif ch == "\\":
                    esc = True
                elif ch == '"':
                    in_str = False
                continue
            if ch == '"':
                in_str = True
            elif ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    try:
                        return json.loads(text[start:i + 1])
                    except json.JSONDecodeError:
                        break
        start = text.find("{", start + 1)
    raise ValueError(f"no JSON object in model reply: {text[:200]!r}")


def extract_code(text: str) -> str | None:
    blocks = re.findall(r"```(?:python|py)?[ \t]*\n(.*?)```", text, re.S)
    if not blocks:
        return None
    return max(blocks, key=len).rstrip() + "\n"
