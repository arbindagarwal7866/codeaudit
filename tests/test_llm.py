"""The HTTP client against fake servers that speak the real Anthropic / OpenAI wire formats."""
import pytest

from codeaudit.agents.llm import LLM, LLMError, parse_json, extract_code, detect_provider


def test_anthropic_wire_format(fake_llm_server, tmp_path):
    llm = LLM("anthropic", base_url=fake_llm_server.url, api_key="sk-test", cache_dir=str(tmp_path))
    rep = llm.chat("You are a software architect.", [{"role": "user", "content": "hi"}])
    req = fake_llm_server.requests[-1]
    assert req["path"] == "/v1/messages"
    assert req["headers"]["x-api-key"] == "sk-test" and req["headers"]["anthropic-version"] == "2023-06-01"
    assert req["body"]["model"] == "claude-haiku-5-5" and req["body"]["system"]
    assert "refactorable" in rep.text and "hmm" not in rep.text               # thinking block skipped
    assert rep.raw[0]["type"] == "thinking"                                    # but kept for multi-turn
    assert llm.usage()["input_tokens"] == 100


def test_openai_compatible_wire_format(fake_llm_server, tmp_path):
    llm = LLM("openai", model="my-model", base_url=fake_llm_server.url, api_key="k", cache_dir=str(tmp_path))
    out = llm.ask_json("You are a software architect.", "x")
    req = fake_llm_server.requests[-1]
    assert req["path"] == "/v1/chat/completions" and req["headers"]["authorization"] == "Bearer k"
    assert req["body"]["messages"][0]["role"] == "system" and req["body"]["model"] == "my-model"
    assert out["fix_plan"] == ["do the fix"]


def test_cache_makes_reruns_free(fake_llm_server, tmp_path):
    llm = LLM("ollama", base_url=fake_llm_server.url, cache_dir=str(tmp_path))
    llm.ask("You are a software architect.", "same")
    llm.ask("You are a software architect.", "same")
    assert llm.calls == 1 and llm.cache_hits == 1


def test_http_errors_raise_without_endless_retries(fake_llm_server, tmp_path):
    fake_llm_server.fail_with = 401
    llm = LLM("anthropic", base_url=fake_llm_server.url, api_key="bad", cache_dir=str(tmp_path), retry_wait=0)
    with pytest.raises(LLMError, match="401"):
        llm.ask("s", "u")
    assert len(fake_llm_server.requests) == 1                                  # 401 is not retried


def test_missing_key_is_a_clear_error(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    with pytest.raises(LLMError, match="ANTHROPIC_API_KEY"):
        LLM("anthropic")


def test_auto_falls_back_to_offline(monkeypatch):
    for k in ("ANTHROPIC_API_KEY", "OPENAI_API_KEY", "GEMINI_API_KEY", "GOOGLE_API_KEY", "GROQ_API_KEY",
              "OPENROUTER_API_KEY"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("OLLAMA_HOST", "http://127.0.0.1:9")                    # nothing listens there
    assert detect_provider() == "offline"
    assert LLM("auto").offline


def test_json_and_code_extraction_are_robust():
    assert parse_json('```json\n{"a": 1}\n```') == {"a": 1}
    assert parse_json('Sure! {"a": {"b": "}"}} hope that helps') == {"a": {"b": "}"}}
    assert extract_code("text\n```python\nx = 1\n```\nmore") == "x = 1\n"
    assert extract_code("no code here") is None
