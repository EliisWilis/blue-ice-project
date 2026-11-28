from __future__ import annotations

from pathlib import Path

import httpx
import pytest

from aegis.app import create_app
from aegis.config import Settings


class FakeResponse:
    status_code = 200
    headers = {"content-length": "128"}

    def json(self):
        return {
            "id": "chatcmpl-test",
            "object": "chat.completion",
            "created": 1,
            "model": "test-model",
            "choices": [
                {
                    "index": 0,
                    "message": {"role": "assistant", "content": "Returned __AEGIS_SEC_001__"},
                    "finish_reason": "stop",
                }
            ],
        }


class FakeProvider:
    def __init__(self):
        self.calls = []

    async def post(self, url, **kwargs):
        self.calls.append((url, kwargs))
        return FakeResponse()


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    (tmp_path / ".privacyignore").write_text(".env\n", encoding="utf-8")
    return Settings(
        config_path=tmp_path / "config.yaml",
        project_root=tmp_path,
        provider="groq",
        model="test-model",
        allowed_domains=(),
        privacyignore_rules=(".env", "**/.env"),
        max_request_bytes=16_384,
        max_response_bytes=1_000_000,
        audit_path=tmp_path / "audit.jsonl",
        token_path=tmp_path / "token",
        require_local_auth=False,
        key_source="env",
        registry_checks=False,
        llm_guard_enabled=False,
        custom_provider_urls=(),
        custom_models_urls=(),
        custom_responses_urls=(),
    )


@pytest.mark.asyncio
async def test_anthropic_messages_endpoint_translates_through_gateway(settings, monkeypatch):
    monkeypatch.setenv("AEGIS_GROQ_API_KEY", "groq-test-key")
    provider = FakeProvider()
    app = create_app(settings, http_client=provider)
    app.state.http_client = provider
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.post(
            "/v1/messages",
            json={
                "model": "claude-test",
                "max_tokens": 20,
                "messages": [{"role": "user", "content": "Hello"}],
            },
        )
    assert response.status_code == 200
    assert response.json()["type"] == "message"
    assert response.json()["content"][0]["text"] == "Returned __AEGIS_SEC_001__"
    assert provider.calls[0][1]["json"]["messages"][0]["role"] == "user"


@pytest.mark.asyncio
async def test_gemini_generate_content_endpoint_translates_through_gateway(settings, monkeypatch):
    monkeypatch.setenv("AEGIS_GROQ_API_KEY", "groq-test-key")
    provider = FakeProvider()
    app = create_app(settings, http_client=provider)
    app.state.http_client = provider
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.post(
            "/v1beta/models/gemini-test:generateContent",
            json={"contents": [{"role": "user", "parts": [{"text": "Hello"}]}]},
        )
    assert response.status_code == 200
    assert response.json()["candidates"][0]["content"]["parts"]
    assert provider.calls[0][1]["json"]["model"] == "gemini-test"


@pytest.mark.asyncio
async def test_anthropic_messages_endpoint_replays_buffered_sse(settings, monkeypatch):
    monkeypatch.setenv("AEGIS_GROQ_API_KEY", "groq-test-key")
    provider = FakeProvider()
    app = create_app(settings, http_client=provider)
    app.state.http_client = provider
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.post(
            "/v1/messages",
            json={
                "model": "claude-test",
                "stream": True,
                "max_tokens": 20,
                "messages": [{"role": "user", "content": "Hello"}],
            },
        )
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/event-stream")
    assert "event: message_start" in response.text
    assert "event: message_stop" in response.text
