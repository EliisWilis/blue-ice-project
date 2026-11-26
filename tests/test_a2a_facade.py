from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest

from aegis.app import create_app
from aegis.config import Settings


class ProviderResponse:
    status_code = 200
    headers = {"content-type": "application/json", "content-length": "200"}

    def json(self):
        return {
            "id": "chatcmpl-a2a",
            "object": "chat.completion",
            "created": 1,
            "model": "test-model",
            "choices": [
                {
                    "index": 0,
                    "message": {"role": "assistant", "content": "Delegated answer"},
                    "finish_reason": "stop",
                }
            ],
        }


class Provider:
    def __init__(self):
        self.calls = []

    async def post(self, url, **kwargs):
        self.calls.append((url, kwargs))
        return ProviderResponse()


@pytest.fixture
async def a2a_settings(tmp_path: Path) -> Settings:
    (tmp_path / ".privacyignore").write_text(".env\n", encoding="utf-8")
    token = "local-a2a-token-with-at-least-thirty-two-characters"
    token_path = tmp_path / "token"
    token_path.write_text(token, encoding="ascii")
    token_path.chmod(0o600)
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
        token_path=token_path,
        require_local_auth=True,
        key_source="env",
        registry_checks=False,
        llm_guard_enabled=False,
        custom_provider_urls=(),
        custom_models_urls=(),
        custom_responses_urls=(),
        a2a_enabled=True,
    )


@pytest.mark.asyncio
async def test_a2a_agent_card_uses_cli_base_url_and_disables_unimplemented_capabilities(
    a2a_settings,
):
    app = create_app(a2a_settings, http_client=Provider(), a2a_base_url="http://127.0.0.1:9081")
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get("/.well-known/agent-card.json")

    assert response.status_code == 200
    card = response.json()
    assert card["name"] == "Blue Ice Project"
    assert card["supportedInterfaces"][0]["url"] == "http://127.0.0.1:9081/a2a"
    assert card["capabilities"]["streaming"] is False
    assert card["capabilities"]["pushNotifications"] is False
    assert card["defaultInputModes"] == ["text/plain"]


@pytest.mark.asyncio
async def test_a2a_auth_covers_rpc_path_and_trailing_slash_before_dispatch(a2a_settings):
    provider = Provider()
    app = create_app(a2a_settings, http_client=provider)
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        plain = await client.post("/a2a", json={})
        slash = await client.post("/a2a/", json={})

    assert plain.status_code == 401
    assert slash.status_code == 401
    assert provider.calls == []


@pytest.mark.asyncio
async def test_a2a_jsonrpc_delegates_text_through_gateway_and_keeps_credentials_separate(
    a2a_settings, monkeypatch
):
    monkeypatch.setenv("AEGIS_GROQ_API_KEY", "upstream-groq-key")
    local_token = a2a_settings.token_path.read_text(encoding="ascii").strip()
    provider = Provider()
    app = create_app(a2a_settings, http_client=provider)
    app.state.http_client = provider
    transport = httpx.ASGITransport(app=app)
    message = {
        "messageId": "msg-local-1",
        "role": "ROLE_USER",
        "parts": [{"text": "Explain this error without running commands."}],
    }
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.post(
            "/a2a",
            json={
                "jsonrpc": "2.0",
                "id": "req-1",
                "method": "SendMessage",
                "params": {"message": message},
            },
            headers={"Authorization": f"Bearer {local_token}", "A2A-Version": "1.0"},
        )

    assert response.status_code == 200, response.text
    assert provider.calls, response.text
    upstream_url, kwargs = provider.calls[0]
    assert upstream_url == "https://api.groq.com/openai/v1/chat/completions"
    assert kwargs["headers"]["Authorization"] == "Bearer upstream-groq-key"
    assert local_token not in json.dumps(kwargs["headers"])
    assert (
        kwargs["json"]["messages"][0]["content"] == "Explain this error without running commands."
    )
    audit = a2a_settings.audit_path.read_text(encoding="utf-8")
    assert '"event":"a2a_request"' in audit
    assert "Explain this error" not in audit
    assert "upstream-groq-key" not in audit


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("host", "expected_url"),
    [("127.0.0.1", "http://127.0.0.1:9099/a2a"), ("::1", "http://[::1]:9099/a2a")],
)
async def test_cli_start_advertises_selected_loopback_port(
    a2a_settings, monkeypatch, host: str, expected_url: str
):
    import uvicorn

    from aegis.cli import start_command

    captured = {}
    monkeypatch.setattr("aegis.cli.load_settings", lambda _config: a2a_settings)
    monkeypatch.setattr(
        uvicorn,
        "run",
        lambda app, **kwargs: captured.update(app=app, kwargs=kwargs),
    )

    start_command(host=host, port=9099, config=None)

    assert captured["kwargs"]["host"] == host
    assert captured["kwargs"]["port"] == 9099
    transport = httpx.ASGITransport(app=captured["app"])
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        card_response = await client.get("/.well-known/agent-card.json")
    assert card_response.status_code == 200
    assert card_response.json()["supportedInterfaces"][0]["url"] == expected_url
