from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import httpx
import pytest

from aegis.app import create_app
from aegis.config import Settings
from aegis.mcp_server import handle_request


def make_settings(tmp_path: Path, *, require_local_auth: bool = False) -> Settings:
    root = tmp_path / "project"
    root.mkdir()
    (root / "skills" / "demo-skill").mkdir(parents=True)
    (root / "skills" / "demo-skill" / "SKILL.md").write_text(
        "---\nname: demo-skill\ndescription: Demo test skill\n---\nUse safely.\n",
        encoding="utf-8",
    )
    token = tmp_path / "token"
    token.write_text("t" * 40, encoding="ascii")
    token.chmod(0o600)
    return Settings(
        config_path=tmp_path / "config.yaml",
        project_root=root,
        provider="ollama",
        model="llama3.2",
        allowed_domains=(),
        privacyignore_rules=(".env", "*.key", "**/.env"),
        max_request_bytes=16_384,
        max_response_bytes=1_000_000,
        audit_path=tmp_path / "audit.jsonl",
        token_path=token,
        require_local_auth=require_local_auth,
        key_source="env",
        registry_checks=False,
        llm_guard_enabled=False,
        custom_provider_urls=(),
        custom_models_urls=(),
        custom_responses_urls=(),
    )


async def post_mcp(app: Any, payload: Any, headers: dict[str, str] | None = None) -> httpx.Response:
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        return await client.post("/mcp", json=payload, headers=headers or {})


@pytest.mark.asyncio
async def test_mcp_initialize_and_tools_are_read_only(tmp_path: Path) -> None:
    settings = make_settings(tmp_path)
    initialized = await handle_request(
        settings, {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}
    )
    assert initialized is not None
    assert initialized["result"]["serverInfo"]["name"] == "blue-ice"
    listed = await handle_request(settings, {"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
    assert listed is not None
    names = {tool["name"] for tool in listed["result"]["tools"]}
    assert "blue_ice_get_capabilities" in names
    assert "blue_ice_run_security_check" in names
    assert "run_command" not in names
    assert "execute_shell" not in names


@pytest.mark.asyncio
async def test_mcp_tools_boundaries_and_audit_are_safe(tmp_path: Path) -> None:
    settings = make_settings(tmp_path)
    skill = await handle_request(
        settings,
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": "blue_ice_read_skill", "arguments": {"name": "demo-skill"}},
        },
    )
    assert skill is not None
    assert "Use safely" in skill["result"]["content"][0]["text"]
    outside = await handle_request(
        settings,
        {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {
                "name": "blue_ice_check_project_path",
                "arguments": {"path": "../secret"},
            },
        },
    )
    assert outside is not None
    assert outside["result"]["structuredContent"]["allowed"] is False
    ignored = await handle_request(
        settings,
        {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {
                "name": "blue_ice_check_project_path",
                "arguments": {"path": ".env"},
            },
        },
    )
    assert ignored is not None
    assert ignored["result"]["structuredContent"]["allowed"] is False
    listed = await handle_request(
        settings,
        {
            "jsonrpc": "2.0",
            "id": 4,
            "method": "tools/call",
            "params": {"name": "blue_ice_read_audit", "arguments": {"limit": 20}},
        },
    )
    assert listed is not None
    assert "events" in listed["result"]["structuredContent"]
    assert "api_key" not in json.dumps(listed)


@pytest.mark.asyncio
async def test_mcp_notifications_and_invalid_requests(tmp_path: Path) -> None:
    settings = make_settings(tmp_path)
    assert (
        await handle_request(settings, {"jsonrpc": "2.0", "method": "notifications/initialized"})
        is None
    )
    invalid = await handle_request(settings, {"jsonrpc": "1.0", "id": 1, "method": "ping"})
    assert invalid is not None and invalid["error"]["code"] == -32600
    unknown = await handle_request(settings, {"jsonrpc": "2.0", "id": 2, "method": "unknown"})
    assert unknown is not None and unknown["error"]["code"] == -32601
    bad_tool = await handle_request(
        settings,
        {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {"name": "not_a_tool", "arguments": {}},
        },
    )
    assert bad_tool is not None and bad_tool["error"]["code"] == -32602


@pytest.mark.asyncio
async def test_mcp_http_requires_local_token(tmp_path: Path) -> None:
    settings = make_settings(tmp_path, require_local_auth=True)
    app = create_app(settings, http_client=object())
    denied = await post_mcp(app, {"jsonrpc": "2.0", "id": 1, "method": "ping"})
    assert denied.status_code == 401
    allowed = await post_mcp(
        app,
        {"jsonrpc": "2.0", "id": 1, "method": "ping"},
        {"Authorization": "Bearer " + "t" * 40},
    )
    assert allowed.status_code == 200
    assert allowed.json()["result"] == {}


@pytest.mark.asyncio
async def test_mcp_http_rejects_oversized_payload(tmp_path: Path) -> None:
    settings = make_settings(tmp_path, require_local_auth=False)
    app = create_app(settings, http_client=object())
    response = await post_mcp(
        app,
        {"jsonrpc": "2.0", "id": 1, "method": "ping", "padding": "x" * 20_000},
    )
    assert response.status_code == 413
