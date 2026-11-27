"""Read-only MCP server surface for Codex and other local coding agents."""

from __future__ import annotations

import asyncio
import json
import sys
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import Any

from aegis.audit import read_events
from aegis.config import Settings

_PROTOCOL_VERSION = "2025-06-18"
_SERVER_INFO = {"name": "blue-ice", "version": "0.1.0"}
_MAX_SKILL_BYTES = 64_000
_MAX_PATH_LENGTH = 512
ModelLister = Callable[[], Awaitable[list[dict[str, Any]]]]


def _result(request_id: Any, value: Any) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": request_id, "result": value}


def _error(request_id: Any, code: int, message: str) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": request_id, "error": {"code": code, "message": message}}


def _text_result(value: Any, structured: Any | None = None) -> dict[str, Any]:
    result: dict[str, Any] = {
        "content": [{"type": "text", "text": json.dumps(value, ensure_ascii=False)}]
    }
    if structured is not None:
        result["structuredContent"] = structured
    return result


def tool_definitions() -> list[dict[str, Any]]:
    return [
        {
            "name": "blue_ice_get_capabilities",
            "description": "Return Blue Ice APIs and security controls without credentials or content.",
            "inputSchema": {"type": "object", "additionalProperties": False},
        },
        {
            "name": "blue_ice_list_models",
            "description": "List models from the explicitly selected Blue Ice provider.",
            "inputSchema": {"type": "object", "additionalProperties": False},
        },
        {
            "name": "blue_ice_read_audit",
            "description": "Read bounded metadata-only audit records.",
            "inputSchema": {
                "type": "object",
                "properties": {"limit": {"type": "integer", "minimum": 1, "maximum": 100}},
                "additionalProperties": False,
            },
        },
        {
            "name": "blue_ice_list_skills",
            "description": "List installed Blue Ice, REA, and agency skill metadata.",
            "inputSchema": {"type": "object", "additionalProperties": False},
        },
        {
            "name": "blue_ice_read_skill",
            "description": "Read one bounded, non-symlinked SKILL.md from an installed skill.",
            "inputSchema": {
                "type": "object",
                "properties": {"name": {"type": "string", "maxLength": 128}},
                "required": ["name"],
                "additionalProperties": False,
            },
        },
        {
            "name": "blue_ice_check_project_path",
            "description": "Check a relative path against project-root and privacyignore policy.",
            "inputSchema": {
                "type": "object",
                "properties": {"path": {"type": "string", "maxLength": _MAX_PATH_LENGTH}},
                "required": ["path"],
                "additionalProperties": False,
            },
        },
        {
            "name": "blue_ice_run_security_check",
            "description": "Run deterministic, read-only Blue Ice security checks; never runs shell commands.",
            "inputSchema": {
                "type": "object",
                "properties": {"path": {"type": "string", "maxLength": _MAX_PATH_LENGTH}},
                "additionalProperties": False,
            },
        },
    ]


def capabilities(settings: Settings) -> dict[str, Any]:
    responses_url = dict(settings.custom_responses_urls).get(settings.provider)
    return {
        "object": "blue_ice.capabilities",
        "version": "1",
        "provider": settings.provider,
        "model": settings.model,
        "mcp": {"transport": ["stdio", "streamable_http"], "execution": "read_only"},
        "apis": {
            "models": {"method": "GET", "path": "/v1/models"},
            "chat_completions": {"method": "POST", "path": "/v1/chat/completions"},
            "responses": {
                "method": "POST",
                "path": "/v1/responses",
                "supported": settings.provider == "openai" or responses_url is not None,
            },
            "anthropic_messages": {"method": "POST", "path": "/v1/messages", "supported": True},
            "gemini_generate_content": {
                "method": "POST",
                "path": "/v1beta/models/{model}:generateContent",
                "supported": True,
            },
        },
        "security": {
            "local_bearer_auth": settings.require_local_auth,
            "llm_guard": {"enabled": settings.llm_guard_enabled, "failure_mode": "fail_closed"},
            "secret_redaction": True,
            "egress_inspection": True,
            "metadata_only_audit": True,
            "mcp_tool_execution": "read_only",
        },
    }


def _skill_roots(settings: Settings) -> list[Path]:
    return [
        root
        for root in (settings.project_root / "skills", settings.project_root / ".agents" / "skills")
        if root.is_dir() and not root.is_symlink()
    ]


def _skill_path(settings: Settings, name: Any) -> Path:
    if not isinstance(name, str) or not name or len(name) > 128:
        raise ValueError("skill name is invalid")
    if name in {".", ".."} or "/" in name or "\\" in name or any(ord(ch) < 32 for ch in name):
        raise ValueError("skill name must be a single directory name")
    for root in _skill_roots(settings):
        candidate = (root / name / "SKILL.md").resolve(strict=False)
        try:
            candidate.relative_to(root.resolve())
        except ValueError:
            continue
        if candidate.is_file() and not candidate.is_symlink():
            return candidate
    raise ValueError("skill was not found")


def _list_skills(settings: Settings) -> list[dict[str, str]]:
    rows: dict[str, dict[str, str]] = {}
    for root in _skill_roots(settings):
        for directory in sorted(root.iterdir(), key=lambda item: item.name):
            if not directory.is_dir() or directory.is_symlink():
                continue
            skill_file = directory / "SKILL.md"
            if not skill_file.is_file() or skill_file.is_symlink():
                continue
            description = ""
            try:
                for line in skill_file.read_text(encoding="utf-8").splitlines()[:16]:
                    if line.startswith("description:"):
                        description = line.split(":", 1)[1].strip().strip('"')[:300]
                        break
            except (OSError, UnicodeError):
                description = "unreadable"
            rows.setdefault(directory.name, {"name": directory.name, "description": description})
    return list(rows.values())[:256]


def check_project_path(settings: Settings, relative_path: Any) -> dict[str, Any]:
    if (
        not isinstance(relative_path, str)
        or not relative_path
        or len(relative_path) > _MAX_PATH_LENGTH
    ):
        raise ValueError("path is invalid")
    candidate = (settings.project_root / relative_path).resolve(strict=False)
    try:
        relative = candidate.relative_to(settings.project_root)
    except ValueError:
        return {"allowed": False, "reason": "outside_project_root"}
    if any(candidate.match(rule) for rule in settings.privacyignore_rules):
        return {"allowed": False, "reason": "privacyignore"}
    return {
        "allowed": True,
        "relative_path": str(relative),
        "exists": candidate.exists(),
        "regular_file": candidate.is_file() if candidate.exists() else False,
    }


def _security_check(settings: Settings, relative_path: Any) -> dict[str, Any]:
    path_result = (
        check_project_path(settings, relative_path)
        if relative_path is not None
        else {"allowed": True, "reason": "no_path_requested"}
    )
    return {
        "read_only": True,
        "shell_execution": False,
        "project_path": path_result,
        "controls": {
            "local_auth": settings.require_local_auth,
            "secret_redaction": True,
            "egress_inspection": True,
            "metadata_only_audit": True,
            "llm_guard_fail_closed": settings.llm_guard_enabled,
        },
    }


async def _call_tool(
    settings: Settings,
    name: str,
    arguments: Any,
    model_lister: ModelLister | None,
) -> dict[str, Any]:
    if not isinstance(arguments, dict):
        raise ValueError("tool arguments must be an object")
    if name == "blue_ice_get_capabilities":
        value = capabilities(settings)
        return _text_result(value, value)
    if name == "blue_ice_list_models":
        rows = await model_lister() if model_lister is not None else [{"id": settings.model}]
        return _text_result({"object": "list", "data": rows}, {"models": rows})
    if name == "blue_ice_read_audit":
        limit = arguments.get("limit", 20)
        if type(limit) is not int or not 1 <= limit <= 100:
            raise ValueError("limit must be between 1 and 100")
        rows = read_events(settings.audit_path, limit=limit)
        return _text_result({"events": rows}, {"events": rows})
    if name == "blue_ice_list_skills":
        rows = _list_skills(settings)
        return _text_result({"skills": rows}, {"skills": rows})
    if name == "blue_ice_read_skill":
        path = _skill_path(settings, arguments.get("name"))
        if path.stat().st_size > _MAX_SKILL_BYTES:
            raise ValueError("skill file exceeds the MCP read limit")
        return {"content": [{"type": "text", "text": path.read_text(encoding="utf-8")}]}
    if name == "blue_ice_check_project_path":
        value = check_project_path(settings, arguments.get("path"))
        return _text_result(value, value)
    if name == "blue_ice_run_security_check":
        value = _security_check(settings, arguments.get("path"))
        return _text_result(value, value)
    raise ValueError("unknown tool")


async def handle_request(
    settings: Settings,
    request: Any,
    *,
    model_lister: ModelLister | None = None,
) -> dict[str, Any] | None:
    """Handle one MCP JSON-RPC request; notifications return no response."""
    if not isinstance(request, dict) or request.get("jsonrpc") != "2.0":
        request_id = request.get("id") if isinstance(request, dict) else None
        return _error(request_id, -32600, "Invalid Request")
    request_id = request.get("id")
    method = request.get("method")
    if not isinstance(method, str):
        return _error(request_id, -32600, "Invalid Request")
    if "id" not in request:
        return None
    if method == "initialize":
        return _result(
            request_id,
            {
                "protocolVersion": _PROTOCOL_VERSION,
                "capabilities": {"tools": {}},
                "serverInfo": _SERVER_INFO,
            },
        )
    if method == "ping":
        return _result(request_id, {})
    if method == "tools/list":
        return _result(request_id, {"tools": tool_definitions()})
    if method == "tools/call":
        params = request.get("params")
        if not isinstance(params, dict) or not isinstance(params.get("name"), str):
            return _error(request_id, -32602, "tools/call requires a tool name")
        try:
            value = await _call_tool(
                settings, params["name"], params.get("arguments", {}), model_lister
            )
        except (OSError, UnicodeError, ValueError):
            return _error(request_id, -32602, "Tool arguments or target are invalid")
        return _result(request_id, value)
    return _error(request_id, -32601, "Method not found")


async def serve_stdio(settings: Settings) -> None:
    """Serve newline-delimited JSON-RPC over stdin/stdout."""
    loop = asyncio.get_running_loop()
    while True:
        line = await loop.run_in_executor(None, sys.stdin.readline)
        if not line:
            return
        try:
            request = json.loads(line)
        except (UnicodeError, json.JSONDecodeError):
            print(json.dumps(_error(None, -32700, "Parse error")), flush=True)
            continue
        response = await handle_request(settings, request)
        if response is not None:
            print(json.dumps(response, separators=(",", ":"), ensure_ascii=False), flush=True)


__all__ = ["capabilities", "handle_request", "serve_stdio", "tool_definitions"]
