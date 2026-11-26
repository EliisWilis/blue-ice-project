"""Fixed-destination pass-throughs for native Anthropic and Gemini API contracts.

These functions do not translate one provider's schema into another. Stream
responses are buffered so the application can inspect them before replaying.
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from typing import Any
from urllib.parse import quote

from aegis.routing.privacy_router import ProviderRequestError, _validate_json_value

_TIMEOUT_SECONDS = 30.0
_MODEL_RE = re.compile(r"^[A-Za-z0-9._-]{1,120}$")
_BLOCKED_ROUTING_FIELDS = frozenset({"url", "api_url", "base_url", "api_base", "endpoint"})


async def _post_native(
    *,
    client: Any,
    endpoint: str,
    payload: Mapping[str, Any],
    headers: dict[str, str],
    max_response_bytes: int,
    stream: bool,
) -> dict[str, Any] | bytes:
    if not isinstance(payload, Mapping):
        raise ValueError("payload must be a JSON object")
    if type(max_response_bytes) is not int or not 1_024 <= max_response_bytes <= 64_000_000:
        raise ValueError("max_response_bytes must be between 1024 and 64000000")
    if _BLOCKED_ROUTING_FIELDS.intersection(key.lower() for key in payload):
        raise ValueError("payload must not contain destination or endpoint fields")
    _validate_json_value(dict(payload))

    received = 0
    chunks: list[bytes] = []
    stream_method = getattr(client, "stream", None)
    try:
        if callable(stream_method):
            async with stream_method(
                "POST",
                endpoint,
                json=dict(payload),
                headers=headers,
                timeout=_TIMEOUT_SECONDS,
                follow_redirects=False,
            ) as response:
                status_code = getattr(response, "status_code", None)
                if not isinstance(status_code, int) or not 200 <= status_code < 300:
                    raise ProviderRequestError(
                        "provider returned an unsuccessful HTTP status",
                        status_code=status_code if isinstance(status_code, int) else None,
                    )
                response_headers = getattr(response, "headers", {})
                response_length = response_headers.get("content-length")
                if isinstance(response_length, str) and response_length.isdigit():
                    if int(response_length) > max_response_bytes:
                        raise ProviderRequestError(
                            "provider response exceeded the configured safety limit"
                        )
                content_type = str(response_headers.get("content-type", "")).lower()
                if stream and "text/event-stream" not in content_type:
                    raise ProviderRequestError("provider returned an invalid native SSE stream")
                if not stream and "json" not in content_type:
                    raise ProviderRequestError("provider returned an invalid JSON response")
                async for chunk in response.aiter_bytes():
                    received += len(chunk)
                    if received > max_response_bytes:
                        raise ProviderRequestError(
                            "provider response exceeded the configured safety limit"
                        )
                    chunks.append(chunk)
        else:
            response = await client.post(
                endpoint,
                json=dict(payload),
                headers=headers,
                timeout=_TIMEOUT_SECONDS,
                follow_redirects=False,
            )
            status_code = getattr(response, "status_code", None)
            if not isinstance(status_code, int) or not 200 <= status_code < 300:
                raise ProviderRequestError(
                    "provider returned an unsuccessful HTTP status",
                    status_code=status_code if isinstance(status_code, int) else None,
                )
            content = getattr(response, "content", None)
            if not isinstance(content, (bytes, bytearray)):
                raise ProviderRequestError("provider returned an invalid response")
            if len(content) > max_response_bytes:
                raise ProviderRequestError("provider response exceeded the configured safety limit")
            content_type = str(getattr(response, "headers", {}).get("content-type", "")).lower()
            if stream and "text/event-stream" not in content_type:
                raise ProviderRequestError("provider returned an invalid native SSE stream")
            if not stream and "json" not in content_type:
                raise ProviderRequestError("provider returned an invalid JSON response")
            chunks.append(bytes(content))
    except ProviderRequestError:
        raise
    except Exception:
        raise ProviderRequestError("provider request failed") from None

    body = b"".join(chunks)
    if stream:
        return body
    try:
        decoded = json.loads(body)
    except (UnicodeError, json.JSONDecodeError):
        raise ProviderRequestError("provider returned an invalid JSON response") from None
    if not isinstance(decoded, dict):
        raise ProviderRequestError("provider returned a non-object response")
    return decoded


async def forward_anthropic_messages(
    payload: Mapping[str, Any],
    *,
    api_key: str,
    client: Any,
    max_response_bytes: int,
    client_headers: Mapping[str, str] | None = None,
) -> dict[str, Any] | bytes:
    """Forward an Anthropic Messages request without translating its schema."""
    if not isinstance(api_key, str) or not api_key.strip():
        raise ValueError("api_key is required for Anthropic Messages")
    if not isinstance(payload.get("model"), str) or not payload["model"].strip():
        raise ValueError("model must be a non-empty string")
    messages = payload.get("messages")
    if not isinstance(messages, list) or not messages:
        raise ValueError("messages must be a non-empty array")
    stream = payload.get("stream", False)
    if type(stream) is not bool:
        raise ValueError("stream must be true or false")

    incoming = {key.lower(): value for key, value in (client_headers or {}).items()}
    headers = {
        "Accept": "text/event-stream" if stream else "application/json",
        "Content-Type": "application/json",
        "x-api-key": api_key.strip(),
    }
    version = incoming.get("anthropic-version")
    if (
        isinstance(version, str)
        and 0 < len(version) <= 64
        and not any(ord(ch) < 32 for ch in version)
    ):
        headers["anthropic-version"] = version
    beta = incoming.get("anthropic-beta")
    if isinstance(beta, str) and len(beta) <= 2_048 and not any(ord(ch) < 32 for ch in beta):
        headers["anthropic-beta"] = beta
    return await _post_native(
        client=client,
        endpoint="https://api.anthropic.com/v1/messages",
        payload=payload,
        headers=headers,
        max_response_bytes=max_response_bytes,
        stream=stream,
    )


async def forward_gemini_generate_content(
    model: str,
    payload: Mapping[str, Any],
    *,
    api_key: str,
    client: Any,
    max_response_bytes: int,
    stream: bool = False,
) -> dict[str, Any] | bytes:
    """Forward Gemini GenerateContent using its native model/path contract."""
    if not isinstance(api_key, str) or not api_key.strip():
        raise ValueError("api_key is required for Gemini GenerateContent")
    if not isinstance(model, str) or not _MODEL_RE.fullmatch(model):
        raise ValueError("Gemini model path is invalid")
    if not isinstance(payload, Mapping):
        raise ValueError("payload must be a JSON object")
    if "stream" in payload:
        raise ValueError("Gemini streaming is selected by the native endpoint path")
    if not isinstance(payload.get("contents"), list) or not payload["contents"]:
        raise ValueError("contents must be a non-empty array")
    action = "streamGenerateContent" if stream else "generateContent"
    endpoint = (
        "https://generativelanguage.googleapis.com/v1beta/models/"
        f"{quote(model, safe='._-')}:{action}"
    )
    if stream:
        endpoint += "?alt=sse"
    headers = {
        "Accept": "text/event-stream" if stream else "application/json",
        "Content-Type": "application/json",
        "x-goog-api-key": api_key.strip(),
    }
    return await _post_native(
        client=client,
        endpoint=endpoint,
        payload=payload,
        headers=headers,
        max_response_bytes=max_response_bytes,
        stream=stream,
    )
