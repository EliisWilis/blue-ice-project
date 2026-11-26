"""Fail-closed async chat forwarding to a small, fixed provider allowlist.

Credentials are supplied by the caller (for example, after reading a keyring or
an environment variable). This module never discovers, stores, rotates, or logs
credentials. No URL from the request payload is used to select a destination.
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import math
import socket
from collections.abc import Mapping
from typing import Any, Literal, Protocol
from urllib.parse import urlsplit

Provider = Literal["openai", "openrouter", "groq", "google", "cerebras", "ollama"]

# An explicit default for callers to select; forwarding still requires provider
# to be passed so a request cannot silently fall back to a cloud destination.
DEFAULT_PROVIDER: Provider = "openrouter"

_PROVIDER_URLS: dict[str, str] = {
    "openai": "https://api.openai.com/v1/chat/completions",
    "openrouter": "https://openrouter.ai/api/v1/chat/completions",
    "groq": "https://api.groq.com/openai/v1/chat/completions",
    "google": "https://generativelanguage.googleapis.com/v1beta/openai/chat/completions",
    "cerebras": "https://api.cerebras.ai/v1/chat/completions",
    # Deliberately local-only and fixed. Callers cannot supply an Ollama URL.
    "ollama": "http://127.0.0.1:11434/v1/chat/completions",
}
_CLOUD_PROVIDERS = frozenset({"openai", "openrouter", "groq", "google", "cerebras"})
_BLOCKED_ROUTING_FIELDS = frozenset(
    {"url", "api_url", "base_url", "api_base", "endpoint", "provider_url"}
)
_TIMEOUT_SECONDS = 30.0
_MAX_ATTEMPTS = 3
_RETRYABLE_STATUS_CODES = frozenset({408, 429})


class AsyncChatClient(Protocol):
    """Minimal interface required from an injected async HTTP client."""

    async def post(self, url: str, **kwargs: Any) -> Any: ...


class ProviderRequestError(RuntimeError):
    """Sanitized forwarding error that never includes request or credential data."""

    def __init__(self, message: str, *, status_code: int | None = None) -> None:
        super().__init__(message)
        self.status_code = status_code


async def _bounded_post(
    client: Any,
    endpoint: str,
    body: dict[str, Any],
    headers: dict[str, str],
    max_response_bytes: int,
) -> tuple[int | None, Any]:
    """Send a POST and enforce the response limit while streaming when supported."""
    stream = getattr(client, "stream", None)
    if callable(stream):
        async with stream(
            "POST",
            endpoint,
            json=body,
            headers=headers,
            timeout=_TIMEOUT_SECONDS,
        ) as response:
            status_code = getattr(response, "status_code", None)
            if not isinstance(status_code, int) or not 200 <= status_code < 300:
                return status_code, None
            response_headers = getattr(response, "headers", {})
            response_length = response_headers.get("content-length")
            if isinstance(response_length, str) and response_length.isdigit():
                if int(response_length) > max_response_bytes:
                    raise ProviderRequestError(
                        "provider response exceeded the configured safety limit"
                    )
            received = 0
            chunks: list[bytes] = []
            async for chunk in response.aiter_bytes():
                received += len(chunk)
                if received > max_response_bytes:
                    raise ProviderRequestError(
                        "provider response exceeded the configured safety limit"
                    )
                chunks.append(chunk)
        try:
            return status_code, json.loads(b"".join(chunks))
        except (UnicodeError, json.JSONDecodeError):
            raise ProviderRequestError("provider returned an invalid JSON response") from None

    # Compatibility path for injected test clients that implement only post().
    # Production uses HTTPX AsyncClient.stream() and is bounded during transfer.
    response = await client.post(
        endpoint,
        json=body,
        headers=headers,
        timeout=_TIMEOUT_SECONDS,
    )
    status_code = getattr(response, "status_code", None)
    if not isinstance(status_code, int) or not 200 <= status_code < 300:
        return status_code, None
    response_content = getattr(response, "content", None)
    if (
        isinstance(response_content, (bytes, bytearray))
        and len(response_content) > max_response_bytes
    ):
        raise ProviderRequestError("provider response exceeded the configured safety limit")
    response_length = getattr(response, "headers", {}).get("content-length")
    if isinstance(response_length, str) and response_length.isdigit():
        if int(response_length) > max_response_bytes:
            raise ProviderRequestError("provider response exceeded the configured safety limit")
    try:
        return status_code, response.json()
    except Exception:
        raise ProviderRequestError("provider returned an invalid JSON response") from None


def _validate_json_value(value: Any, path: str = "payload") -> None:
    """Reject non-JSON values before handing data to an HTTP implementation."""
    if value is None or isinstance(value, (str, bool, int)):
        return
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError(f"{path} contains a non-finite number")
        return
    if isinstance(value, list):
        for index, item in enumerate(value):
            _validate_json_value(item, f"{path}[{index}]")
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise ValueError(f"{path} object keys must be strings")
            _validate_json_value(item, f"{path}.{key}")
        return
    raise ValueError(f"{path} contains a value that is not JSON-compatible")


def _validated_provider(provider: str) -> str:
    """Return a recognized provider name without interpreting it as a URL."""
    if not isinstance(provider, str):
        raise ValueError("provider must be one of the configured provider names")
    normalized = provider.strip().lower()
    if normalized not in _PROVIDER_URLS:
        raise ValueError("provider must be one of the configured provider names")
    return normalized


async def _validate_custom_endpoint(url: str) -> str:
    """Revalidate a trusted config endpoint and reject private DNS results."""
    try:
        parsed = urlsplit(url)
        hostname = parsed.hostname
        port = parsed.port or 443
    except (TypeError, ValueError):
        raise ValueError("custom endpoint is invalid") from None
    if (
        parsed.scheme != "https"
        or not hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or port != 443
        or not parsed.path.endswith("/chat/completions")
    ):
        raise ValueError("custom endpoint must be an HTTPS chat-completions URL")
    try:
        records = await asyncio.to_thread(socket.getaddrinfo, hostname, port, 0, socket.SOCK_STREAM)
        addresses = {record[4][0] for record in records}
        if not addresses or any(
            not ipaddress.ip_address(address).is_global for address in addresses
        ):
            raise ValueError("custom endpoint resolved to a non-public address")
    except (OSError, ValueError, TypeError):
        raise ValueError("custom endpoint DNS validation failed") from None
    return url


async def _validate_custom_responses_endpoint(url: str) -> str:
    """Revalidate an explicit custom Responses URL and reject private DNS results."""
    try:
        parsed = urlsplit(url)
        hostname = parsed.hostname
        port = parsed.port or 443
    except (TypeError, ValueError):
        raise ValueError("custom Responses endpoint is invalid") from None
    if (
        parsed.scheme != "https"
        or not hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or port != 443
        or not parsed.path.endswith("/responses")
    ):
        raise ValueError("custom Responses endpoint must be an HTTPS /responses URL")
    try:
        records = await asyncio.to_thread(socket.getaddrinfo, hostname, port, 0, socket.SOCK_STREAM)
        addresses = {record[4][0] for record in records}
        if not addresses or any(
            not ipaddress.ip_address(address).is_global for address in addresses
        ):
            raise ValueError("custom Responses endpoint resolved to a non-public address")
    except (OSError, ValueError, TypeError):
        raise ValueError("custom Responses endpoint DNS validation failed") from None
    return url


async def _validate_custom_models_endpoint(url: str) -> str:
    """Revalidate a configured models endpoint and reject private DNS results."""
    try:
        parsed = urlsplit(url)
        hostname = parsed.hostname
        port = parsed.port or 443
    except (TypeError, ValueError):
        raise ValueError("custom models endpoint is invalid") from None
    if (
        parsed.scheme != "https"
        or not hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or port != 443
        or not parsed.path.endswith("/models")
    ):
        raise ValueError("custom models endpoint must be an HTTPS /models URL")
    try:
        records = await asyncio.to_thread(socket.getaddrinfo, hostname, port, 0, socket.SOCK_STREAM)
        addresses = {record[4][0] for record in records}
        if not addresses or any(
            not ipaddress.ip_address(address).is_global for address in addresses
        ):
            raise ValueError("custom models endpoint resolved to a non-public address")
    except (OSError, ValueError, TypeError):
        raise ValueError("custom models endpoint DNS validation failed") from None
    return url


async def forward_models(
    provider: str,
    api_key: str | None,
    client: Any,
    endpoint_url: str | None = None,
    models_url: str | None = None,
    max_response_bytes: int = 8_000_000,
) -> list[dict[str, Any]]:
    """Return a sanitized model catalog from the one explicitly selected provider."""
    if type(max_response_bytes) is not int or not 1_024 <= max_response_bytes <= 64_000_000:
        raise ValueError("max_response_bytes must be between 1024 and 64000000")
    selected = provider.strip().lower() if isinstance(provider, str) else ""
    is_custom = endpoint_url is not None
    if is_custom:
        if (
            not selected
            or len(selected) > 48
            or not isinstance(endpoint_url, str)
            or not endpoint_url.endswith("/chat/completions")
        ):
            raise ValueError("custom provider name is invalid")
        derived_url = endpoint_url[: -len("/chat/completions")] + "/models"
        endpoint = await _validate_custom_models_endpoint(models_url or derived_url)
    else:
        selected = _validated_provider(selected)
        if models_url is not None:
            raise ValueError("a custom models URL cannot override a built-in provider")
        if selected == "ollama":
            endpoint = "http://127.0.0.1:11434/api/tags"
        else:
            endpoint = _PROVIDER_URLS[selected][: -len("/chat/completions")] + "/models"

    if selected != "ollama" and (not isinstance(api_key, str) or not api_key.strip()):
        raise ValueError("api_key is required for the selected cloud provider")
    headers = {"Accept": "application/json"}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"

    raw: bytes
    try:
        stream_method = getattr(client, "stream", None)
        if callable(stream_method):
            async with stream_method(
                "GET", endpoint, headers=headers, timeout=_TIMEOUT_SECONDS
            ) as response:
                status_code = getattr(response, "status_code", None)
                if not isinstance(status_code, int) or not 200 <= status_code < 300:
                    raise ProviderRequestError(
                        "provider models request returned an unsuccessful HTTP status",
                        status_code=status_code if isinstance(status_code, int) else None,
                    )
                response_headers = getattr(response, "headers", {})
                response_length = response_headers.get("content-length")
                if isinstance(response_length, str) and response_length.isdigit():
                    if int(response_length) > max_response_bytes:
                        raise ProviderRequestError(
                            "provider model list exceeded the configured safety limit"
                        )
                received = 0
                chunks: list[bytes] = []
                async for chunk in response.aiter_bytes():
                    received += len(chunk)
                    if received > max_response_bytes:
                        raise ProviderRequestError(
                            "provider model list exceeded the configured safety limit"
                        )
                    chunks.append(chunk)
                raw = b"".join(chunks)
        else:
            response = await client.get(
                endpoint,
                headers=headers,
                timeout=_TIMEOUT_SECONDS,
                follow_redirects=False,
            )
            status_code = getattr(response, "status_code", None)
            if not isinstance(status_code, int) or not 200 <= status_code < 300:
                raise ProviderRequestError(
                    "provider models request returned an unsuccessful HTTP status",
                    status_code=status_code if isinstance(status_code, int) else None,
                )
            content = getattr(response, "content", b"")
            if not isinstance(content, (bytes, bytearray)) or len(content) > max_response_bytes:
                raise ProviderRequestError(
                    "provider model list exceeded the configured safety limit"
                )
            raw = bytes(content)
    except ProviderRequestError:
        raise
    except Exception:
        raise ProviderRequestError("provider model-list request failed") from None

    try:
        decoded = json.loads(raw)
    except (UnicodeError, json.JSONDecodeError):
        raise ProviderRequestError("provider returned an invalid model list") from None
    if not isinstance(decoded, dict):
        raise ProviderRequestError("provider returned an invalid model list")
    source = decoded.get("models") if selected == "ollama" else decoded.get("data")
    if not isinstance(source, list):
        raise ProviderRequestError("provider returned an unsupported model-list format")

    result: list[dict[str, Any]] = []
    seen: set[str] = set()
    for item in source[:1000]:
        if not isinstance(item, dict):
            continue
        model_id = item.get("name" if selected == "ollama" else "id")
        if (
            not isinstance(model_id, str)
            or not model_id.strip()
            or len(model_id) > 200
            or any(ord(character) < 32 for character in model_id)
        ):
            continue
        model_id = model_id.strip()
        if model_id in seen:
            continue
        seen.add(model_id)
        model: dict[str, Any] = {"id": model_id, "object": "model"}
        created = item.get("created")
        if type(created) is int and created >= 0:
            model["created"] = created
        owned_by = item.get("owned_by")
        if isinstance(owned_by, str) and len(owned_by) <= 128:
            model["owned_by"] = owned_by
        result.append(model)
    if not result:
        raise ProviderRequestError("provider returned no usable model IDs")
    return result


def _request_body(provider: str, payload: Mapping[str, Any]) -> dict[str, Any]:
    """Copy and validate the body, applying OpenRouter's supported privacy prefs."""
    body = dict(payload)
    blocked = _BLOCKED_ROUTING_FIELDS.intersection(key.lower() for key in body)
    if blocked:
        raise ValueError("payload must not contain destination or endpoint fields")
    _validate_json_value(body)

    if provider == "openrouter":
        preferences = body.get("provider", {})
        if not isinstance(preferences, dict):
            raise ValueError("OpenRouter provider preferences must be a JSON object")
        # These are documented request preferences, not headers or a guarantee of
        # end-to-end ZDR; provider and account policies may still apply.
        body["provider"] = {
            **preferences,
            "data_collection": "deny",
            "zdr": True,
        }
    return body


def _is_retryable_exception(exc: Exception) -> bool:
    """Recognize transport failures without exposing or logging exception text."""
    if isinstance(exc, (TimeoutError, OSError)):
        return True
    try:
        import httpx  # type: ignore[import-not-found]
    except ImportError:
        return False
    return isinstance(exc, (httpx.TimeoutException, httpx.TransportError))


async def forward_chat(
    payload: Mapping[str, Any],
    provider: Provider | str,
    api_key: str | None = None,
    client: AsyncChatClient | None = None,
    endpoint_url: str | None = None,
    max_response_bytes: int = 8_000_000,
) -> Any:
    """Forward a JSON chat payload to exactly one allowlisted provider.

    Retries are bounded and target the same selected provider only. There is no
    automatic failover. Cloud credentials must be passed by the caller; Ollama
    permits an omitted key. The function never logs the body, headers, or secret.

    Args:
        payload: OpenAI-compatible JSON request body. Destination fields such as
            ``url`` and ``base_url`` are rejected rather than interpreted.
        provider: Explicit allowlisted destination name.
        api_key: Caller-supplied credential. Never read from or persisted by this
            module. Required for cloud providers and optional for local Ollama.
        client: Optional injected asynchronous HTTP client. When omitted, ``httpx``
            is imported lazily and a temporary ``AsyncClient`` is used.

    Returns:
        The decoded JSON response from the selected provider.

    Raises:
        ValueError: If provider, credentials, or payload are invalid.
        RuntimeError: If ``httpx`` is unavailable and no client was injected.
        ProviderRequestError: For sanitized transport, HTTP, or response errors.
    """
    custom_endpoint = endpoint_url is not None
    if custom_endpoint:
        if not isinstance(provider, str) or not provider or len(provider) > 48:
            raise ValueError("custom provider name is invalid")
        selected = provider
        endpoint = await _validate_custom_endpoint(endpoint_url)
    else:
        selected = _validated_provider(provider)
        endpoint = _PROVIDER_URLS[selected]
    if not isinstance(payload, Mapping):
        raise ValueError("payload must be a JSON object")
    if type(max_response_bytes) is not int or not 1_024 <= max_response_bytes <= 64_000_000:
        raise ValueError("max_response_bytes must be between 1024 and 64000000")
    if selected in _CLOUD_PROVIDERS or custom_endpoint:
        if not isinstance(api_key, str) or not api_key.strip():
            raise ValueError("api_key is required for the selected cloud provider")
    elif api_key is not None and (not isinstance(api_key, str) or not api_key.strip()):
        raise ValueError("api_key must be a non-empty string when provided")

    body = _request_body(selected if not custom_endpoint else "custom", payload)
    headers = {"Accept": "application/json", "Content-Type": "application/json"}
    if api_key is not None:
        headers["Authorization"] = f"Bearer {api_key}"
    if selected == "openrouter" and not custom_endpoint:
        headers["HTTP-Referer"] = "http://localhost"

    owns_client = client is None
    if client is None:
        try:
            import httpx  # type: ignore[import-not-found]
        except ImportError as exc:
            raise RuntimeError("httpx is required unless an async client is supplied") from exc
        client = httpx.AsyncClient()

    try:
        for attempt in range(_MAX_ATTEMPTS):
            try:
                status_code, response_body = await _bounded_post(
                    client, endpoint, body, headers, max_response_bytes
                )
            except ProviderRequestError:
                raise
            except Exception as exc:
                if _is_retryable_exception(exc) and attempt + 1 < _MAX_ATTEMPTS:
                    await asyncio.sleep(0.1 * (2**attempt))
                    continue
                if _is_retryable_exception(exc):
                    raise ProviderRequestError(
                        "provider transport failed after bounded retries"
                    ) from None
                raise ProviderRequestError("provider request failed") from None

            if not isinstance(status_code, int):
                raise ProviderRequestError("provider returned an invalid response")
            if status_code < 200 or status_code >= 300:
                retryable = status_code in _RETRYABLE_STATUS_CODES or status_code >= 500
                if retryable and attempt + 1 < _MAX_ATTEMPTS:
                    await asyncio.sleep(0.1 * (2**attempt))
                    continue
                raise ProviderRequestError(
                    "provider returned an unsuccessful HTTP status",
                    status_code=status_code,
                )
            return response_body

        # The loop always returns or raises; this is a defensive fail-closed guard.
        raise ProviderRequestError("provider request exhausted bounded retries")
    finally:
        if owns_client:
            await client.aclose()  # type: ignore[union-attr]


async def forward_responses(
    provider: str,
    payload: Mapping[str, Any],
    api_key: str | None,
    client: Any,
    max_response_bytes: int = 8_000_000,
    endpoint_url: str | None = None,
) -> dict[str, Any] | bytes:
    """Forward native Responses API requests to a configured native endpoint.

    Streaming event bytes are bounded and returned intact for inspection by the
    application before they are replayed. This function never translates a chat
    payload into a Responses payload or retries a potentially stateful request.
    """
    if not isinstance(payload, Mapping):
        raise ValueError("payload must be a JSON object")
    if not isinstance(api_key, str) or not api_key.strip():
        raise ValueError("api_key is required for the selected cloud provider")
    if type(max_response_bytes) is not int or not 1_024 <= max_response_bytes <= 64_000_000:
        raise ValueError("max_response_bytes must be between 1024 and 64000000")
    if endpoint_url is None:
        if provider != "openai":
            raise ValueError("native Responses endpoint is not configured for this provider")
        endpoint = "https://api.openai.com/v1/responses"
        body = _request_body("openai", payload)
    else:
        if provider == "openai" or provider in _PROVIDER_URLS:
            raise ValueError("custom Responses URL cannot override a built-in provider")
        endpoint = await _validate_custom_responses_endpoint(endpoint_url)
        body = _request_body("custom", payload)
    stream_requested = body.get("stream", False)
    if type(stream_requested) is not bool:
        raise ValueError("stream must be true or false")
    headers = {
        "Accept": "text/event-stream" if stream_requested else "application/json",
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }
    received = 0
    chunks: list[bytes] = []
    status_code: int | None = None
    try:
        stream_method = getattr(client, "stream", None)
        if callable(stream_method):
            async with stream_method(
                "POST", endpoint, json=body, headers=headers, timeout=_TIMEOUT_SECONDS
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
                async for chunk in response.aiter_bytes():
                    received += len(chunk)
                    if received > max_response_bytes:
                        raise ProviderRequestError(
                            "provider response exceeded the configured safety limit"
                        )
                    chunks.append(chunk)
                content_type = str(response_headers.get("content-type", "")).lower()
                if stream_requested and "text/event-stream" not in content_type:
                    raise ProviderRequestError("provider returned an invalid Responses stream")
        else:
            response = await client.post(
                endpoint,
                json=body,
                headers=headers,
                timeout=_TIMEOUT_SECONDS,
            )
            status_code = getattr(response, "status_code", None)
            if not isinstance(status_code, int) or not 200 <= status_code < 300:
                raise ProviderRequestError(
                    "provider returned an unsuccessful HTTP status",
                    status_code=status_code if isinstance(status_code, int) else None,
                )
            raw = getattr(response, "content", b"")
            if not isinstance(raw, (bytes, bytearray)):
                raise ProviderRequestError("provider returned an invalid response")
            if len(raw) > max_response_bytes:
                raise ProviderRequestError("provider response exceeded the configured safety limit")
            chunks.append(bytes(raw))
    except ProviderRequestError:
        raise
    except Exception as exc:
        if _is_retryable_exception(exc):
            raise ProviderRequestError("provider transport failed") from None
        raise ProviderRequestError("provider request failed") from None

    raw_body = b"".join(chunks)
    if stream_requested:
        return raw_body
    try:
        decoded = json.loads(raw_body)
    except (UnicodeError, json.JSONDecodeError):
        raise ProviderRequestError("provider returned an invalid JSON response") from None
    if not isinstance(decoded, dict):
        raise ProviderRequestError("provider returned a non-object response")
    return decoded
