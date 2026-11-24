"""Fail-closed, optional local prompt summarization through Ollama.

No request is made unless explicitly enabled. The Ollama URL is deliberately
fixed to a loopback address; this module does not support remote providers or
API keys. Summarization is best-effort and never substitutes the input text
when disabled or when a request fails.
"""

from __future__ import annotations

import asyncio
import inspect
import ipaddress
from typing import Any
from urllib.parse import urlsplit

_OLLAMA_URL = "http://127.0.0.1:11434/api/generate"
_DEFAULT_MODEL = "llama3.2"
_REQUEST_TIMEOUT_SECONDS = 8.0
_MAX_INPUT_CHARS = 100_000
_MAX_MODEL_CHARS = 128


def _validate_loopback_url(url: str) -> bool:
    """Return whether *url* is the permitted plain-HTTP loopback endpoint."""
    try:
        parsed = urlsplit(url)
        if (
            parsed.scheme != "http"
            or parsed.username is not None
            or parsed.password is not None
            or parsed.port != 11434
            or parsed.path != "/api/generate"
            or parsed.query
            or parsed.fragment
            or parsed.hostname is None
        ):
            return False
        address = ipaddress.ip_address(parsed.hostname)
        return address.is_loopback
    except (ValueError, TypeError):
        return False


async def summarize_locally(
    text: str,
    enabled: bool = False,
    model: str = _DEFAULT_MODEL,
    client: Any | None = None,
) -> str | None:
    """Ask a local Ollama instance to summarize text, or return ``None``.

    The feature is opt-in. Network calls are restricted to the fixed
    ``127.0.0.1:11434`` Ollama endpoint and bounded by an eight-second timeout.
    An optional async HTTP client may be injected for reuse or testing; it must
    provide ``await client.post(url, json=..., timeout=..., follow_redirects=False)``
    and return a response with an integer ``status_code`` and ``json()`` method.
    An internally created ``httpx.AsyncClient`` is used only when no client is
    injected; ``httpx`` is imported lazily.

    This helper sends only the supplied text and a summarization instruction,
    never an API key or authorization header. It does not log payloads or
    secrets. Disabled, invalid, overlong, timed-out, or failed requests return
    ``None`` rather than the original text, so callers must explicitly decide
    how to handle that result.
    """
    if not enabled or not isinstance(text, str) or not text.strip():
        return None
    if len(text) > _MAX_INPUT_CHARS:
        return None
    if (
        not isinstance(model, str)
        or not model.strip()
        or len(model) > _MAX_MODEL_CHARS
        or any(ord(character) < 32 for character in model)
    ):
        return None
    if not _validate_loopback_url(_OLLAMA_URL):
        return None

    prompt = (
        "Summarize the following text faithfully and concisely. Preserve key "
        "facts, constraints, and uncertainty; do not invent information.\n\n"
        f"{text}"
    )
    payload = {"model": model.strip(), "prompt": prompt, "stream": False}

    try:
        async with asyncio.timeout(_REQUEST_TIMEOUT_SECONDS):
            if client is not None:
                response = await client.post(
                    _OLLAMA_URL,
                    json=payload,
                    timeout=_REQUEST_TIMEOUT_SECONDS,
                    follow_redirects=False,
                )
                return await _extract_summary(response)

            # Keep the HTTP dependency optional and avoid blocking the event loop.
            try:
                import httpx
            except ImportError:
                return None

            async with httpx.AsyncClient(
                timeout=_REQUEST_TIMEOUT_SECONDS,
                follow_redirects=False,
            ) as local_client:
                response = await local_client.post(
                    _OLLAMA_URL,
                    json=payload,
                    timeout=_REQUEST_TIMEOUT_SECONDS,
                    follow_redirects=False,
                )
                return await _extract_summary(response)
    except (TimeoutError, Exception):
        # Deliberately fail closed without logging prompt, response, or secrets.
        return None


async def _extract_summary(response: Any) -> str | None:
    """Extract a non-empty Ollama response from a successful HTTP response."""
    status_code = getattr(response, "status_code", None)
    if not isinstance(status_code, int) or not 200 <= status_code < 300:
        return None

    result = response.json()
    if inspect.isawaitable(result):
        result = await result
    if not isinstance(result, dict):
        return None
    summary = result.get("response")
    if not isinstance(summary, str) or not summary.strip():
        return None
    return summary.strip()
