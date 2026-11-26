"""FastAPI application implementing Blue Ice Project's buffered security pipeline."""

from __future__ import annotations

import asyncio
import copy
import hmac
import json
import re
import time
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response, StreamingResponse

from aegis.audit import append_event
from aegis.config import Settings, read_local_token, resolve_provider_key
from aegis.egress.egress_firewall import inspect_output
from aegis.egress.reconstructor import reconstruct
from aegis.egress.slopsquat_guard import check_packages, extract_packages
from aegis.ingress.blast_radius import inspect_messages
from aegis.ingress.secret_redactor import SessionVault, redact_text
from aegis.llm_guard_adapter import (
    ScannerUnavailable,
    ScanRejected,
    build_default_scanners,
    scan_input,
    scan_output,
)
from aegis.routing.native_protocols import (
    forward_anthropic_messages,
    forward_gemini_generate_content,
)
from aegis.routing.privacy_router import (
    ProviderRequestError,
    forward_chat,
    forward_models,
    forward_responses,
)

_SECRET_PLACEHOLDER_RE = re.compile(r"__AEGIS_SEC_\d{3,}__")
_ALLOWED_ROLES = {"system", "developer", "user", "assistant", "tool"}


class PolicyBlocked(Exception):
    def __init__(
        self,
        rules: list[str],
        *,
        public_message: str = "Request blocked by Blue Ice Project policy",
    ) -> None:
        super().__init__(public_message)
        self.rules = rules[:32]


class AuditUnavailable(RuntimeError):
    """An event could not be recorded; callers must not receive a normal result."""


class RequestSizeLimitMiddleware:
    """Bound request buffering, including chunked bodies without Content-Length."""

    def __init__(self, app: Any, max_bytes: int) -> None:
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope: dict[str, Any], receive: Any, send: Any) -> None:
        if (
            scope.get("type") != "http"
            or scope.get("method") != "POST"
            or not _request_path_has_body_limit(scope.get("path", ""))
        ):
            await self.app(scope, receive, send)
            return
        headers = {key.lower(): value for key, value in scope.get("headers", [])}
        length = headers.get(b"content-length")
        if length is not None:
            try:
                if int(length) > self.max_bytes:
                    await self._too_large(send)
                    return
            except ValueError:
                await send(
                    {
                        "type": "http.response.start",
                        "status": 400,
                        "headers": [(b"content-type", b"application/json")],
                    }
                )
                await send(
                    {
                        "type": "http.response.body",
                        "body": b'{"error":{"type":"invalid_request","message":"Invalid Content-Length"}}',
                    }
                )
                return
        buffered: list[dict[str, Any]] = []
        total = 0
        while True:
            message = await receive()
            if message["type"] == "http.disconnect":
                return
            chunk = message.get("body", b"")
            total += len(chunk)
            if total > self.max_bytes:
                await self._too_large(send)
                return
            buffered.append(message)
            if not message.get("more_body", False):
                break
        index = 0

        async def replay_receive() -> dict[str, Any]:
            nonlocal index
            if index < len(buffered):
                item = buffered[index]
                index += 1
                return item
            return await receive()

        await self.app(scope, replay_receive, send)

    @staticmethod
    async def _too_large(send: Any) -> None:
        await send(
            {
                "type": "http.response.start",
                "status": 413,
                "headers": [(b"content-type", b"application/json")],
            }
        )
        await send(
            {
                "type": "http.response.body",
                "body": b'{"error":{"type":"request_too_large","message":"Request body exceeds configured size limit"}}',
            }
        )


def _request_path_has_body_limit(path: str) -> bool:
    return (
        path in {"/v1/chat/completions", "/v1/responses", "/v1/messages"}
        or path.rstrip("/") == "/a2a"
        or (
            path.startswith("/v1beta/models/")
            and (path.endswith(":generateContent") or path.endswith(":streamGenerateContent"))
        )
    )


def _transform_strings(value: Any, transform: Any) -> Any:
    if isinstance(value, str):
        return transform(value)
    if isinstance(value, list):
        return [_transform_strings(item, transform) for item in value]
    if isinstance(value, dict):
        return {key: _transform_strings(item, transform) for key, item in value.items()}
    return value


def _all_strings(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        return [text for item in value.values() for text in _all_strings(item)]
    if isinstance(value, list):
        return [text for item in value for text in _all_strings(item)]
    return []


def _validate_chat_payload(payload: Any) -> tuple[list[dict[str, Any]], bool]:
    if not isinstance(payload, dict):
        raise ValueError("JSON request body must be an object")
    model = payload.get("model")
    messages = payload.get("messages")
    stream = payload.get("stream", False)
    if not isinstance(model, str) or not model.strip() or len(model) > 200:
        raise ValueError("model must be a non-empty string of at most 200 characters")
    if not isinstance(messages, list) or not 1 <= len(messages) <= 100:
        raise ValueError("messages must contain between 1 and 100 entries")
    if type(stream) is not bool:
        raise ValueError("stream must be true or false")
    for message in messages:
        if not isinstance(message, dict) or message.get("role") not in _ALLOWED_ROLES:
            raise ValueError("each message must have a supported role")
        if "content" not in message and message.get("role") != "assistant":
            raise ValueError("each non-assistant message must include content")
    return messages, stream


def _assistant_texts(response_body: dict[str, Any]) -> list[str]:
    choices = response_body.get("choices")
    if not isinstance(choices, list) or not choices:
        raise ProviderRequestError("provider returned no chat choices")
    found: list[str] = []
    for choice in choices:
        if not isinstance(choice, dict):
            raise ProviderRequestError("provider returned an invalid chat choice")
        message = choice.get("message")
        if not isinstance(message, dict):
            raise ProviderRequestError("provider returned an invalid chat message")
        found.extend(_all_strings(message))
    return found


def _collect_vault_mapping(redacted: Any, vault: SessionVault) -> dict[str, str]:
    mapping: dict[str, str] = {}
    for text in _all_strings(redacted):
        for match in _SECRET_PLACEHOLDER_RE.finditer(text):
            secret = vault.resolve(match.group(0))
            if secret is not None:
                mapping[match.group(0)] = secret
    return mapping


def _replace_assistant_strings(response_body: dict[str, Any], transform: Any) -> dict[str, Any]:
    result = copy.deepcopy(response_body)
    for choice in result.get("choices", []):
        if isinstance(choice, dict) and isinstance(choice.get("message"), dict):
            choice["message"] = _transform_strings(choice["message"], transform)
    return result


def _stream_response(body: dict[str, Any]) -> StreamingResponse:
    """Emit a complete inspected response as a small OpenAI-compatible SSE stream."""
    try:
        choice = body["choices"][0]
        message = choice["message"]
        delta: dict[str, Any] = {"role": "assistant"}
        for key in ("content", "tool_calls", "refusal", "function_call"):
            if key in message:
                delta[key] = message[key]
        chunk = {
            "id": body.get("id", "chatcmpl-blue-ice"),
            "object": "chat.completion.chunk",
            "created": body.get("created", int(time.time())),
            "model": body.get("model", "blue-ice-project"),
            "choices": [
                {
                    "index": choice.get("index", 0),
                    "delta": delta,
                    "finish_reason": choice.get("finish_reason", "stop"),
                }
            ],
        }
        data = "data: " + json.dumps(chunk, separators=(",", ":"), ensure_ascii=False) + "\n\n"
    except Exception:
        raise ProviderRequestError("provider returned an invalid streamable response") from None

    async def events() -> AsyncIterator[bytes]:
        yield data.encode("utf-8")
        yield b"data: [DONE]\n\n"

    return StreamingResponse(
        events(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


def _validate_responses_payload(payload: Any) -> bool:
    if not isinstance(payload, dict):
        raise ValueError("JSON request body must be an object")
    model = payload.get("model")
    input_value = payload.get("input")
    stream = payload.get("stream", False)
    if not isinstance(model, str) or not model.strip() or len(model) > 200:
        raise ValueError("model must be a non-empty string of at most 200 characters")
    if not isinstance(input_value, (str, list)) or (
        isinstance(input_value, list) and len(input_value) > 1000
    ):
        raise ValueError("input must be a string or an array with at most 1000 entries")
    if type(stream) is not bool:
        raise ValueError("stream must be true or false")
    if payload.get("background") is True:
        raise ValueError("background Responses are not supported by this gateway")
    return stream


def _parse_response_sse(raw: bytes) -> list[dict[str, Any]]:
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        raise ProviderRequestError("provider returned an invalid Responses stream") from None
    events: list[dict[str, Any]] = []
    for frame in re.split(r"\r?\n\r?\n", text):
        if not frame.strip():
            continue
        lines = frame.splitlines()
        event_name = next((line[6:] for line in lines if line.startswith("event:")), "")
        data_lines = [line[5:].lstrip(" ") for line in lines if line.startswith("data:")]
        if not data_lines:
            events.append({"lines": lines, "event": event_name, "data": None})
            continue
        try:
            data = json.loads("\n".join(data_lines))
        except (json.JSONDecodeError, UnicodeError):
            raise ProviderRequestError("provider returned an invalid Responses event") from None
        if not isinstance(data, dict):
            raise ProviderRequestError("provider returned an invalid Responses event")
        events.append({"lines": lines, "event": event_name, "data": data})
    return events


def _completed_response(events: list[dict[str, Any]]) -> dict[str, Any]:
    completed: dict[str, Any] | None = None
    for event in events:
        data = event.get("data")
        name = event.get("event")
        if completed is not None:
            raise ProviderRequestError("provider Responses stream continued after completion")
        if name == "error" or (
            isinstance(data, dict) and data.get("type") in {"error", "response.failed"}
        ):
            raise ProviderRequestError("provider Responses stream did not complete successfully")
        if name == "response.completed" or (
            isinstance(data, dict) and data.get("type") == "response.completed"
        ):
            response = data.get("response") if isinstance(data, dict) else None
            if not isinstance(response, dict) or not isinstance(response.get("output"), list):
                raise ProviderRequestError("provider returned an invalid completed response")
            completed = response
    if completed is None:
        raise ProviderRequestError("provider Responses stream ended without a completion event")
    return completed


def _responses_sse_strings(events: list[dict[str, Any]]) -> list[str]:
    """Collect every text value that will be exposed in a replayed SSE frame."""
    output: list[str] = []
    for event in events:
        output.extend(_all_strings(event.get("data")))
        event_name = event.get("event")
        if isinstance(event_name, str):
            output.append(event_name)
        lines = event.get("lines", [])
        if isinstance(lines, list):
            output.extend(
                line[1:].strip() for line in lines if isinstance(line, str) and line.startswith(":")
            )
    return output


def _responses_sse_inspection_text(events: list[dict[str, Any]]) -> list[str]:
    """Include parsed values, serialized objects, and replayed non-data SSE fields."""
    output = _responses_sse_strings(events)
    for event in events:
        data = event.get("data")
        if isinstance(data, dict):
            output.append(json.dumps(data, separators=(",", ":"), ensure_ascii=False))
        lines = event.get("lines", [])
        if isinstance(lines, list):
            output.extend(
                line for line in lines if isinstance(line, str) and not line.startswith("data:")
            )
    return output


def _serialize_response_sse(events: list[dict[str, Any]]) -> bytes:
    frames: list[str] = []
    for event in events:
        lines = list(event["lines"])
        data = event.get("data")
        if isinstance(data, dict):
            replaced = False
            output_lines: list[str] = []
            for line in lines:
                if line.startswith("data:"):
                    if not replaced:
                        output_lines.append(
                            "data: " + json.dumps(data, separators=(",", ":"), ensure_ascii=False)
                        )
                        replaced = True
                else:
                    output_lines.append(line)
            if not replaced:
                raise ProviderRequestError("provider returned an invalid Responses event")
            lines = output_lines
        frames.append("\n".join(lines))
    return ("\n\n".join(frames) + "\n\n").encode("utf-8")


_NATIVE_OUTPUT_METADATA = {
    "type",
    "id",
    "role",
    "name",
    "model",
    "modelVersion",
    "responseId",
    "finishReason",
    "stop_reason",
    "stop_sequence",
    "index",
    "mimeType",
    "thoughtSignature",
    "signature",
    "usage",
    "usageMetadata",
    "promptTokenCount",
    "candidatesTokenCount",
    "totalTokenCount",
    "safetyRatings",
    "citationMetadata",
    "groundingMetadata",
}


def _native_output_strings(value: Any, protocol: str, active: bool = False) -> list[str]:
    if isinstance(value, str):
        return [value] if active else []
    if isinstance(value, list):
        return [text for item in value for text in _native_output_strings(item, protocol, active)]
    if not isinstance(value, dict):
        return []
    roots = (
        {"content", "content_block", "delta", "input"}
        if protocol == "anthropic"
        else {"candidates", "promptFeedback"}
    )
    found: list[str] = []
    for child_key, child in value.items():
        if child_key in _NATIVE_OUTPUT_METADATA:
            continue
        if active or child_key in roots:
            found.extend(_native_output_strings(child, protocol, True))
    return found


def _transform_native_output(
    value: Any, protocol: str, transform: Any, active: bool = False
) -> Any:
    if isinstance(value, str):
        return transform(value) if active else value
    if isinstance(value, list):
        return [_transform_native_output(item, protocol, transform, active) for item in value]
    if not isinstance(value, dict):
        return value
    roots = (
        {"content", "content_block", "delta", "input"}
        if protocol == "anthropic"
        else {"candidates", "promptFeedback"}
    )
    return {
        child_key: (
            child
            if child_key in _NATIVE_OUTPUT_METADATA
            else _transform_native_output(child, protocol, transform, active or child_key in roots)
        )
        for child_key, child in value.items()
    }


def _parse_native_sse(raw: bytes, protocol: str) -> list[dict[str, Any]]:
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        raise ProviderRequestError("provider returned an invalid native SSE stream") from None
    frames: list[dict[str, Any]] = []
    for frame_text in re.split(r"\r?\n\r?\n", text):
        if not frame_text.strip():
            continue
        lines = frame_text.splitlines()
        event_name = ""
        data_lines: list[str] = []
        for line in lines:
            if line.startswith("event:"):
                event_name = line[6:].strip()
            elif line.startswith("data:"):
                data_lines.append(line[5:].lstrip(" "))
        data: dict[str, Any] | None = None
        if data_lines:
            try:
                decoded = json.loads("\n".join(data_lines))
            except (UnicodeError, json.JSONDecodeError):
                raise ProviderRequestError(
                    "provider returned an invalid native SSE event"
                ) from None
            if not isinstance(decoded, dict):
                raise ProviderRequestError("provider returned an invalid native SSE event")
            data = decoded
        if protocol == "anthropic":
            if event_name == "error" or (data and data.get("type") == "error"):
                raise ProviderRequestError("Anthropic stream ended with an error event")
            declared_type = data.get("type") if data else None
            if event_name and isinstance(declared_type, str) and event_name != declared_type:
                raise ProviderRequestError("Anthropic stream event type did not match its payload")
        elif data and data.get("error"):
            raise ProviderRequestError("Gemini stream ended with an error event")
        frames.append({"lines": lines, "event": event_name, "data": data})

    if not frames:
        raise ProviderRequestError("provider returned an empty native SSE stream")
    if protocol == "anthropic":
        names = [frame["event"] for frame in frames if frame["event"]]
        try:
            start = names.index("message_start")
            stop = names.index("message_stop")
        except ValueError:
            raise ProviderRequestError(
                "Anthropic stream ended without its message lifecycle"
            ) from None
        if start > stop or any(name == "message_stop" for name in names[stop + 1 :]):
            raise ProviderRequestError("Anthropic stream contained an invalid message lifecycle")
        if any(name == "message_start" for name in names[start + 1 :]):
            raise ProviderRequestError("Anthropic stream contained duplicate message starts")
        if any(
            frame["event"]
            and index
            > next(idx for idx, item in enumerate(frames) if item["event"] == "message_stop")
            for index, frame in enumerate(frames)
        ):
            raise ProviderRequestError("Anthropic stream continued after message_stop")
    else:
        has_candidate = any(
            isinstance(frame.get("data", {}).get("candidates"), list)
            or isinstance(frame.get("data", {}).get("promptFeedback"), dict)
            for frame in frames
            if isinstance(frame.get("data"), dict)
        )
        if not has_candidate:
            raise ProviderRequestError("Gemini stream contained no candidate response")
    return frames


def _serialize_native_sse(frames: list[dict[str, Any]]) -> bytes:
    serialized: list[str] = []
    for frame in frames:
        lines = frame["lines"]
        data = frame.get("data")
        if isinstance(data, dict):
            output_lines: list[str] = []
            replaced = False
            for line in lines:
                if line.startswith("data:"):
                    if not replaced:
                        output_lines.append(
                            "data: " + json.dumps(data, separators=(",", ":"), ensure_ascii=False)
                        )
                        replaced = True
                else:
                    output_lines.append(line)
            if not replaced:
                raise ProviderRequestError("provider returned an invalid native SSE event")
            lines = output_lines
        serialized.append("\n".join(lines))
    return ("\n\n".join(serialized) + "\n\n").encode("utf-8")


def _validate_native_response(value: Any, protocol: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ProviderRequestError("provider returned a non-object response")
    if protocol == "anthropic" and (
        value.get("type") != "message" or not isinstance(value.get("content"), list)
    ):
        raise ProviderRequestError("Anthropic returned an unsupported Messages response")
    if protocol == "gemini" and not (
        isinstance(value.get("candidates"), list) or isinstance(value.get("promptFeedback"), dict)
    ):
        raise ProviderRequestError("Gemini returned an unsupported GenerateContent response")
    return value


def create_app(
    settings: Settings,
    *,
    http_client: Any | None = None,
    input_scanners: list[Any] | None = None,
    output_scanners: list[Any] | None = None,
    a2a_base_url: str = "http://127.0.0.1:8080",
) -> FastAPI:
    """Create the app. Inject dependencies in tests; production pools HTTPX."""
    if settings.a2a_enabled and not settings.require_local_auth:
        raise ValueError("A2A facade requires local bearer authentication")
    local_token = read_local_token(settings)
    if settings.llm_guard_enabled:
        if input_scanners is None or output_scanners is None:
            defaults_in, defaults_out = build_default_scanners()
            input_scanners = defaults_in if input_scanners is None else input_scanners
            output_scanners = defaults_out if output_scanners is None else output_scanners

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        owned = None
        if http_client is None:
            try:
                import httpx
            except ImportError:
                raise RuntimeError("HTTPX is required to start Blue Ice Project") from None
            owned = httpx.AsyncClient(
                timeout=30.0,
                limits=httpx.Limits(max_connections=32, max_keepalive_connections=16),
                follow_redirects=False,
            )
        app.state.http_client = http_client or owned
        try:
            yield
        finally:
            if owned is not None:
                await owned.aclose()

    app = FastAPI(
        title="Blue Ice Project LLM Proxy",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
        lifespan=lifespan,
    )

    @app.exception_handler(AuditUnavailable)
    async def audit_unavailable_handler(_request: Request, _exc: AuditUnavailable) -> JSONResponse:
        return _audit_unavailable_response()

    app.add_middleware(RequestSizeLimitMiddleware, max_bytes=settings.max_request_bytes)

    async def require_local_auth(
        request: Request, *, protocol: str | None = None
    ) -> Response | None:
        if not settings.require_local_auth:
            return None
        header = request.headers.get("authorization", "")
        supplied = header[7:].strip() if header.lower().startswith("bearer ") else ""
        if not supplied and protocol == "anthropic":
            supplied = request.headers.get("x-api-key", "").strip()
        if not supplied and protocol == "gemini":
            supplied = request.headers.get("x-goog-api-key", "").strip()
        if not local_token or not supplied or not hmac.compare_digest(supplied, local_token):
            return JSONResponse(
                status_code=401,
                content={
                    "error": {
                        "message": "Valid local Blue Ice Project bearer token required",
                        "type": "authentication_error",
                    }
                },
                headers={"WWW-Authenticate": "Bearer"},
            )
        return None

    @app.middleware("http")
    async def authenticate_a2a(request: Request, call_next: Any) -> Response:
        if settings.a2a_enabled and request.url.path.rstrip("/") == "/a2a":
            denied = await require_local_auth(request)
            if denied:
                return denied
        return await call_next(request)

    @app.get("/healthz")
    async def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/v1/models")
    async def models(request: Request) -> Response:
        denied = await require_local_auth(request)
        if denied:
            return denied
        key = resolve_provider_key(settings)
        if settings.provider != "ollama" and not key:
            return JSONResponse(
                status_code=503,
                content={
                    "error": {
                        "message": "No API credential is configured for the selected provider",
                        "type": "configuration_error",
                    }
                },
            )
        try:
            model_rows = await forward_models(
                provider=settings.provider,
                api_key=key,
                client=request.app.state.http_client,
                endpoint_url=dict(settings.custom_provider_urls).get(settings.provider),
                models_url=dict(settings.custom_models_urls).get(settings.provider),
                max_response_bytes=settings.max_response_bytes,
            )
            headers: dict[str, str] = {}
        except ProviderRequestError as exc:
            if exc.status_code not in {404, 405, 501}:
                return JSONResponse(
                    status_code=502,
                    content={
                        "error": {
                            "message": "Could not retrieve models from the selected provider",
                            "type": "provider_error",
                        }
                    },
                )
            model_rows = [
                {
                    "id": settings.model,
                    "object": "model",
                    "created": 0,
                    "owned_by": "blue-ice-project",
                }
            ]
            headers = {"X-Blue-Ice-Models-Source": "configured-fallback"}
        except (ValueError, TypeError):
            return JSONResponse(
                status_code=502,
                content={
                    "error": {
                        "message": "Could not retrieve models from the selected provider",
                        "type": "provider_error",
                    }
                },
            )
        return JSONResponse(content={"object": "list", "data": model_rows}, headers=headers)

    @app.post("/v1/chat/completions")
    async def chat_completions(request: Request) -> Response:
        denied = await require_local_auth(request)
        if denied:
            return denied
        started = time.monotonic()
        vault = SessionVault(ttl_seconds=180.0)
        redacted_count = 0
        audit_rules: list[str] = []
        key: str | None = None
        try:
            try:
                payload = await request.json()
            except Exception:
                raise ValueError("Request body must be valid JSON") from None
            messages, stream = _validate_chat_payload(payload)
            path_findings = inspect_messages(
                messages, settings.project_root, settings.privacyignore_rules
            )
            if path_findings:
                audit_rules = sorted(
                    {str(finding.get("code", "path_policy_block")) for finding in path_findings}
                )
                raise PolicyBlocked(
                    audit_rules,
                    public_message="Message references a path outside the permitted project context",
                )

            clean_payload = copy.deepcopy(payload)

            def redact(value: str) -> str:
                nonlocal redacted_count
                value, count = redact_text(value, vault)
                redacted_count += count
                if settings.llm_guard_enabled:
                    value, changed = scan_input(value, input_scanners or [])
                    redacted_count += changed
                return value

            clean_payload = _transform_strings(clean_payload, redact)
            # The upstream is always called in buffered mode so no uninspected
            # provider chunk can reach the coding client. SSE is recreated below.
            upstream_payload = dict(clean_payload)
            upstream_payload["stream"] = False
            if settings.provider == "openrouter":
                upstream_payload.pop("stream_options", None)
            key = resolve_provider_key(settings)
            if settings.provider != "ollama" and not key:
                raise ProviderRequestError(
                    "No API credential is configured for the selected provider"
                )

            raw_response = await forward_chat(
                upstream_payload,
                provider=settings.provider,
                api_key=key,
                client=request.app.state.http_client,
                endpoint_url=dict(settings.custom_provider_urls).get(settings.provider),
                max_response_bytes=settings.max_response_bytes,
            )
            if not isinstance(raw_response, dict):
                raise ProviderRequestError("provider returned a non-object response")
            response_body = raw_response
            assistant_strings = _assistant_texts(response_body)
            reconstructed_prompt = "\n".join(_all_strings(clean_payload.get("messages", [])))
            if settings.llm_guard_enabled:
                output_texts: list[str] = []
                for text in assistant_strings:
                    scanned, _changed = scan_output(
                        text, reconstructed_prompt, output_scanners or []
                    )
                    output_texts.append(scanned)
                iterator = iter(output_texts)

                def replace_scanned(value: str) -> str:
                    # The same string can occur more than once; preserve traversal order.
                    return next(iterator, value)

                response_body = _replace_assistant_strings(response_body, replace_scanned)
                assistant_strings = _assistant_texts(response_body)

            combined_output = "\n".join(assistant_strings)
            firewall_findings = inspect_output(
                combined_output, allowed_domains=settings.allowed_domains
            )
            if firewall_findings:
                audit_rules = sorted({str(item["rule"]) for item in firewall_findings})
                raise PolicyBlocked(
                    audit_rules,
                    public_message="Provider response blocked by Blue Ice Project egress policy",
                )

            if settings.registry_checks:
                # Registry queries are explicit opt-in because package names are
                # sent to public registries. Unknown/unsafe package results block.
                found_packages = extract_packages(combined_output)
                package_findings = await check_packages(
                    combined_output, client=request.app.state.http_client, cache=None
                )
                suspicious = [
                    item
                    for item in package_findings
                    if item.get("reason")
                    in {"not_found", "recently_created", "verification_unavailable"}
                ]
                supported = {"pypi", "npm"}
                unknown = [item for item in found_packages if item["ecosystem"] not in supported]
                if suspicious or unknown:
                    audit_rules = [
                        "package_registry_risk" if suspicious else "package_registry_unverified"
                    ]
                    raise PolicyBlocked(
                        audit_rules,
                        public_message="Provider response blocked by package safety policy",
                    )

            vault_mapping = _collect_vault_mapping(clean_payload, vault)

            def restore(value: str) -> str:
                restored, _counts = reconstruct(value, vault=vault_mapping)
                return restored

            restore_count = 0

            def restore_and_count(value: str) -> str:
                nonlocal restore_count
                restore_count += sum(value.count(placeholder) for placeholder in vault_mapping)
                restored, _counts = reconstruct(value, vault=vault_mapping)
                return restored

            response_body = _replace_assistant_strings(response_body, restore_and_count)
            final_output = "\n".join(_assistant_texts(response_body))
            final_findings = inspect_output(final_output, allowed_domains=settings.allowed_domains)
            if final_findings:
                audit_rules = sorted({str(item["rule"]) for item in final_findings})
                raise PolicyBlocked(
                    audit_rules,
                    public_message="Reconstructed provider response blocked by Blue Ice Project egress policy",
                )
            elapsed_ms = int((time.monotonic() - started) * 1000)
            try:
                await asyncio.to_thread(
                    append_event,
                    settings.audit_path,
                    event="chat_request",
                    outcome="allowed",
                    provider=settings.provider,
                    counts={"secrets_redacted": redacted_count, "secrets_restored": restore_count},
                    latency_ms=elapsed_ms,
                )
            except OSError:
                # The provider call has completed, but Blue Ice Project withholds the result
                # if its local audit cannot be written.
                raise RuntimeError("Local audit write failed; response withheld") from None
            return (
                _stream_response(response_body) if stream else JSONResponse(content=response_body)
            )
        except PolicyBlocked as exc:
            audit_rules = exc.rules
            await _safe_audit(
                settings,
                event="chat_blocked",
                outcome="blocked",
                provider=settings.provider,
                counts={"secrets_redacted": redacted_count},
                rules=audit_rules,
                latency_ms=int((time.monotonic() - started) * 1000),
            )
            return JSONResponse(
                status_code=403,
                content={
                    "error": {
                        "message": str(exc),
                        "type": "aegis_policy_block",
                        "rules": audit_rules,
                    }
                },
            )
        except (ValueError, ScanRejected) as exc:
            code = "scanner_rejected" if isinstance(exc, ScanRejected) else "invalid_request"
            await _safe_audit(
                settings,
                event="chat_blocked",
                outcome="blocked",
                provider=settings.provider,
                counts={"secrets_redacted": redacted_count},
                rules=[code],
                latency_ms=int((time.monotonic() - started) * 1000),
            )
            return JSONResponse(
                status_code=400 if code == "invalid_request" else 403,
                content={"error": {"message": str(exc), "type": code}},
            )
        except ScannerUnavailable:
            await _safe_audit(
                settings,
                event="chat_blocked",
                outcome="blocked",
                provider=settings.provider,
                counts={"secrets_redacted": redacted_count},
                rules=["scanner_unavailable"],
                latency_ms=int((time.monotonic() - started) * 1000),
            )
            return JSONResponse(
                status_code=503,
                content={
                    "error": {
                        "message": "Configured scanner is unavailable; request blocked",
                        "type": "scanner_unavailable",
                    }
                },
            )
        except ProviderRequestError as exc:
            await _safe_audit(
                settings,
                event="chat_error",
                outcome="error",
                provider=settings.provider,
                counts={"secrets_redacted": redacted_count},
                rules=["provider_error"],
                latency_ms=int((time.monotonic() - started) * 1000),
            )
            status = exc.status_code if exc.status_code and 400 <= exc.status_code < 500 else 502
            return JSONResponse(
                status_code=status,
                content={"error": {"message": str(exc), "type": "provider_error"}},
            )
        except Exception:
            await _safe_audit(
                settings,
                event="chat_error",
                outcome="error",
                provider=settings.provider,
                counts={"secrets_redacted": redacted_count},
                rules=["internal_error"],
                latency_ms=int((time.monotonic() - started) * 1000),
            )
            return JSONResponse(
                status_code=503,
                content={
                    "error": {
                        "message": "Blue Ice Project could not safely complete this request",
                        "type": "aegis_error",
                    }
                },
            )
        finally:
            key = None
            vault.clear()

    async def native_endpoint(
        request: Request,
        *,
        protocol: str,
        model: str | None = None,
        gemini_stream: bool = False,
    ) -> Response:
        denied = await require_local_auth(request, protocol=protocol)
        if denied:
            return denied
        enabled = (
            settings.native_anthropic_enabled
            if protocol == "anthropic"
            else settings.native_gemini_enabled
        )
        if not enabled:
            return JSONResponse(
                status_code=501,
                content={
                    "error": {
                        "message": f"Native {protocol.title()} adapter is disabled by local policy",
                        "type": "protocol_adapter_disabled",
                    }
                },
            )

        started = time.monotonic()
        audit_prefix = "anthropic" if protocol == "anthropic" else "gemini"
        provider_name = "anthropic" if protocol == "anthropic" else "google"
        vault = SessionVault(ttl_seconds=180.0)
        redacted_count = 0
        audit_rules: list[str] = []
        key: str | None = None
        try:
            try:
                payload = await request.json()
            except Exception:
                raise ValueError("Request body must be valid JSON") from None
            if not isinstance(payload, dict):
                raise ValueError("JSON request body must be an object")
            if protocol == "anthropic":
                if not isinstance(payload.get("model"), str) or not payload["model"].strip():
                    raise ValueError("model must be a non-empty string")
                if not isinstance(payload.get("messages"), list) or not payload["messages"]:
                    raise ValueError("messages must be a non-empty array")
                stream = payload.get("stream", False)
                if type(stream) is not bool:
                    raise ValueError("stream must be true or false")
            else:
                stream = gemini_stream
                if "stream" in payload:
                    raise ValueError("Gemini streaming is selected by the native endpoint path")
                if not isinstance(payload.get("contents"), list) or not payload["contents"]:
                    raise ValueError("contents must be a non-empty array")
                if not isinstance(model, str) or not re.fullmatch(r"[A-Za-z0-9._-]{1,120}", model):
                    raise ValueError("Gemini model path is invalid")

            inspected_text = "\n".join(_all_strings(payload))
            path_findings = inspect_messages(
                [{"role": "user", "content": inspected_text}],
                settings.project_root,
                settings.privacyignore_rules,
            )
            if path_findings:
                audit_rules = sorted(
                    {str(finding.get("code", "path_policy_block")) for finding in path_findings}
                )
                raise PolicyBlocked(
                    audit_rules,
                    public_message="Request references a path outside the permitted project context",
                )

            def redact(value: str) -> str:
                nonlocal redacted_count
                value, count = redact_text(value, vault)
                redacted_count += count
                if settings.llm_guard_enabled:
                    value, changed = scan_input(value, input_scanners or [])
                    redacted_count += changed
                return value

            clean_payload = _transform_strings(copy.deepcopy(payload), redact)
            key = resolve_provider_key(settings, provider_name)
            if not key:
                raise ProviderRequestError(
                    f"No API credential is configured for native {protocol.title()}",
                    status_code=503,
                )
            if protocol == "anthropic":
                raw_response = await forward_anthropic_messages(
                    clean_payload,
                    api_key=key,
                    client=request.app.state.http_client,
                    max_response_bytes=settings.max_response_bytes,
                    client_headers=request.headers,
                )
            else:
                raw_response = await forward_gemini_generate_content(
                    model or "",
                    clean_payload,
                    api_key=key,
                    client=request.app.state.http_client,
                    max_response_bytes=settings.max_response_bytes,
                    stream=stream,
                )

            if stream:
                if not isinstance(raw_response, bytes):
                    raise ProviderRequestError("provider returned an invalid native SSE stream")
                frames = _parse_native_sse(raw_response, protocol)
                response_body: dict[str, Any] | None = None
                output_values = [
                    text
                    for frame in frames
                    for text in _native_output_strings(frame.get("data"), protocol)
                ]
            else:
                if isinstance(raw_response, bytes):
                    raise ProviderRequestError("provider returned an invalid native response")
                response_body = _validate_native_response(raw_response, protocol)
                frames = []
                output_values = _native_output_strings(response_body, protocol)

            reconstructed_prompt = "\n".join(_all_strings(clean_payload))
            if settings.llm_guard_enabled:
                scanned = [
                    scan_output(text, reconstructed_prompt, output_scanners or [])[0]
                    for text in output_values
                ]
                iterator = iter(scanned)

                def replace_scanned(value: str) -> str:
                    return next(iterator, value)

                if stream:
                    for frame in frames:
                        if isinstance(frame.get("data"), dict):
                            frame["data"] = _transform_native_output(
                                frame["data"], protocol, replace_scanned
                            )
                else:
                    response_body = _transform_native_output(
                        response_body, protocol, replace_scanned
                    )
                output_values = (
                    [
                        text
                        for frame in frames
                        for text in _native_output_strings(frame.get("data"), protocol)
                    ]
                    if stream
                    else _native_output_strings(response_body, protocol)
                )

            vault_mapping = _collect_vault_mapping(clean_payload, vault)
            restore_count = sum(
                text.count(placeholder) for text in output_values for placeholder in vault_mapping
            )

            def restore(value: str) -> str:
                restored, _counts = reconstruct(value, vault=vault_mapping)
                return restored

            if stream:
                for frame in frames:
                    if isinstance(frame.get("data"), dict):
                        frame["data"] = _transform_native_output(frame["data"], protocol, restore)
                output_values = [
                    text
                    for frame in frames
                    for text in _native_output_strings(frame.get("data"), protocol)
                ]
                serialized = _serialize_native_sse(frames)
                output_values.extend(
                    line
                    for frame in frames
                    for line in frame["lines"]
                    if not line.startswith("data:")
                )
            else:
                response_body = _transform_native_output(response_body, protocol, restore)
                output_values = _native_output_strings(response_body, protocol)
                serialized = b""

            combined_output = "\n".join(output_values)
            firewall_findings = inspect_output(
                combined_output, allowed_domains=settings.allowed_domains
            )
            if firewall_findings:
                audit_rules = sorted({str(item["rule"]) for item in firewall_findings})
                raise PolicyBlocked(
                    audit_rules,
                    public_message="Provider response blocked by Blue Ice Project egress policy",
                )
            if settings.registry_checks:
                found_packages = extract_packages(combined_output)
                package_findings = await check_packages(
                    combined_output, client=request.app.state.http_client, cache=None
                )
                suspicious = [
                    item
                    for item in package_findings
                    if item.get("reason")
                    in {"not_found", "recently_created", "verification_unavailable"}
                ]
                unknown = [
                    item for item in found_packages if item["ecosystem"] not in {"pypi", "npm"}
                ]
                if suspicious or unknown:
                    audit_rules = [
                        "package_registry_risk" if suspicious else "package_registry_unverified"
                    ]
                    raise PolicyBlocked(
                        audit_rules,
                        public_message="Provider response blocked by package safety policy",
                    )

            await asyncio.to_thread(
                append_event,
                settings.audit_path,
                event=f"{audit_prefix}_request",
                outcome="allowed",
                provider=provider_name,
                counts={"secrets_redacted": redacted_count, "secrets_restored": restore_count},
                latency_ms=int((time.monotonic() - started) * 1000),
            )
            if stream:
                return Response(
                    content=serialized,
                    media_type="text/event-stream",
                    headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
                )
            return JSONResponse(content=response_body)
        except PolicyBlocked as exc:
            audit_rules = exc.rules
            await _safe_audit(
                settings,
                event=f"{audit_prefix}_blocked",
                outcome="blocked",
                provider=provider_name,
                counts={"secrets_redacted": redacted_count},
                rules=audit_rules,
                latency_ms=int((time.monotonic() - started) * 1000),
            )
            return JSONResponse(
                status_code=403,
                content={
                    "error": {
                        "message": str(exc),
                        "type": "aegis_policy_block",
                        "rules": audit_rules,
                    }
                },
            )
        except (ValueError, ScanRejected) as exc:
            code = "scanner_rejected" if isinstance(exc, ScanRejected) else "invalid_request"
            await _safe_audit(
                settings,
                event=f"{audit_prefix}_blocked",
                outcome="blocked",
                provider=provider_name,
                counts={"secrets_redacted": redacted_count},
                rules=[code],
                latency_ms=int((time.monotonic() - started) * 1000),
            )
            return JSONResponse(
                status_code=400 if code == "invalid_request" else 403,
                content={"error": {"message": str(exc), "type": code}},
            )
        except ScannerUnavailable:
            await _safe_audit(
                settings,
                event=f"{audit_prefix}_blocked",
                outcome="blocked",
                provider=provider_name,
                counts={"secrets_redacted": redacted_count},
                rules=["scanner_unavailable"],
                latency_ms=int((time.monotonic() - started) * 1000),
            )
            return JSONResponse(
                status_code=503,
                content={
                    "error": {
                        "message": "Configured scanner is unavailable; request blocked",
                        "type": "scanner_unavailable",
                    }
                },
            )
        except ProviderRequestError as exc:
            await _safe_audit(
                settings,
                event=f"{audit_prefix}_error",
                outcome="error",
                provider=provider_name,
                counts={"secrets_redacted": redacted_count},
                rules=["provider_error"],
                latency_ms=int((time.monotonic() - started) * 1000),
            )
            status = (
                exc.status_code
                if exc.status_code and 400 <= exc.status_code < 500
                else (503 if exc.status_code == 503 else 502)
            )
            return JSONResponse(
                status_code=status,
                content={"error": {"message": str(exc), "type": "provider_error"}},
            )
        except Exception:
            await _safe_audit(
                settings,
                event=f"{audit_prefix}_error",
                outcome="error",
                provider=provider_name,
                counts={"secrets_redacted": redacted_count},
                rules=["internal_error"],
                latency_ms=int((time.monotonic() - started) * 1000),
            )
            return JSONResponse(
                status_code=503,
                content={
                    "error": {
                        "message": "Blue Ice Project could not safely complete this request",
                        "type": "aegis_error",
                    }
                },
            )
        finally:
            key = None
            vault.clear()

    @app.post("/v1/messages")
    async def anthropic_messages(request: Request) -> Response:
        return await native_endpoint(request, protocol="anthropic")

    @app.post("/v1beta/models/{model}:generateContent")
    async def gemini_generate_content(model: str, request: Request) -> Response:
        return await native_endpoint(request, protocol="gemini", model=model)

    @app.post("/v1beta/models/{model}:streamGenerateContent")
    async def gemini_stream_generate_content(model: str, request: Request) -> Response:
        return await native_endpoint(request, protocol="gemini", model=model, gemini_stream=True)

    @app.post("/v1/responses")
    async def responses(request: Request) -> Response:
        denied = await require_local_auth(request)
        if denied:
            return denied
        responses_endpoint = dict(settings.custom_responses_urls).get(settings.provider)
        if settings.provider != "openai" and responses_endpoint is None:
            return JSONResponse(
                status_code=501,
                content={
                    "error": {
                        "message": "The selected provider has no configured native Responses API",
                        "type": "responses_api_unsupported",
                    }
                },
            )
        started = time.monotonic()
        vault = SessionVault(ttl_seconds=180.0)
        redacted_count = 0
        audit_rules: list[str] = []
        key: str | None = None
        try:
            try:
                payload = await request.json()
            except Exception:
                raise ValueError("Request body must be valid JSON") from None
            stream = _validate_responses_payload(payload)
            path_findings = inspect_messages(
                [{"role": "user", "content": "\n".join(_all_strings(payload))}],
                settings.project_root,
                settings.privacyignore_rules,
            )
            if path_findings:
                audit_rules = sorted(
                    {str(finding.get("code", "path_policy_block")) for finding in path_findings}
                )
                raise PolicyBlocked(
                    audit_rules,
                    public_message="Request references a path outside the permitted project context",
                )

            def redact(value: str) -> str:
                nonlocal redacted_count
                value, count = redact_text(value, vault)
                redacted_count += count
                if settings.llm_guard_enabled:
                    value, changed = scan_input(value, input_scanners or [])
                    redacted_count += changed
                return value

            clean_payload = _transform_strings(copy.deepcopy(payload), redact)
            key = resolve_provider_key(settings)
            if not key:
                raise ProviderRequestError(
                    "No API credential is configured for the selected provider"
                )
            raw_response = await forward_responses(
                settings.provider,
                clean_payload,
                api_key=key,
                client=request.app.state.http_client,
                max_response_bytes=settings.max_response_bytes,
                endpoint_url=responses_endpoint,
            )
            reconstructed_prompt = "\n".join(_all_strings(clean_payload.get("input")))
            vault_mapping = _collect_vault_mapping(clean_payload, vault)
            restore_count = 0

            if stream:
                if not isinstance(raw_response, bytes):
                    raise ProviderRequestError("provider returned an invalid Responses stream")
                events = _parse_response_sse(raw_response)
                _completed_response(events)
                output_strings = _responses_sse_strings(events)
                if settings.llm_guard_enabled:
                    for text in output_strings:
                        _scanned, changed = scan_output(
                            text, reconstructed_prompt, output_scanners or []
                        )
                        if changed:
                            raise PolicyBlocked(
                                ["llm_guard_stream_rewrite_unsupported"],
                                public_message="Responses stream withheld because the configured scanner requires output rewriting",
                            )
                restore_count = sum(
                    text.count(placeholder)
                    for text in output_strings
                    for placeholder in vault_mapping
                )

                def restore_event(value: str) -> str:
                    restored, _counts = reconstruct(value, vault=vault_mapping)
                    return restored

                for event in events:
                    if isinstance(event.get("data"), dict):
                        event["data"] = _transform_strings(event["data"], restore_event)
                _completed_response(events)
                output_texts = _responses_sse_inspection_text(events)
                combined_output = "\n".join(output_texts)
                sse_body = _serialize_response_sse(events)
            else:
                if not isinstance(raw_response, dict):
                    raise ProviderRequestError("provider returned a non-object response")
                response_body = raw_response
                output = response_body.get("output")
                if not isinstance(output, list):
                    raise ProviderRequestError("provider returned an invalid Responses output")
                output_strings = _all_strings(output)
                if settings.llm_guard_enabled:
                    scanned_strings = [
                        scan_output(text, reconstructed_prompt, output_scanners or [])[0]
                        for text in output_strings
                    ]
                    iterator = iter(scanned_strings)

                    def replace_scanned(value: str) -> str:
                        return next(iterator, value)

                    output = _transform_strings(output, replace_scanned)
                restore_count = sum(
                    text.count(placeholder)
                    for text in _all_strings(output)
                    for placeholder in vault_mapping
                )

                def restore_output(value: str) -> str:
                    restored, _counts = reconstruct(value, vault=vault_mapping)
                    return restored

                response_body["output"] = _transform_strings(output, restore_output)
                output_texts = _all_strings(response_body["output"])
                combined_output = "\n".join(output_texts)

            firewall_findings = inspect_output(
                combined_output, allowed_domains=settings.allowed_domains
            )
            if firewall_findings:
                audit_rules = sorted({str(item["rule"]) for item in firewall_findings})
                raise PolicyBlocked(
                    audit_rules,
                    public_message="Provider response blocked by Blue Ice Project egress policy",
                )
            if settings.registry_checks:
                found_packages = extract_packages(combined_output)
                package_findings = await check_packages(
                    combined_output, client=request.app.state.http_client, cache=None
                )
                suspicious = [
                    item
                    for item in package_findings
                    if item.get("reason")
                    in {"not_found", "recently_created", "verification_unavailable"}
                ]
                unknown = [
                    item for item in found_packages if item["ecosystem"] not in {"pypi", "npm"}
                ]
                if suspicious or unknown:
                    audit_rules = [
                        "package_registry_risk" if suspicious else "package_registry_unverified"
                    ]
                    raise PolicyBlocked(
                        audit_rules,
                        public_message="Provider response blocked by package safety policy",
                    )

            try:
                await asyncio.to_thread(
                    append_event,
                    settings.audit_path,
                    event="response_request",
                    outcome="allowed",
                    provider=settings.provider,
                    counts={"secrets_redacted": redacted_count, "secrets_restored": restore_count},
                    latency_ms=int((time.monotonic() - started) * 1000),
                )
            except OSError:
                raise RuntimeError("Local audit write failed; response withheld") from None
            if stream:
                return Response(
                    content=sse_body,
                    media_type="text/event-stream",
                    headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
                )
            return JSONResponse(content=response_body)
        except PolicyBlocked as exc:
            audit_rules = exc.rules
            await _safe_audit(
                settings,
                event="response_blocked",
                outcome="blocked",
                provider=settings.provider,
                counts={"secrets_redacted": redacted_count},
                rules=audit_rules,
                latency_ms=int((time.monotonic() - started) * 1000),
            )
            return JSONResponse(
                status_code=403,
                content={
                    "error": {
                        "message": str(exc),
                        "type": "aegis_policy_block",
                        "rules": audit_rules,
                    }
                },
            )
        except (ValueError, ScanRejected) as exc:
            code = "scanner_rejected" if isinstance(exc, ScanRejected) else "invalid_request"
            await _safe_audit(
                settings,
                event="response_blocked",
                outcome="blocked",
                provider=settings.provider,
                counts={"secrets_redacted": redacted_count},
                rules=[code],
                latency_ms=int((time.monotonic() - started) * 1000),
            )
            return JSONResponse(
                status_code=400 if code == "invalid_request" else 403,
                content={"error": {"message": str(exc), "type": code}},
            )
        except ScannerUnavailable:
            await _safe_audit(
                settings,
                event="response_blocked",
                outcome="blocked",
                provider=settings.provider,
                counts={"secrets_redacted": redacted_count},
                rules=["scanner_unavailable"],
                latency_ms=int((time.monotonic() - started) * 1000),
            )
            return JSONResponse(
                status_code=503,
                content={
                    "error": {
                        "message": "Configured scanner is unavailable; request blocked",
                        "type": "scanner_unavailable",
                    }
                },
            )
        except ProviderRequestError as exc:
            await _safe_audit(
                settings,
                event="response_error",
                outcome="error",
                provider=settings.provider,
                counts={"secrets_redacted": redacted_count},
                rules=["provider_error"],
                latency_ms=int((time.monotonic() - started) * 1000),
            )
            status = exc.status_code if exc.status_code and 400 <= exc.status_code < 500 else 502
            return JSONResponse(
                status_code=status,
                content={"error": {"message": str(exc), "type": "provider_error"}},
            )
        except Exception:
            await _safe_audit(
                settings,
                event="response_error",
                outcome="error",
                provider=settings.provider,
                counts={"secrets_redacted": redacted_count},
                rules=["internal_error"],
                latency_ms=int((time.monotonic() - started) * 1000),
            )
            return JSONResponse(
                status_code=503,
                content={
                    "error": {
                        "message": "Blue Ice Project could not safely complete this request",
                        "type": "aegis_error",
                    }
                },
            )
        finally:
            key = None
            vault.clear()

    if settings.a2a_enabled:
        try:
            from a2a.helpers import new_text_message
            from a2a.server.agent_execution import AgentExecutor
            from a2a.server.request_handlers import DefaultRequestHandler
            from a2a.server.routes import create_agent_card_routes, create_jsonrpc_routes
            from a2a.server.tasks import InMemoryTaskStore
            from a2a.types import AgentCapabilities, AgentCard, AgentInterface, AgentSkill
        except ImportError as exc:
            raise RuntimeError(
                "A2A support requires the optional dependency group: pip install 'blue-ice-project[a2a]'"
            ) from exc

        class A2AInvocationError(RuntimeError):
            pass

        async def invoke_a2a_text(text: str, context_id: str | None, task_id: str | None) -> str:
            if len(text.encode("utf-8")) > settings.max_request_bytes:
                raise A2AInvocationError("A2A text input exceeds the configured request limit")
            body = json.dumps(
                {
                    "model": settings.model,
                    "messages": [{"role": "user", "content": text}],
                    "stream": False,
                },
                separators=(",", ":"),
            ).encode("utf-8")
            headers = [
                (b"content-type", b"application/json"),
                (b"content-length", str(len(body)).encode("ascii")),
            ]
            if local_token:
                headers.append((b"authorization", f"Bearer {local_token}".encode("ascii")))
            scope = {
                "type": "http",
                "asgi": {"version": "3.0", "spec_version": "2.3"},
                "http_version": "1.1",
                "method": "POST",
                "scheme": "http",
                "path": "/v1/chat/completions",
                "raw_path": b"/v1/chat/completions",
                "query_string": b"",
                "headers": headers,
                "server": ("127.0.0.1", 8080),
                "client": ("127.0.0.1", 0),
                "root_path": "",
                "app": app,
            }
            sent = False

            async def receive() -> dict[str, Any]:
                nonlocal sent
                if sent:
                    return {"type": "http.disconnect"}
                sent = True
                return {"type": "http.request", "body": body, "more_body": False}

            internal_request = Request(scope, receive)
            result = await chat_completions(internal_request)
            if result.status_code != 200 or not isinstance(result, JSONResponse):
                outcome = "blocked" if result.status_code in {400, 403} else "error"
                await asyncio.to_thread(
                    append_event,
                    settings.audit_path,
                    event="a2a_blocked" if outcome == "blocked" else "a2a_error",
                    outcome=outcome,
                    provider=settings.provider,
                    rules=[
                        "delegated_request_blocked"
                        if outcome == "blocked"
                        else "delegated_request_error"
                    ],
                )
                raise A2AInvocationError(
                    "Delegated request was blocked by policy"
                    if outcome == "blocked"
                    else "Delegated request could not be safely completed"
                )
            try:
                response_body = json.loads(result.body)
                message = response_body["choices"][0]["message"]
                content = message.get("content")
                if isinstance(content, str):
                    answer = content
                elif isinstance(content, list):
                    answer = "\n".join(
                        item["text"]
                        for item in content
                        if isinstance(item, dict) and isinstance(item.get("text"), str)
                    )
                else:
                    raise ValueError
            except (KeyError, IndexError, TypeError, ValueError, json.JSONDecodeError):
                raise A2AInvocationError("Gateway returned an unsupported text response") from None
            await asyncio.to_thread(
                append_event,
                settings.audit_path,
                event="a2a_request",
                outcome="allowed",
                provider=settings.provider,
            )
            return answer

        class BlueIceA2AExecutor(AgentExecutor):
            async def execute(self, context: Any, event_queue: Any) -> None:
                message = context.message
                if message is None or not message.parts:
                    raise A2AInvocationError("A2A requires at least one text part")
                if any(not part.HasField("text") for part in message.parts):
                    raise A2AInvocationError("A2A facade accepts text/plain parts only")
                text = context.get_user_input()
                if not text.strip():
                    raise A2AInvocationError("A2A text input must not be empty")
                answer = await invoke_a2a_text(text, context.context_id, context.task_id)
                await event_queue.enqueue_event(
                    new_text_message(
                        answer,
                        media_type="text/plain",
                        context_id=context.context_id,
                        task_id=context.task_id,
                    )
                )

            async def cancel(self, context: Any, event_queue: Any) -> None:
                raise A2AInvocationError("A2A facade does not create long-running tasks")

        base_url = a2a_base_url.rstrip("/")
        public_card = AgentCard(
            name="Blue Ice Project",
            description="Text-only delegation through the local Blue Ice security pipeline.",
            version="0.1.0",
            default_input_modes=["text/plain"],
            default_output_modes=["text/plain"],
            capabilities=AgentCapabilities(streaming=False, push_notifications=False),
            supported_interfaces=[
                AgentInterface(
                    protocol_binding="JSONRPC",
                    url=f"{base_url}/a2a",
                    protocol_version="1.0",
                )
            ],
            skills=[
                AgentSkill(
                    id="secure-text-delegation",
                    name="Secure text delegation",
                    description="Delegates a text prompt through the configured Blue Ice model and security checks.",
                    tags=["privacy", "coding-assistant"],
                    examples=["Explain this error message"],
                    input_modes=["text/plain"],
                    output_modes=["text/plain"],
                )
            ],
        )
        request_handler = DefaultRequestHandler(
            agent_executor=BlueIceA2AExecutor(),
            task_store=InMemoryTaskStore(),
            agent_card=public_card,
        )
        app.router.routes.extend(create_agent_card_routes(public_card))
        app.router.routes.extend(create_jsonrpc_routes(request_handler, "/a2a"))

    return app


async def _safe_audit(
    settings: Settings,
    *,
    event: str,
    outcome: str,
    provider: str,
    counts: dict[str, int],
    rules: list[str],
    latency_ms: int,
) -> None:
    try:
        await asyncio.to_thread(
            append_event,
            settings.audit_path,
            event=event,
            outcome=outcome,
            provider=provider,
            counts=counts,
            rules=rules,
            latency_ms=latency_ms,
        )
    except Exception:
        raise AuditUnavailable("Local audit write failed") from None


def _audit_unavailable_response() -> JSONResponse:
    return JSONResponse(
        status_code=503,
        content={
            "error": {
                "message": "Blue Ice Project could not record this event",
                "type": "audit_unavailable",
            }
        },
    )
