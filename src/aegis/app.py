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
from aegis.mcp_server import handle_request as handle_mcp_request
from aegis.protocol_adapters import (
    anthropic_to_chat,
    chat_to_anthropic,
    chat_to_anthropic_sse,
    chat_to_gemini,
    chat_to_gemini_sse,
    gemini_to_chat,
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
            or not (
                scope.get("path")
                in {"/mcp", "/v1/chat/completions", "/v1/responses", "/v1/messages"}
                or str(scope.get("path", "")).startswith("/v1beta/models/")
            )
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


def create_app(
    settings: Settings,
    *,
    http_client: Any | None = None,
    input_scanners: list[Any] | None = None,
    output_scanners: list[Any] | None = None,
) -> FastAPI:
    """Create the app. Inject dependencies in tests; production pools HTTPX."""
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

    async def require_local_auth(request: Request) -> Response | None:
        if not settings.require_local_auth:
            return None
        header = request.headers.get("authorization", "")
        supplied = header[7:].strip() if header.lower().startswith("bearer ") else ""
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

    @app.get("/healthz")
    async def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.post("/mcp")
    async def mcp(request: Request) -> Response:
        """Serve the read-only MCP surface over authenticated Streamable HTTP."""
        denied = await require_local_auth(request)
        if denied:
            return denied
        try:
            payload = await request.json()
        except Exception:
            return JSONResponse(
                status_code=400,
                content={
                    "jsonrpc": "2.0",
                    "id": None,
                    "error": {"code": -32700, "message": "Parse error"},
                },
            )
        if isinstance(payload, list):
            return JSONResponse(
                status_code=400,
                content={
                    "jsonrpc": "2.0",
                    "id": None,
                    "error": {"code": -32600, "message": "Batch requests are not supported"},
                },
            )

        async def list_models_for_mcp() -> list[dict[str, Any]]:
            key = resolve_provider_key(settings)
            fallback = [{"id": settings.model, "object": "model", "owned_by": "blue-ice-project"}]
            if settings.provider != "ollama" and not key:
                return fallback
            try:
                return await forward_models(
                    provider=settings.provider,
                    api_key=key,
                    client=request.app.state.http_client,
                    endpoint_url=dict(settings.custom_provider_urls).get(settings.provider),
                    models_url=dict(settings.custom_models_urls).get(settings.provider),
                    max_response_bytes=settings.max_response_bytes,
                )
            except (ProviderRequestError, TypeError, ValueError):
                return fallback

        result = await handle_mcp_request(settings, payload, model_lister=list_models_for_mcp)
        if result is None:
            return Response(status_code=202)
        return JSONResponse(content=result)

    @app.get("/v1/blue-ice/capabilities")
    async def capabilities(request: Request) -> Response:
        denied = await require_local_auth(request)
        if denied:
            return denied
        responses_url = dict(settings.custom_responses_urls).get(settings.provider)
        responses_supported = settings.provider == "openai" or responses_url is not None
        return JSONResponse(
            content={
                "object": "blue_ice.capabilities",
                "version": "1",
                "provider": settings.provider,
                "model": settings.model,
                "apis": {
                    "models": {"method": "GET", "path": "/v1/models"},
                    "chat_completions": {
                        "method": "POST",
                        "path": "/v1/chat/completions",
                        "streaming": "buffered_replay",
                        "tool_calls": "pass_through_with_egress_inspection",
                    },
                    "responses": {
                        "method": "POST",
                        "path": "/v1/responses",
                        "supported": responses_supported,
                        "streaming": "buffered_replay" if responses_supported else "unsupported",
                    },
                    "anthropic_messages": {
                        "method": "POST",
                        "path": "/v1/messages",
                        "supported": True,
                        "translation": "anthropic_to_chat_completions",
                        "streaming": "buffered_json_only",
                    },
                    "gemini_generate_content": {
                        "method": "POST",
                        "path": "/v1beta/models/{model}:generateContent",
                        "supported": True,
                        "translation": "gemini_to_chat_completions",
                        "streaming": "buffered_json_only",
                    },
                },
                "security": {
                    "local_bearer_auth": settings.require_local_auth,
                    "llm_guard": {
                        "enabled": settings.llm_guard_enabled,
                        "failure_mode": "fail_closed",
                    },
                    "secret_redaction": True,
                    "egress_inspection": True,
                    "metadata_only_audit": True,
                },
            }
        )

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

    async def _adapter_chat(payload: dict[str, Any]) -> dict[str, Any]:
        """Run a translated native-agent request through the chat security path."""
        messages, _stream = _validate_chat_payload(payload)
        findings = inspect_messages(messages, settings.project_root, settings.privacyignore_rules)
        if findings:
            raise PolicyBlocked(
                sorted({str(item.get("code", "path_policy_block")) for item in findings})
            )
        vault = SessionVault(ttl_seconds=180.0)
        redacted_count = 0
        try:

            def redact(value: str) -> str:
                nonlocal redacted_count
                value, count = redact_text(value, vault)
                redacted_count += count
                if settings.llm_guard_enabled:
                    value, changed = scan_input(value, input_scanners or [])
                    redacted_count += changed
                return value

            clean_payload = _transform_strings(copy.deepcopy(payload), redact)
            clean_payload["stream"] = False
            key = resolve_provider_key(settings)
            if settings.provider != "ollama" and not key:
                raise ProviderRequestError(
                    "No API credential is configured for the selected provider"
                )
            response = await forward_chat(
                clean_payload,
                provider=settings.provider,
                api_key=key,
                client=app.state.http_client,
                endpoint_url=dict(settings.custom_provider_urls).get(settings.provider),
                max_response_bytes=settings.max_response_bytes,
            )
            if not isinstance(response, dict):
                raise ProviderRequestError("provider returned a non-object response")
            texts = _assistant_texts(response)
            prompt = "\n".join(_all_strings(clean_payload.get("messages", [])))
            if settings.llm_guard_enabled:
                scanned = [scan_output(text, prompt, output_scanners or [])[0] for text in texts]
                iterator = iter(scanned)
                response = _replace_assistant_strings(response, lambda value: next(iterator, value))
            output = "\n".join(_assistant_texts(response))
            if inspect_output(output, allowed_domains=settings.allowed_domains):
                raise PolicyBlocked(["egress_policy_block"])
            mapping = _collect_vault_mapping(clean_payload, vault)
            response = _replace_assistant_strings(
                response, lambda value: reconstruct(value, vault=mapping)[0]
            )
            await asyncio.to_thread(
                append_event,
                settings.audit_path,
                event="chat_request",
                outcome="allowed",
                provider=settings.provider,
                counts={"secrets_redacted": redacted_count},
                latency_ms=0,
            )
            return response
        finally:
            vault.clear()

    @app.post("/v1/messages")
    async def anthropic_messages(request: Request) -> Response:
        denied = await require_local_auth(request)
        if denied:
            return denied
        try:
            payload = await request.json()
            chat_payload = anthropic_to_chat(payload)
            result = await _adapter_chat(chat_payload)
            if isinstance(payload, dict) and payload.get("stream") is True:
                return Response(
                    content=chat_to_anthropic_sse(result, model=chat_payload["model"]),
                    media_type="text/event-stream",
                    headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
                )
            return JSONResponse(content=chat_to_anthropic(result, model=chat_payload["model"]))
        except PolicyBlocked as exc:
            return JSONResponse(
                status_code=403,
                content={"error": {"type": "aegis_policy_block", "message": str(exc)}},
            )
        except ScannerUnavailable:
            return JSONResponse(
                status_code=503,
                content={
                    "error": {
                        "type": "scanner_unavailable",
                        "message": "Configured scanner is unavailable; request blocked",
                    }
                },
            )
        except (ValueError, ScanRejected) as exc:
            return JSONResponse(
                status_code=400, content={"error": {"type": "invalid_request", "message": str(exc)}}
            )
        except ProviderRequestError as exc:
            return JSONResponse(
                status_code=502, content={"error": {"type": "provider_error", "message": str(exc)}}
            )
        except Exception:
            return JSONResponse(
                status_code=503,
                content={
                    "error": {
                        "type": "aegis_error",
                        "message": "Blue Ice Project could not safely complete this request",
                    }
                },
            )

    @app.post("/v1beta/models/{model}:generateContent")
    async def gemini_generate_content(model: str, request: Request) -> Response:
        denied = await require_local_auth(request)
        if denied:
            return denied
        try:
            payload = await request.json()
            payload["model"] = model
            chat_payload = gemini_to_chat(payload)
            result = await _adapter_chat(chat_payload)
            if isinstance(payload, dict) and payload.get("stream") is True:
                return Response(
                    content=chat_to_gemini_sse(result),
                    media_type="text/event-stream",
                    headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
                )
            return JSONResponse(content=chat_to_gemini(result))
        except PolicyBlocked as exc:
            return JSONResponse(
                status_code=403,
                content={"error": {"type": "aegis_policy_block", "message": str(exc)}},
            )
        except ScannerUnavailable:
            return JSONResponse(
                status_code=503,
                content={
                    "error": {
                        "type": "scanner_unavailable",
                        "message": "Configured scanner is unavailable; request blocked",
                    }
                },
            )
        except (ValueError, ScanRejected) as exc:
            return JSONResponse(
                status_code=400, content={"error": {"type": "invalid_request", "message": str(exc)}}
            )
        except ProviderRequestError as exc:
            return JSONResponse(
                status_code=502, content={"error": {"type": "provider_error", "message": str(exc)}}
            )
        except Exception:
            return JSONResponse(
                status_code=503,
                content={
                    "error": {
                        "type": "aegis_error",
                        "message": "Blue Ice Project could not safely complete this request",
                    }
                },
            )

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
