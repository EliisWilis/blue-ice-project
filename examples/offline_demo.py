"""Run Blue Ice Project's request path without contacting an AI provider or the internet.

The injected provider client returns synthetic model and chat responses. All HTTP
requests from the demo client are routed through an in-process ASGI transport.
"""

from __future__ import annotations

import asyncio
import json
import os
import secrets
import tempfile
from pathlib import Path
from typing import Any

import httpx

from aegis.app import create_app
from aegis.config import Settings


class SyntheticResponse:
    """Minimal HTTP response shape consumed by the gateway's injected client path."""

    status_code = 200

    def __init__(self, body: dict[str, Any]) -> None:
        self.body = body
        self.content = json.dumps(body).encode("utf-8")
        self.headers = {"content-length": str(len(self.content))}

    def json(self) -> dict[str, Any]:
        return self.body


class SyntheticProvider:
    """Return canned provider responses; no socket or real provider is used."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, str, dict[str, Any]]] = []

    async def get(self, url: str, **kwargs: Any) -> SyntheticResponse:
        self.calls.append(("GET", url, kwargs))
        return SyntheticResponse(
            {
                "object": "list",
                "data": [
                    {"id": "demo-chat", "object": "model", "owned_by": "synthetic"},
                    {"id": "demo-code", "object": "model", "owned_by": "synthetic"},
                ],
            }
        )

    async def post(self, url: str, **kwargs: Any) -> SyntheticResponse:
        self.calls.append(("POST", url, kwargs))
        return SyntheticResponse(
            {
                "id": "chatcmpl-blue-ice-demo",
                "object": "chat.completion",
                "created": 1,
                "model": "demo-chat",
                "choices": [
                    {
                        "index": 0,
                        "message": {
                            "role": "assistant",
                            "content": (
                                "This reply is synthetic. The request passed through "
                                "Blue Ice Project's local chat-completions route."
                            ),
                        },
                        "finish_reason": "stop",
                    }
                ],
            }
        )


async def run_demo() -> list[str]:
    """Exercise auth, model listing, and chat with only temporary demo files."""
    output: list[str] = []
    key_name = "AEGIS_GROQ_API_KEY"
    previous_key = os.environ.get(key_name)

    with tempfile.TemporaryDirectory(prefix="blue-ice-offline-demo-") as temporary:
        root = Path(temporary)
        token = secrets.token_urlsafe(40)
        token_path = root / "local-token"
        token_path.write_text(token, encoding="ascii")
        token_path.chmod(0o600)

        settings = Settings(
            config_path=root / "config.yaml",
            project_root=root,
            provider="groq",
            model="demo-chat",
            allowed_domains=(),
            privacyignore_rules=(),
            max_request_bytes=16_384,
            max_response_bytes=1_000_000,
            audit_path=root / "audit.jsonl",
            token_path=token_path,
            require_local_auth=True,
            key_source="env",
            registry_checks=False,
            llm_guard_enabled=False,
            custom_provider_urls=(),
            custom_models_urls=(),
            custom_responses_urls=(),
        )
        provider = SyntheticProvider()
        app = create_app(settings, http_client=provider)
        app.state.http_client = provider
        os.environ[key_name] = "synthetic-demo-credential-not-a-real-key"

        try:
            transport = httpx.ASGITransport(app=app)
            async with httpx.AsyncClient(
                transport=transport,
                base_url="http://blue-ice-demo",
                timeout=5.0,
            ) as client:
                unauthenticated = await client.get("/v1/models")
                assert unauthenticated.status_code == 401
                assert not provider.calls
                output.append("PASS  local authentication rejects missing credentials (HTTP 401)")

                headers = {"Authorization": f"Bearer {token}"}
                models = await client.get("/v1/models", headers=headers)
                assert models.status_code == 200, models.text
                model_ids = [item["id"] for item in models.json()["data"]]
                assert model_ids == ["demo-chat", "demo-code"]
                assert len(provider.calls) == 1
                output.append("PASS  authenticated GET /v1/models returns two synthetic model IDs")

                completion = await client.post(
                    "/v1/chat/completions",
                    headers=headers,
                    json={
                        "model": "demo-chat",
                        "messages": [{"role": "user", "content": "Show me the offline demo path."}],
                    },
                )
                assert completion.status_code == 200, completion.text
                reply = completion.json()["choices"][0]["message"]["content"]
                assert "synthetic" in reply
                assert len(provider.calls) == 2
                output.append("PASS  POST /v1/chat/completions returns a synthetic chat response")
        finally:
            if previous_key is None:
                os.environ.pop(key_name, None)
            else:
                os.environ[key_name] = previous_key

    output.append("PASS  no external network connection was opened")
    return output


def main() -> None:
    print("Blue Ice Project offline demonstration")
    print("Synthetic provider responses; no real API key or internet required.\n")
    for line in asyncio.run(run_demo()):
        print(line)
    print("\nDemo complete. Temporary token, config, and audit files were removed.")


if __name__ == "__main__":
    main()
