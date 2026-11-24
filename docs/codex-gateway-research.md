# Codex Gateway Compatibility Research

Research snapshot: 2026-11-24. OpenAI documentation can change; verify against the client and model versions being deployed.

## Codex CLI and desktop

OpenAI's gateway guidance requires a custom Codex gateway to accept `POST /v1/responses` and preserve the request and response fields used by the client. A Chat Completions endpoint alone does not establish compatibility. The gateway must preserve Responses streaming incrementally, including event types and payloads, completion and failure events; replayed conversation input, tool calls, matching tool outputs and identifiers; authentication; model routing; and useful errors. `previous_response_id` is needed only when the selected transport relies on it; a stateless HTTP request can carry replayed input. A custom provider uses `wire_api = "responses"`, a `base_url`, and environment-backed credentials such as `env_key`.

OpenAI documents semantic Responses SSE events, including `response.created`, `response.output_text.delta`, `response.completed`, and `error`, with additional events for output items and tool calls. Tool-capable integrations need to preserve the full function-call/function-output cycle, not only text. The exact model name and advertised capabilities must match the upstream provider.

## Codex Security CLI

The standalone Codex Security CLI has its own authentication and provider options. Its reference currently lists `openai`, `openrouter`, `fireworks`, and `amazon-bedrock`; it also exposes repeated `--codex KEY=VALUE` overrides for native Codex configuration values. The documentation does not confirm arbitrary local gateways as a supported `--provider` choice. Native Codex overrides may provide an experimental path to a custom provider, but this requires end-to-end verification with the specific Security CLI release and must not be represented as supported in advance.

## Privacy and implementation implications

A gateway that buffers a complete Responses stream for inspection does not satisfy the documented requirement to forward SSE incrementally. Blue Ice Project buffers, inspects parsed text from every replayed frame, requires a terminal completion event, rejects events after completion, and replays the captured frames with event names preserved. This reduces the risk of exposing an unchecked delta before configured checks, but delays delivery and is not full gateway conformance. The Responses create reference documents `store` as defaulting to `true`; this implementation forwards `store` and `previous_response_id` without silently forcing a value that could break continuation, so it must not claim zero retention. Provider-side retention remains governed by the selected provider and account.

The baseline version inspected for this research implemented only `/v1/chat/completions`. The current revision adds `/v1/responses` for the built-in OpenAI provider and custom providers only when a native `responses_url` is explicitly registered. Forwarding is bounded and synthetic tests cover authentication, input redaction, continuation fields, tool output, response limits, custom endpoint selection, mismatched SSE delta/completion content, and rejection of post-completion events. Other configured providers return `501` rather than being translated. No Codex CLI, desktop app, upstream provider account, or Codex Security CLI end-to-end test has been performed; protocol tests do not prove product compatibility.

## References

[1]: https://developers.openai.com/codex/enterprise/gateway-compatibility "Codex gateway compatibility requirements"
[2]: https://developers.openai.com/codex/config-file/config-advanced "Codex advanced configuration"
[3]: https://developers.openai.com/codex/security/cli "Codex Security CLI quickstart"
[4]: https://developers.openai.com/codex/security/cli/reference "Codex Security CLI reference"
[5]: https://developers.openai.com/api/reference/resources/responses/methods/create "Responses API create reference"
[6]: https://developers.openai.com/api/docs/guides/streaming-responses "Responses API streaming guide"
