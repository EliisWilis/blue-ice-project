# TODO

## Capability discovery for all coding agents
- [x] Authenticated `GET /v1/blue-ice/capabilities` endpoint is available.
- [x] The response documents `GET /v1/models`, Chat Completions, and Responses without exposing API keys, prompts, outputs, audit records, or filesystem paths.
- [x] The response states that streaming is buffered before inspection, tool calls are passed through while outputs still undergo egress checks, and LLM Guard fails closed when enabled.

## Debugging and validation
- [x] All existing tests still pass: 50 passed.
- [x] Ruff check, Ruff format check, compileall, and git diff --check pass.
- [x] Real typing errors in the egress firewall and custom routing were fixed without changing runtime behavior; mypy passes for the source.
- [x] New tests cover authentication and the capability-response shape.

## Skill repository
- [x] 71 agency skills from `WebWakaHub/manus-agency-skills` are available under `skills/agency-*` without `.git` data or credentials.
- [x] The REA skill is available under `skills/reverse-engineer-anything` and is used only for shipped-artifact/runtime evidence, not source-repository analysis.

## Native agent protocol adapters
- [x] An Anthropic Messages adapter is available at `POST /v1/messages` for text, system, tool-use, tool-result, redaction, egress inspection, audit, and buffered SSE replay.
- [x] A Gemini GenerateContent adapter is available at `POST /v1beta/models/{model}:generateContent` for mapped content/system/generation fields, redaction, egress inspection, audit, and buffered SSE replay.
- [x] Contract tests for converters and native endpoints pass; live binary-agent tests remain open and are not claimed as certification.

## MCP integration for Codex
- [x] A read-only MCP JSON-RPC server is available through the `blue-ice mcp` command over STDIO and the authenticated `POST /mcp` endpoint on the loopback listener.
- [x] Initial MCP tools cover capabilities, model discovery, metadata-only audit, installed-skill listing/reading, project-path policy checks, and deterministic security checks without arbitrary shell execution.
- [x] MCP request-size limits, local bearer authentication, project-root boundaries, privacyignore checks, bounded skill/audit reads, and sanitized errors are tested.
- [x] The README and agent compatibility guide document the separation between MCP tools and Codex model traffic through `/v1/responses`.
- [x] MCP contract tests pass; end-to-end verification with a specific Codex binary/version remains open and is not claimed as certified compatibility.
- [ ] An A2A facade for agent-to-agent delegation is not enabled; A2A remains an extension point/reference and is not a required runtime dependency.
