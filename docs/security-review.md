# Security review notes

This is an implementation review, not a penetration test, formal audit, or guarantee that the code is free of vulnerabilities. The checks recorded here cover source review and automated tests only. Re-run them after any security-relevant change.

## Controls present in this revision

The service binds to loopback by default and requires a private local bearer token unless the operator explicitly disables local authentication. Request bodies have a byte limit. Provider URLs are selected from built-in endpoints or local policy; request payloads cannot choose an outbound URL. The HTTPX production client disables redirects. Custom HTTPS endpoints are checked for public DNS results before use. Provider keys are obtained only from the selected provider-specific environment variable or OS keyring; configuration does not accept API-key fields.

Recognized secrets are replaced before forwarding, with a request-scoped in-memory vault. Provider responses are read in bounded chunks in the production HTTPX path, buffered for inspection, and released only after the checks finish. Audit records are owner-only, metadata-only, limited in file size, and expose only allowlisted fields when read. The terminal interfaces do not print provider keys or prompt bodies.

## Residual risks and constraints

### Custom-provider DNS rebinding and SSRF

DNS answers are checked for public addresses, but those results are not pinned to the HTTP connection. A hostname may resolve differently when HTTPX connects. Use only custom endpoints controlled by a trusted operator; this is not a complete SSRF defense.

### Incomplete detection

Secret patterns, path rules, package checks, prompt-injection checks, and response rules are heuristics. They can miss new or transformed secrets and unsafe content, and may also block benign content. Do not rely on them as the only security boundary.

### Local trust boundary and availability

The service uses plain HTTP on loopback. A process running as the same user, malware in that account, or an attacker who obtains the local token can call the proxy. The token file's owner-only permissions do not defend against a compromised account. Request and response sizes are bounded, and the HTTP client has a connection pool, but the service does not implement per-client quotas or an application-level rate limit. Heavy local concurrent usage can consume CPU, memory, or provider budget.

### Retries and buffered output

A bounded retry targets only the selected Chat Completions provider, but a transport timeout or retryable server response can occur after the provider has processed a request. Retrying may duplicate model work or charges; there is no idempotency-key coordination. The production HTTPX response is read incrementally up to the configured byte ceiling, then held in memory for inspection before being returned. This adds latency and memory use. Chat Completions SSE is recreated from the inspected completion. Responses SSE frame text is checked before replay; a terminal completion is required and any later event is rejected. This remains buffered, is not incremental gateway streaming, and has no live Codex end-to-end test.

### Provider and scanner limitations

Redaction does not remove every sensitive detail. Whatever remains in the request is transmitted to the selected provider. Provider privacy headers are preferences, not evidence of zero retention. ProtectAI LLM Guard is archived upstream and is disabled by default; even when enabled, its scanners are not a comprehensive safety guarantee. Optional registry checks disclose package names to public registries. A missing, new, or unverified package is a risk signal rather than proof of maliciousness. Dedicated secret-scanner binaries were unavailable for this review, so the manual pattern scan covered current workspace files only. No pre-commit or CI secret scan is configured, and this repository has no commit history to inspect.

### Client protocol compatibility

Blue Ice Project implements native `/v1/responses` forwarding for the built-in OpenAI provider and for a custom provider only when its native `responses_url` is explicitly registered and validated. Other configured destinations remain Chat Completions-only and return `501` on `/v1/responses`; no lossy protocol conversion is attempted. Codex custom-provider configuration may target this route, but buffered replay does not satisfy incremental-streaming expectations and no Codex CLI, desktop, or live upstream request has been tested. Codex Security CLI remains unverified because its documentation does not confirm arbitrary local gateways; its auth/configuration is separate. See [the integration guide](agent-integrations.md) and [the protocol research note](codex-gateway-research.md).

If an event cannot be written for a blocked or failed request, the shared audit helper now raises a dedicated error and the API returns `503` rather than silently returning the original result. The event itself still cannot be recorded while storage is unavailable; this is surfaced to the caller, not treated as a completed audit record.

### Provider-side Responses state and retention

The Responses payload is forwarded with its requested fields, including `store` and `previous_response_id`; this gateway does not silently force a retention setting that could alter continuation behavior. OpenAI's create reference documents `store` as defaulting to `true`. Local metadata-only audit therefore does not imply that upstream request or response state is not retained. Review the selected provider's current data controls and account terms before sending sensitive content.

## Review checks performed

The revision was checked with pytest, Ruff lint and format checks, Python bytecode compilation, a package wheel build, TypeScript compilation, CLI smoke tests, sample YAML parsing, local Markdown link checks, bundled skill validation/copy comparison, and a local high-confidence secret-pattern scan. The tests are synthetic; no provider, Codex CLI, or Codex Security CLI end-to-end run was performed. These checks can detect regressions but cannot prove safety or the absence of other defects.
