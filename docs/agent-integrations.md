# Coding-agent integration guide

Blue Ice Project exposes `GET /v1/models`, `POST /v1/chat/completions`, and `POST /v1/responses` at `http://127.0.0.1:8080/v1`. Native Responses forwarding is available for the built-in `openai` provider or a custom provider that has an explicit `responses_url` registered. Other providers return `501`; a Chat Completions URL is never assumed to implement Responses. The local bearer token is a gateway credential, not a cloud-provider key. Keep both it and the upstream provider key outside project files.

A client’s ability to store a custom base URL does not prove that it speaks the same API as this service. Chat Completions streams are buffered and recreated as a simplified SSE response. Native Responses SSE frames are buffered; parsed frame text is inspected before replay, and frames after the terminal completion event are rejected rather than forwarded incrementally. The route passes Responses continuation and tool fields through without translating them, but its buffering behavior and lack of a live Codex test mean this is not a claim of full gateway conformance. See the [protocol research note](codex-gateway-research.md).

## Codex CLI and Codex desktop

OpenAI documents custom providers for Codex through `~/.codex/config.toml` (Windows: `%USERPROFILE%\.codex\config.toml`). The desktop app and CLI share this configuration. A provider can specify `base_url`, an environment-variable name in `env_key`, and `wire_api = "responses"`.[1] [2]

**Conditional and not yet verified end-to-end.** The service has a native `/v1/responses` route for OpenAI and for custom endpoints explicitly registered with `--responses-url`. It forwards request fields, including `previous_response_id` and function-call output, and preserves Responses SSE event types after full-response inspection. It does not translate Chat Completions providers into Responses. Because events are buffered rather than forwarded incrementally, and no installed Codex CLI/desktop session has yet been tested against the local gateway, do not call this certified or fully compatible.[3]

After selecting `openai` in Blue Ice Project and providing its upstream key to the proxy process, a Codex configuration can point at the local endpoint as follows. For another vendor, register a native endpoint explicitly with `blue-ice provider add <name> --url <chat-completions-url> --responses-url <native-responses-url> --model <model-id>` and provide its key as `AEGIS_CUSTOM_<NAME>_API_KEY`. Select a model ID accepted by the configured upstream and visible from `/v1/models`:

```sh
blue-ice init --project-root /absolute/path/to/project --provider openai
blue-ice provider use openai --model "$OPENAI_MODEL"
export AEGIS_OPENAI_API_KEY="<upstream-openai-key>"
export BLUE_ICE_LOCAL_TOKEN="$(cat "$HOME/.aegis/local-token")"
blue-ice start
```

Run Codex in another shell that inherits `BLUE_ICE_LOCAL_TOKEN`. Keep the upstream key only in the proxy process environment or OS keyring. The proxy forwards the Codex request's model; it does not infer a replacement.

```toml
model = "<model-id-supported-by-the-gateway>"
model_provider = "local"

[model_providers.local]
name = "Blue Ice Project"
base_url = "http://127.0.0.1:8080/v1"
wire_api = "responses"
env_key = "BLUE_ICE_LOCAL_TOKEN"
requires_openai_auth = false
```

Keep the actual token in `BLUE_ICE_LOCAL_TOKEN`, provided to the Codex process through its environment. OpenAI discourages the experimental static bearer-token option in favor of environment-backed authentication.[1] [2] OpenAI documents gateway setup for Codex desktop, but the reviewed documentation does not establish that every desktop version accepts a plain-HTTP localhost gateway; do not assume it does.[3]

## Codex Security CLI

Codex Security is not simply the `codex` command with a different name. The standalone Security CLI uses an isolated Codex configuration and has its own auth and provider options. Its reference lists built-in providers and supports native Codex setting overrides with `--codex KEY=VALUE`; it can also select a Security-specific config/profile.[4] [5]

**Not verified; do not treat as supported.** Although Blue Ice Project now has a Responses route for the OpenAI provider, the Security CLI documentation does not establish arbitrary local gateways as a supported provider, and its isolated configuration/authentication path is separate from ordinary Codex CLI. The `--codex KEY=VALUE` override is documented, but this project has not confirmed the required keys or completed a Security scan through the local endpoint. Do not assume that the Codex CLI configuration above is inherited by a Security scan.

## Hermes Agent

Hermes documents a custom endpoint for providers implementing OpenAI Chat Completions at `/v1/chat/completions`. Set `model.provider` to `custom`, use `model.base_url`, select a model served by the endpoint, and use `model.key_env` so the secret stays outside YAML.[6] [7]

For example, place the token in Hermes' documented user secret file `~/.hermes/.env` as `LOCAL_LLM_API_KEY=<local-token>`, then configure `~/.hermes/config.yaml`:

```yaml
model:
  default: <served-model-id>
  provider: custom
  base_url: http://127.0.0.1:8080/v1
  key_env: LOCAL_LLM_API_KEY
```

Hermes also offers a custom-endpoint setup flow. Use the exact model ID from Blue Ice Project's `/v1/models` response. The configuration pathway is documented; this does not prove every model feature or optional tool call works with this proxy.[6] [7]

## OpenCode

OpenCode documents custom OpenAI-compatible providers with a configurable base URL and API key.[8] [9] Add a provider and model entry to `opencode.json` or `opencode.jsonc`, for example:

```json
{
  "$schema": "https://opencode.ai/config.json",
  "model": "local/coder",
  "providers": {
    "local": {
      "name": "Blue Ice Project",
      "package": "@opencode/ai/providers/openai-compatible",
      "settings": {
        "baseURL": "http://127.0.0.1:8080/v1",
        "apiKey": "{env:BLUE_ICE_LOCAL_TOKEN}"
      },
      "models": {
        "coder": {
          "modelID": "<served-model-id>"
        }
      }
    }
  }
}
```

Define `BLUE_ICE_LOCAL_TOKEN` in the environment inherited by OpenCode. OpenCode documents the custom provider fields, but the pages reviewed do not specify the exact outgoing auth header for every adapter, and do not test this proxy. Verify the request reaches the local service without putting the token in a project file.[8] [9]

## OpenClaw

OpenClaw documents custom provider entries and an `openai-completions` adapter for Chat Completions-style endpoints.[10] [11] Merge a provider into the active `~/.openclaw/openclaw.json` configuration (or the path selected by `OPENCLAW_CONFIG_PATH`) and keep the token in the Gateway process environment or the documented state-dir `.env` file:

```json5
{
  models: {
    mode: "merge",
    providers: {
      "blue-ice": {
        baseUrl: "http://127.0.0.1:8080/v1",
        api: "openai-completions",
        apiKey: "${OPENCLAW_LOCAL_API_KEY}",
        models: [{ id: "<served-model-id>", name: "Blue Ice Project model" }]
      }
    }
  },
  agents: {
    defaults: {
      model: { primary: "blue-ice/<served-model-id>" }
    }
  }
}
```

Set `OPENCLAW_LOCAL_API_KEY` to the local gateway token for the Gateway process. Preserve unrelated existing configuration when merging these fields. This is a documented configuration path, not a live test; the selected model and any tool features must be supported by both ends.[10] [11]

## Cline for VS Code / IDE

Cline's VS Code/IDE extension documents an `OpenAI Compatible` provider with fields for Base URL, API Key, and Model.[12] Set the base URL to `http://127.0.0.1:8080/v1` and use a model ID shown by the local `/v1/models` route.

The official page describes an API Key field but does not explicitly specify its wire-level Authorization header for an individual custom provider. Therefore, a local bearer token should be treated as conditional until verified with the installed Cline version. Cline Desktop documents local model options but does not clearly document a generic user-defined OpenAI-compatible endpoint; do not assume the VS Code configuration applies to the desktop app.[13] [14]

## Roo Code

Roo Code documents an `OpenAI Compatible` provider with Base URL, API Key, and Model fields.[15] Use the same local URL and served model ID. Roo Code requires native tool calling; its documentation warns that compatible providers may implement this feature only partially. The UI can accept the endpoint settings, but successful tool calling is conditional on the proxy and selected model behavior.[15]

## Continue

Continue documents OpenAI-compatible self-hosted model configuration using `provider: openai`, `apiBase`, `model`, and a secret reference for `apiKey`.[16] An example `config.yaml` entry is:

```yaml
models:
  - name: Blue Ice Project
    provider: openai
    apiBase: http://127.0.0.1:8080/v1
    model: <served-model-id>
    apiKey: "${{ secrets.BLUE_ICE_LOCAL_TOKEN }}"
```

Keep `BLUE_ICE_LOCAL_TOKEN` in an applicable Continue `.env` secret source, not in the repository. Continue documents the key as an `Authorization: Bearer` credential; the endpoint still must implement the requested API features.[16] [17]

## Cursor

Cursor's public BYOK documentation lists provider-specific keys. Its data-governance documentation mentions an OpenAI-compatible base-URL override for custom models, but the official pages reviewed do not give a precise setting name or a complete local bearer-token setup.[18] [19] Because the exact supported configuration is unclear, this guide does not claim a verified Cursor setup.

## What “compatible” means here

These examples describe client configuration, not certification or successful end-to-end integration testing. For any client, first check which endpoint path and protocol it calls, whether its authentication method matches the local bearer-token check, which streaming events and tool-call formats it expects, and which model ID is served. Chat Completions SSE is recreated after inspection. Native Responses is available for OpenAI and explicitly registered custom Responses endpoints, but its SSE is buffered before replay and has not been verified end-to-end with Codex. Treat the Codex examples as conditional, not certified compatibility.

## References

[1]: https://developers.openai.com/codex/config-file/config-advanced "Codex advanced configuration"
[2]: https://developers.openai.com/codex/config-reference "Codex configuration reference"
[3]: https://developers.openai.com/codex/enterprise/gateway-compatibility "Codex gateway compatibility"
[4]: https://developers.openai.com/codex/security/cli "Codex Security CLI"
[5]: https://developers.openai.com/codex/security/cli/reference "Codex Security CLI reference"
[6]: https://hermes-agent.nousresearch.com/docs/integrations/providers "Hermes providers"
[7]: https://hermes-agent.nousresearch.com/docs/user-guide/configuring-models "Hermes model configuration"
[8]: https://opencode.ai/docs/providers/ "OpenCode providers"
[9]: https://opencode.ai/docs/config/ "OpenCode configuration"
[10]: https://docs.openclaw.ai/concepts/model-providers/custom-providers "OpenClaw custom model providers"
[11]: https://docs.openclaw.ai/gateway/config-tools/provider-examples "OpenClaw provider examples"
[12]: https://docs.cline.bot/provider-config/openai-compatible "Cline OpenAI-compatible provider"
[13]: https://docs.cline.bot/usage/cline-desktop "Cline Desktop"
[14]: https://docs.cline.bot/usage/cline-desktop-local-models "Cline Desktop local models"
[15]: https://docs.roocode.com/providers/openai-compatible "Roo Code OpenAI-compatible provider"
[16]: https://docs.continue.dev/guides/how-to-self-host-a-model "Continue self-hosted models"
[17]: https://docs.continue.dev/guides/configuring-models-rules-tools "Continue model configuration"
[18]: https://cursor.com/docs/settings/api-keys "Cursor API keys"
[19]: https://cursor.com/docs/enterprise/privacy-and-data-governance "Cursor privacy and data governance"
