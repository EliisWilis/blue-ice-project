# Coding-agent installation and integration guide

This guide covers 15 commonly requested coding-agent clients. It explains how to install or open each client, how to point a compatible client at Blue Ice Project, where each credential belongs, and which integrations remain conditional or unsupported. The official client documentation was reviewed for configuration paths, but **Blue Ice Project has not been end-to-end tested with these clients**. A documented custom endpoint is not a compatibility certification.

Blue Ice Project is a local gateway at `http://127.0.0.1:8080/v1`. It accepts OpenAI Chat Completions for its supported providers. It has a native `/v1/responses` route only for the built-in OpenAI provider and for a custom provider with an explicitly registered native `responses_url`. It does not translate one protocol into the other. The service binds to loopback only, and Chat/Responses event streams are buffered before replay.

Blue Ice also exposes the selected upstream's model catalog through its authenticated OpenAI-compatible `GET /v1/models` route. The upstream key stays in the Blue Ice process; agents use only the local Blue Ice token. Any agent that actually queries this route can use the returned model IDs, but client behavior varies: some agents query it, while others require model IDs to be added manually in their own configuration. A model appearing in the list does not prove support for tools, streaming, or another native protocol. `blue-ice-node models` is a local way to inspect the same catalog.

## Keep the two API credentials separate

There are two different credentials:

1. **Upstream provider API key:** belongs to the Blue Ice service process. Set it in the provider-specific environment variable or use the OS keyring. Do not put it in agent settings, project files, YAML, or command-line arguments.
2. **Local Blue Ice token:** belongs to the agent client. It authenticates requests from the local agent to Blue Ice. If an agent asks for an API key while configured with the local URL, enter the local token, not the upstream provider key. Store it in the agent's user-level secret store or environment variable, never in a committed project file.

The local token is created at `~/.aegis/local-token` by `blue-ice init`. For local shells, load it without writing the value into shell history:

```sh
export BLUE_ICE_TOKEN="$(cat "$HOME/.aegis/local-token")"
```

Agent-specific environment variable names differ. For example, Codex can reference `BLUE_ICE_TOKEN` through `env_key`; Aider commonly uses `OPENAI_API_KEY` for the local token; Continue uses a secret reference; and Qwen Code can use `BLUE_ICE_API_KEY`. In every case, the variable's value is the local Blue Ice token, not an upstream key.

## Select the upstream provider and configure the router

Blue Ice selects one upstream destination for the local service. All local agents using that service are routed through the same selected provider; the current router does not provide per-agent upstream selection, key rotation, cross-provider fallback, or automatic failover.

Initialize the project once, then choose a provider and model. This example uses OpenRouter:

```sh
blue-ice init --project-root /absolute/path/to/project --provider openrouter
blue-ice provider use openrouter --model openrouter/auto
read -r -s -p "OpenRouter API key: " AEGIS_OPENROUTER_API_KEY
printf '\n'
export AEGIS_OPENROUTER_API_KEY
blue-ice start
```

Run the key-entry commands in the same shell that will start the service. Substitute the matching variable for OpenAI, Groq, Google, Cerebras, or a custom provider. Ollama uses a loopback endpoint and does not need a cloud API key. The key is never passed as a CLI argument or saved in policy YAML. The `init` command can offer to store a key in the OS keyring if a secure backend is available.

For any custom HTTPS provider or gateway that implements OpenAI Chat Completions and Bearer authentication, register its endpoint in local policy and configure the provider-specific key separately. Blue Ice derives the standard `/models` route from the chat endpoint; pass `--models-url` only when the provider uses a different compatible model-list URL:

```sh
blue-ice provider add vendorx \
  --url https://api.vendor.example/v1/chat/completions \
  --models-url https://api.vendor.example/v1/models \
  --model vendor-model
read -r -s -p "Vendor API key: " AEGIS_CUSTOM_VENDORX_API_KEY
printf '\n'
export AEGIS_CUSTOM_VENDORX_API_KEY
blue-ice start
```

Add `--responses-url https://api.vendor.example/v1/responses` only if that upstream implements the native Responses API. Blue Ice validates custom-host DNS before use but does not pin the resolved address to the HTTP connection; use only trusted endpoints.

To change the active upstream later, use `blue-ice provider use NAME --model MODEL`, set that provider's key in the service environment (unless it is stored in the OS keyring), and restart the service. `blue-ice provider list` shows configured providers. When available, upstream model IDs appear through `/v1/models`; if an agent does not query that route, enter a listed ID in its model setting. If the upstream does not implement a model-list route, Blue Ice returns only the configured model. The model name entered in an agent must be accepted by the active upstream; the agent's model name does not create a new Blue Ice route.

## Standard client connection

Install each client using its official installation page below. Run the agent on the same computer/network namespace as Blue Ice so `127.0.0.1` points to the proxy. A remote agent or container may not share the host's loopback interface; this project intentionally refuses non-loopback binds.

For an OpenAI-compatible client that accepts these variables, set the local URL and local token in that agent's shell:

```sh
export OPENAI_BASE_URL='http://127.0.0.1:8080/v1'
export OPENAI_API_KEY="$(cat "$HOME/.aegis/local-token")"
```

Before relying on tool calls or streaming, check that the client sends the expected endpoint path and Bearer token, uses a model accepted by the chosen upstream, and expects the same Chat Completions or Responses protocol that Blue Ice provides. A successful text-only response does not verify those other features.

## Client setup instructions

### Codex CLI and Codex in the ChatGPT desktop app

Install Codex CLI using the [official Codex CLI instructions][1]. Codex in the ChatGPT desktop app is configured through the shared Codex user configuration; follow the official [gateway setup guide][2]. Codex custom providers require the native Responses API. Chat Completions-only providers are not sufficient.[3] [4]

A Codex CLI configuration can point to Blue Ice like this:

```toml
model = "<model-id-known-to-codex-and-the-selected-upstream>"
model_provider = "blue-ice"

[model_providers.blue-ice]
name = "Blue Ice Project"
base_url = "http://127.0.0.1:8080/v1"
wire_api = "responses"
env_key = "BLUE_ICE_TOKEN"
requires_openai_auth = false
```

Set `BLUE_ICE_TOKEN` in the environment inherited by Codex. Do not put its value in `config.toml`. Before using this setup, configure Blue Ice with the built-in `openai` provider or a custom provider that has an explicitly registered native `responses_url`. Codex also requires a model ID it recognizes; a model name visible from `/v1/models` alone might not supply the model metadata Codex needs.[3] [4]

This setup is **conditional and unverified with Blue Ice**. The gateway buffers Responses SSE before replay, while Codex gateway guidance expects compatible streaming, continuation, and tool-call behavior. No live Codex CLI, desktop, or upstream-account test was performed. The CLI's custom-provider screen and the desktop's exact custom-provider UI can vary by version; use the official gateway guide rather than assuming a specific screen path.[2] [3]

Codex can also connect to Blue Ice as an MCP server for tools, independently of its model provider configuration. For local STDIO MCP, add this to the shared Codex configuration:

```toml
[mcp_servers.blue_ice]
command = "blue-ice"
args = ["mcp"]
enabled = true
```

If the Blue Ice service is running, use its authenticated Streamable HTTP MCP endpoint instead:

```toml
[mcp_servers.blue_ice]
url = "http://127.0.0.1:8080/mcp"
bearer_token_env_var = "BLUE_ICE_TOKEN"
enabled = true
```

Set `BLUE_ICE_TOKEN` to the local Blue Ice token, never to an upstream provider key. The initial tools are read-only capability/model discovery, metadata-only audit reading, skill metadata/content reading, project-path policy checks, and deterministic security checks. MCP does not replace `/v1/responses`, and Blue Ice does not expose arbitrary shell execution through MCP. The MCP server has local contract tests; no specific Codex binary/version is end-to-end verified yet.

### Codex Security CLI

Install only from the [official Codex Security CLI guide][5]; that guide lists the supported Node.js/Python versions and install methods. Codex Security is a separate application with its own scanner authentication and configuration. It does not automatically inherit the ordinary Codex CLI settings.[6] [7]

Its native Codex override can be configured to target a custom provider, but the route would still need Blue Ice's native Responses endpoint. The official Security CLI documentation does **not** establish that a Blue Ice local token alone satisfies the scanner's separate authentication requirements. No end-to-end scan through Blue Ice was run. Therefore, Codex Security CLI is **not verified or claimed as supported**; do not treat a successful regular Codex setup as proof that a Security scan works.[5] [6] [7]

### Hermes Agent

Install using the [official Hermes quickstart][11]. Run `hermes model` and choose its custom endpoint flow. Hermes documents OpenAI Chat Completions-compatible endpoints.[9]

A user configuration can use the documented custom endpoint fields:

```yaml
model:
  default: <model-id-accepted-by-blue-ice>
  provider: custom
  base_url: http://127.0.0.1:8080/v1
  key_env: BLUE_ICE_TOKEN
```

Set the custom endpoint's Base URL to `http://127.0.0.1:8080/v1` and keep `BLUE_ICE_TOKEN` in the local Hermes environment source (`~/.hermes/.env`) or the process environment, not in a repository. The selected provider's model list is available at the same base URL's `/models` route. If your installed Hermes version queries that route, it can use the returned IDs; if its model flow asks you to define models explicitly, copy an ID from `blue-ice-node models` into the Hermes model configuration. Hermes documents the custom API-key field but does not explicitly establish its exact wire-level Authorization header in every configuration path. Treat Bearer authentication, model discovery, tool calls, and streaming as **conditional until tested** with your installed Hermes version.[10]

### OpenCode

Install using the [official OpenCode installation guide][12]. The provider documentation describes a custom OpenAI-compatible provider with a base URL, model entry, and environment-backed credential.[13] Use the official current config schema; for this gateway set the base URL to `http://127.0.0.1:8080/v1`, provide the local token through the OpenCode process environment, and select a model ID that Blue Ice's upstream accepts.

OpenCode's documentation does not settle whether every provider adapter can reach an HTTP loopback URL, which path the selected adapter calls in all cases, or whether its credential field always becomes the exact `Authorization: Bearer` header Blue Ice expects. Use the ordinary Chat Completions-compatible provider, not the separate Responses adapter, unless you verify the exact protocol. This is **conditional**, and Blue Ice was not tested with OpenCode.[13] [14] [15]

### OpenClaw

Install using the [official OpenClaw install guide][16]. Its custom-provider docs describe the `openai-completions` adapter and configuration file at `~/.openclaw/openclaw.json`.[17] [19] Merge a provider into the existing config; do not replace unrelated settings:

```json5
{
  models: {
    mode: "merge",
    providers: {
      "blue-ice": {
        baseUrl: "http://127.0.0.1:8080/v1",
        api: "openai-completions",
        apiKey: "${BLUE_ICE_TOKEN}",
        models: [{ id: "<model-id>", name: "Blue Ice model" }]
      }
    }
  },
  agents: {
    defaults: {
      model: { primary: "blue-ice/<model-id>" }
    }
  }
}
```

Set `BLUE_ICE_TOKEN` in OpenClaw's state-directory `.env` or the Gateway process environment; OpenClaw documents `${VAR}` substitution.[18] This is a documented Chat Completions setup pattern, not a live Blue Ice test. Tool calls, streaming, model features, and authentication should be checked with the actual OpenClaw version.

### Claude Code

Install Claude Code using Anthropic's [official setup guide][20]. Blue Ice now exposes a native-shaped `/v1/messages` adapter. It translates the supported Anthropic text, system, tool-use, and tool-result fields into the selected provider's Chat Completions route, then applies the normal redaction, optional LLM Guard, egress inspection, audit, and buffered SSE replay before returning an Anthropic-shaped response.[21] [22]

Set Claude Code's gateway base URL to the Blue Ice origin and use the local Blue Ice token according to Claude Code's gateway configuration. The adapter is implemented and contract-tested, but no live Claude Code binary or upstream-account test has been run. Advanced Anthropic features outside the mapped subset remain unverified. `ANTHROPIC_AUTH_TOKEN` must contain the local Blue Ice token when Claude Code sends it to the local gateway; never put the upstream provider key in Claude Code.[21] [22]

### Gemini CLI

Install Gemini CLI using Google's [official install instructions][23]. Blue Ice now exposes a native-shaped `POST /v1beta/models/{model}:generateContent` adapter, including buffered SSE replay for stream requests. It translates the mapped Gemini content, system instruction, and generation configuration fields into the selected provider's Chat Completions route and keeps the standard security pipeline.[24] [25] [26]

Configure Gemini CLI's base URL and use the Blue Ice local token only if the installed CLI's authentication mode sends that token as a bearer credential to the configured base URL. The adapter is contract-tested, but no live Gemini CLI binary or upstream-account test has been run. Do not substitute the Blue Ice local token for a provider key when Gemini CLI is configured to call Google's own service rather than the local gateway.[24] [25] [26]

### Kilo Code

Install the Kilo Code extension from the [official installation instructions][27]. In Kilo settings, open Providers, add a custom provider, choose **OpenAI Compatible**, set the base URL to `http://127.0.0.1:8080/v1`, and enter a model ID accepted by Blue Ice.[28]

Kilo documents environment references in its trusted global config. Keep the literal local token outside the repository and reference an environment variable such as `BLUE_ICE_TOKEN` instead.[29] Kilo's documentation does not conclusively establish the generic custom provider's Bearer-header behavior, streaming support, or loopback reachability. Enable tool-call capability only when the selected upstream model supports it. This connection is **conditional and untested** with Blue Ice.[28] [29] [30]

### Cline for VS Code/IDE

Install Cline from the [official extension instructions][32]. In the Cline panel, open Settings, select **OpenAI Compatible**, set Base URL to `http://127.0.0.1:8080/v1`, enter the local token in its API Key field, and select a model ID accepted by the active Blue Ice provider.[31] [34]

Cline documents this custom endpoint configuration, but its guide does not specify the exact outbound request route or Bearer-header behavior for every adapter. Treat the configuration as **documented but not tested with Blue Ice**. Keep the token in user-level Cline settings or secret storage, not a shared project file.[33] [34]

### Roo Code

Install Roo Code from the [official VS Code installation instructions][36]. In Roo settings, choose **OpenAI Compatible**, set the Base URL to `http://127.0.0.1:8080/v1`, select the Blue Ice model ID, and enter the local token in the API Key field.[35]

Roo requires native tool calling for its OpenAI-compatible provider. Its docs do not establish that the gateway token field emits exactly the Bearer header Blue Ice requires, nor do they prove tool-call/stream compatibility with this service. Avoid model IDs that make Roo select its special Responses path unless the corresponding Blue Ice Responses provider is configured. This is **conditional and untested**.[35] [37]

### Continue

Install the Continue extension from its [official setup guide][39]. Configure its global `~/.continue/config.yaml` (Windows: `%USERPROFILE%\.continue\config.yaml`) with an OpenAI provider. Continue uses Responses by default for some model families, so set `useResponsesApi: false` to use Blue Ice Chat Completions.[38] [39]

```yaml
models:
  - name: Blue Ice Project
    provider: openai
    apiBase: http://127.0.0.1:8080/v1
    model: <model-id-accepted-by-blue-ice>
    apiKey: "${{ secrets.BLUE_ICE_TOKEN }}"
    useResponsesApi: false
```

Put `BLUE_ICE_TOKEN=<local-token>` in Continue's user-level `~/.continue/.env`, not the project repository. Continue documents that `apiKey` is sent as an Authorization Bearer credential and supports secret interpolation.[40] [41] This is the clearest documented local-token path, but Blue Ice-specific tool/stream compatibility still has not been tested.

### Cursor

Install Cursor from the [official downloads page][42]. Cursor documents an OpenAI-compatible base-URL override for some custom models, but the public docs do not establish reliable loopback reachability or a separate local-gateway Bearer-token setting.[43] [44]

Cursor's BYOK flow sends its own provider key to Cursor's backend; do not paste the Blue Ice local token into a BYOK field unless Cursor explicitly documents that it will send it to the local override. Cursor has also documented model-dependent Responses-versus-Chat-Completions behavior that can mismatch a custom endpoint.[45] The Blue Ice integration status is **unclear**; do not present Cursor as a verified direct local connection.

### Aider

Install Aider using its [official installation guide][47]. Its OpenAI-compatible instructions document `OPENAI_API_BASE`, `OPENAI_API_KEY`, and the `openai/<model-name>` prefix.[46] Set the variables in the Aider process environment, using the Blue Ice local token for `OPENAI_API_KEY`:

```sh
export OPENAI_API_BASE='http://127.0.0.1:8080/v1'
export OPENAI_API_KEY="$(cat "$HOME/.aegis/local-token")"
aider --model openai/REPLACE_WITH_MODEL_ID
```

Aider also supports `.env` files. Prefer a private home-level file or another ignored location rather than the repository root.[48] The docs do not settle the exact route or Bearer-header behavior for every model/provider adapter, so Chat Completions, streaming, and tool calls remain **conditional until verified**. Model metadata may need explicit configuration.[49]

### Goose

Install Goose using the [official platform installation guide][50]. In Goose Desktop, open Settings → Models → Configure providers → Add Custom Provider, choose **OpenAI Compatible**, set the API URL to `http://127.0.0.1:8080/v1/chat/completions`, and configure a model accepted by Blue Ice.[51]

Use Goose's local credential storage for the Blue Ice token; its docs say custom-provider credentials are stored in the system keychain or in `secrets.yaml` if keyring storage is unavailable.[52] The desktop documentation does not establish the exact Authorization header used by the API Key field, and Goose's streamed tool behavior is model-dependent. This setup is **conditional and untested** with Blue Ice.

### Qwen Code

Install Qwen Code using the [official repository instructions][53]. Its OpenAI-compatible provider supports a local base URL and defaults to Chat Completions.[55]

In the user-level `~/.qwen/settings.json`, configure a provider and model. Keep the token in `~/.qwen/.env` or the shell environment; do not put the literal token in `settings.json` or a repository file.[54] [56]

```json
{
  "security": { "auth": { "selectedType": "openai" } },
  "model": { "name": "blue-ice-model", "provider": "openai" },
  "modelProviders": {
    "openai": {
      "name": "Blue Ice Project",
      "baseUrl": "http://127.0.0.1:8080/v1",
      "envKey": "BLUE_ICE_API_KEY",
      "models": [
        { "id": "<model-id-accepted-by-blue-ice>", "name": "Blue Ice model" }
      ]
    }
  }
}
```

Set `BLUE_ICE_API_KEY` to the local token. Leave `wireApi` unset for Chat Completions. Set `wireApi: "responses"` only if the selected Blue Ice provider actually has native Responses configured. Qwen Code does not automatically detect protocol support or fall back between protocols.[55]

## What these statuses mean

“Directly documented” means the agent's official documentation describes a compatible endpoint configuration pattern. It does **not** mean the Blue Ice integration was tested. “Conditional” means material details such as local Bearer-token formatting, request path, streaming, or tool use remain to be verified. “Not directly supported” means the documented client protocol does not match the API currently exposed by Blue Ice. “Unclear” means the official docs do not establish a safe direct configuration.

For all clients, validate the actual API path, `Authorization: Bearer` header, model identifier, stream format, and tool-call loop before sending sensitive code. Blue Ice binds only to loopback, buffers responses for inspection, and does not automatically fail over among providers. It is not a sandbox and does not guarantee zero upstream retention.

## References

[1]: https://developers.openai.com/codex/cli "Codex CLI installation"
[2]: https://developers.openai.com/codex/enterprise/connect-to-a-gateway "Connect Codex to a gateway"
[3]: https://developers.openai.com/codex/enterprise/gateway-compatibility "Codex gateway compatibility"
[4]: https://developers.openai.com/codex/models "Codex models"
[5]: https://learn.chatgpt.com/docs/security/cli "Codex Security CLI quickstart"
[6]: https://learn.chatgpt.com/docs/security/cli/reference "Codex Security CLI reference"
[7]: https://github.com/openai/codex-security/blob/main/docs/project-configuration.md "Codex Security project configuration"
[8]: https://learn.chatgpt.com/codex/config-file/config-reference "Codex configuration reference"
[9]: https://hermes-agent.nousresearch.com/docs/integrations/providers "Hermes Agent providers"
[10]: https://hermes-agent.nousresearch.com/docs/user-guide/configuration "Hermes Agent configuration and secrets"
[11]: https://hermes-agent.nousresearch.com/docs/getting-started/quickstart "Hermes Agent quickstart"
[12]: https://opencode.ai/docs/ "OpenCode installation"
[13]: https://opencode.ai/docs/providers/ "OpenCode providers"
[14]: https://opencode.ai/docs/cli/providers/ "OpenCode CLI providers"
[15]: https://opencode.ai/docs/config/ "OpenCode configuration"
[16]: https://docs.openclaw.ai/install "OpenClaw installation"
[17]: https://docs.openclaw.ai/concepts/model-providers/custom-providers "OpenClaw custom providers"
[18]: https://docs.openclaw.ai/gateway/configuration/environment-variables "OpenClaw environment variables"
[19]: https://docs.openclaw.ai/gateway/configuration "OpenClaw gateway configuration"
[20]: https://code.claude.com/docs/en/setup.md "Claude Code setup"
[21]: https://code.claude.com/docs/en/llm-gateway-connect.md "Connect Claude Code to an LLM gateway"
[22]: https://code.claude.com/docs/en/llm-gateway-protocol.md "Claude Code gateway protocol"
[23]: https://geminicli.com/docs/get-started/installation/ "Gemini CLI installation"
[24]: https://geminicli.com/docs/get-started/authentication/ "Gemini CLI authentication"
[25]: https://geminicli.com/docs/reference/configuration/ "Gemini CLI configuration"
[26]: https://ai.google.dev/gemini-api/docs/openai "Gemini API OpenAI compatibility"
[27]: https://kilo.ai/docs/getting-started/installing "Kilo Code installation"
[28]: https://kilo.ai/docs/ai-providers/openai-compatible "Kilo Code OpenAI-compatible provider"
[29]: https://kilo.ai/docs/code-with-ai/agents/custom-models "Kilo Code custom models"
[30]: https://kilo.ai/docs/getting-started/settings "Kilo Code settings"
[31]: https://docs.cline.bot/provider-config/openai-compatible "Cline OpenAI-compatible provider"
[32]: https://docs.cline.bot/getting-started/installing-cline "Cline installation"
[33]: https://docs.cline.bot/getting-started/config "Cline configuration"
[34]: https://docs.cline.bot/getting-started/authorizing-with-cline "Cline authorization"
[35]: https://docs.roocode.com/providers/openai-compatible "Roo Code OpenAI-compatible provider"
[36]: https://docs.roocode.com/getting-started/installing "Roo Code installation"
[37]: https://docs.roocode.com/features/api-configuration-profiles "Roo Code API configuration profiles"
[38]: https://docs.continue.dev/customize/model-providers/top-level/openai "Continue OpenAI provider"
[39]: https://docs.continue.dev/customize/deep-dives/configuration "Continue configuration"
[40]: https://docs.continue.dev/guides/how-to-self-host-a-model "Continue self-hosted model and Bearer auth"
[41]: https://docs.continue.dev/guides/configuring-models-rules-tools "Continue secrets and configuration"
[42]: https://cursor.com/downloads "Cursor downloads"
[43]: https://cursor.com/docs/settings/api-keys "Cursor API keys"
[44]: https://cursor.com/docs/enterprise/privacy-and-data-governance "Cursor privacy and data governance"
[45]: https://forum.cursor.com/t/cursor-agent-sends-responses-api-format-to-chat-completions-endpoint/153019 "Cursor custom endpoint protocol behavior discussion"
[46]: https://aider.chat/docs/llms/openai-compat.html "Aider OpenAI-compatible APIs"
[47]: https://aider.chat/docs/install.html "Aider installation"
[48]: https://aider.chat/docs/config/dotenv.html "Aider environment and dotenv configuration"
[49]: https://aider.chat/docs/llms/warnings.html "Aider model metadata warnings"
[50]: https://goose-docs.ai/docs/getting-started/installation/ "Goose installation"
[51]: https://goose-docs.ai/docs/getting-started/providers/ "Goose custom providers"
[52]: https://goose-docs.ai/docs/guides/config-files/ "Goose configuration and credentials"
[53]: https://github.com/QwenLM/qwen-code "Qwen Code installation and repository"
[54]: https://qwenlm.github.io/qwen-code-docs/en/users/configuration/auth/ "Qwen Code authentication"
[55]: https://qwenlm.github.io/qwen-code-docs/en/users/configuration/model-providers/ "Qwen Code model providers"
[56]: https://qwenlm.github.io/qwen-code-docs/en/users/configuration/settings/ "Qwen Code settings"
