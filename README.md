<div align="center">
  <img src="assets/blue-ice-logo.png" alt="Blue Ice Project logo" width="176" />
  <h1>Blue Ice Project</h1>
  <p>A local OpenAI-compatible privacy gateway for coding agents</p>
  <p>
    <img src="https://img.shields.io/badge/Python-3.12%2B-3776AB?logo=python&logoColor=white" alt="Python 3.12 or newer" />
    <img src="https://img.shields.io/badge/Node.js-20%2B-339933?logo=nodedotjs&logoColor=white" alt="Node.js 20 or newer for the TypeScript CLI" />
    <a href="https://github.com/EliisWilis/blu-ice-project/actions/workflows/ci.yml"><img src="https://github.com/EliisWilis/blu-ice-project/actions/workflows/ci.yml/badge.svg?branch=main" alt="CI status" /></a>
    <img src="https://img.shields.io/badge/License-MIT-007EC6" alt="MIT License" />
    <img src="https://img.shields.io/badge/Status-Alpha-orange" alt="Alpha software" />
    <a href="#offline-demo"><img src="https://img.shields.io/badge/Demo-offline%20run-blue" alt="Run the offline demo" /></a>
    <a href="https://github.com/EliisWilis/blu-ice-project/stargazers"><img src="https://img.shields.io/github/stars/EliisWilis/blu-ice-project?style=flat" alt="GitHub stars" /></a>
  </p>
  <p>
    <a href="https://m8ven.ai/mcp/eliiswilis-blue-ice-project-mgg3ka?s=readme"><img src="https://m8ven.ai/badge/mcp/eliiswilis-blue-ice-project-mgg3ka?v=dc2b4bceaed7038aa3650b36f05f168c" alt="M8ven Score" /></a>
  </p>
</div>

Blue Ice Project is an early-stage local proxy that sits between a coding client and one explicitly selected AI provider. It offers bounded, configurable checks for requests and responses. It is defense in depth, not a complete security boundary, sandbox, certified gateway, or guarantee of confidentiality or zero data retention.

## Highlights

- Route OpenAI Chat Completions requests through one explicitly selected provider or trusted custom OpenAI-compatible endpoint.
- Keep the upstream provider key in the gateway environment or OS keyring, separate from the local bearer token used by an agent.
- Discover model IDs through authenticated `/v1/models` when the selected upstream supports a compatible catalog.
- Apply configurable, bounded request/response checks and metadata-only local audit events; these controls are heuristics, not a sandbox.
- Use the optional plain-text TypeScript/Node terminal client to inspect models and delegate supported commands.

The repository includes a real offline demonstration rather than a hosted AI playground: it uses synthetic provider responses to exercise authentication, model listing, and chat completion without a real key or external network call.

## Contents

- [What it does](#what-it-does)
- [Tech stack](#tech-stack)
- [Supported APIs and providers](#supported-apis-and-providers)
- [Offline demo](#offline-demo)
- [Quick start](#quick-start)
- [Install on Linux, macOS, and Windows](#install-on-linux-macos-and-windows)
- [Configure providers and credentials](#configure-providers-and-credentials)
- [Model discovery for agents](#model-discovery-for-agents)
- [Use the TypeScript/Node terminal client](#use-the-typescriptnode-terminal-client)
- [Connect an agent or OpenAI-compatible client](#connect-an-agent-or-openai-compatible-client)
- [Agent connection matrix](#agent-connection-matrix)
- [Troubleshooting](#troubleshooting)
- [Agent installation and compatibility guide](docs/agent-integrations.md)
- [Commands](#commands)
- [Security-module maturity](#security-module-maturity)
- [Security, privacy, and operational limits](#security-privacy-and-operational-limits)
- [Development and checks](#development-and-checks)
- [Project documentation](#project-documentation)

## What it does

The service binds to a loopback IP address only (default `127.0.0.1:8080`). It requires a private local bearer token by default, applies request/response byte limits, and routes to one configured provider. Provider destinations are selected in local policy; request payloads cannot choose an outbound URL. The proxy does not rotate provider keys or silently fail over to another provider.

For requests that pass policy, the main path can:

- Check recognizable file-path references against the configured project root and `.privacyignore` patterns. This is a text-reference filter, not filesystem confinement.
- Replace recognized secrets with request-scoped placeholders before forwarding, then restore only exact placeholders after response checks. Detection is heuristic and does not guarantee secure erasure.
- Run the optional LLM Guard adapter when explicitly enabled. It is disabled by default; scanner initialization or runtime failure blocks the request when enabled. The upstream LLM Guard repository is archived.
- Inspect buffered model output for a limited set of risky shell-command patterns and unapproved Markdown links. This is a heuristic content check, not command-execution control.
- Optionally query public PyPI/npm registries about package names suggested in response text. This is not an install interceptor and discloses queried package names to those registries.
- Write bounded, owner-only, metadata-only audit events. Prompts, provider responses, API keys, and reversible secret mappings are not intended to be logged. If an audit write fails, the response is withheld and the API returns an audit error rather than silently treating the event as recorded.
- Retrieve the selected provider's model catalog through the authenticated local `/v1/models` route when the upstream supports OpenAI-compatible model listing; the API key remains on the proxy side.

Both Chat Completions and Responses payloads are buffered for inspection before delivery. Chat Completions SSE is recreated after checks. Responses SSE is parsed and inspected in full before replay; a terminal completion event is required and events after completion are rejected. This is not incremental streaming and adds latency and memory use.

## Tech stack

| Layer | Technologies | Role |
|---|---|---|
| Proxy service | Python 3.12+, FastAPI, Uvicorn/ASGI, asyncio | Local HTTP API and asynchronous request handling |
| Provider transport | HTTPX | Bounded upstream HTTP requests; redirects are disabled |
| Configuration and CLI | PyYAML, Typer | Local YAML policy and the `blue-ice` control command |
| Credential storage | Environment variables, Python `keyring` | Provider credentials are kept out of YAML and command-line arguments |
| Optional scanning | LLM Guard 0.3.16 extra | Opt-in scanning adapter; archived upstream, disabled by default |
| TypeScript terminal client | TypeScript 5.6+, Node.js 20+ | Plain-text front end; Node built-ins at runtime, no extra runtime package dependencies |
| Build and test tools | setuptools, wheel, pytest, pytest-asyncio, Ruff, mypy | Packaging, tests, lint/format, and optional development checks |

The project is in **Alpha**. Versions and optional dependencies are declared in [`pyproject.toml`](pyproject.toml) and [`cli-node/package.json`](cli-node/package.json).

## Supported APIs and providers

| API | Availability | Notes |
|---|---|---|
| `GET /healthz` | Local service | Health endpoint; it is unauthenticated and does not disclose a provider key. |
| `GET /v1/blue-ice/capabilities` | Authenticated local service | Non-secret discovery document for agent API paths, buffered streaming, tool-call pass-through, and enabled guard controls. |
| `POST /mcp` | Authenticated local service | Read-only MCP JSON-RPC tools over Streamable HTTP; supports capability, model, audit, skill, and project-policy inspection. |
| `GET /v1/models` | Configured local service | Requires the local bearer token by default; fetches the selected provider's OpenAI-compatible model catalog. If the provider returns `404`, `405`, or `501`, Blue Ice returns the configured model only and marks the response with `X-Blue-Ice-Models-Source: configured-fallback`. |
| `POST /v1/chat/completions` | Supported provider routes | OpenAI Chat Completions-compatible requests; provider and model must be configured. |
| `POST /v1/responses` | Native Responses only | Available for built-in `openai` or a custom provider with an explicitly registered native `responses_url`. Other providers return `501`; no lossy Chat Completions-to-Responses translation is attempted. |
| `POST /v1/messages` | Native-agent adapter | Anthropic Messages-shaped requests are translated to the selected provider's Chat Completions route and replayed as buffered JSON or SSE. |
| `POST /v1beta/models/{model}:generateContent` | Native-agent adapter | Gemini GenerateContent-shaped requests are translated to Chat Completions and returned as Gemini-shaped JSON or buffered SSE. |

Built-in Chat Completions destinations are **OpenAI, OpenRouter, Groq, Google, Cerebras, and loopback-only Ollama**. Blue Ice is not limited to that list: add any trusted provider or gateway that implements OpenAI Chat Completions with Bearer authentication. Custom providers may supply an explicit `models_url`; otherwise Blue Ice derives `/models` from the configured `/chat/completions` endpoint. Ollama model names are discovered from its local tags API. A custom Responses URL is optional and must be explicitly supplied for an upstream that implements the native Responses API.

This is a broad compatibility path, not support for every proprietary protocol. Blue Ice now includes bounded Anthropic Messages and Gemini GenerateContent adapters, but the adapters cover the mapped text/tool subset and must still be verified with each installed client version. Other provider-specific APIs still need dedicated adapters. See the [agent compatibility guide](docs/agent-integrations.md) for client-specific limits.

Having an OpenAI-compatible base URL does not prove that a client uses a supported route, authentication header, streaming format, tool-call format, or model feature. Client examples are not certification or end-to-end test results. See [agent integration status](docs/agent-integrations.md).

## Offline demo

Try the local request path without creating an AI-provider account or entering an API key. The fake provider is injected into the app; the demo makes no external network connection and uses only temporary synthetic credentials and responses.

From the repository root:

```sh
python -m pip install .
python examples/offline_demo.py
```

The demo verifies that unauthenticated model-list requests are rejected, an authenticated `GET /v1/models` returns two synthetic IDs, and an authenticated `POST /v1/chat/completions` returns a synthetic completion. It removes its temporary token and audit files when it finishes. This is a runnable local demo, not a live model response or hosted notebook.

[Watch the 5-second Blue Ice Project demo video](docs/assets/blue-ice-launch-demo.mp4) (MP4, 16:9). The moving background is AI-generated; the terminal panel shows output from the actual offline demo run. Provider responses are synthetic, and the video is not a live-provider or security guarantee demonstration.

## Quick start

Requirements: Python 3.12 or newer. The optional TypeScript terminal client requires Node.js 20 or newer.

From the repository root:

```sh
python -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install .
blue-ice init --project-root /absolute/path/to/your/project --provider openrouter
```

`--project-root` must be an existing directory. `init` creates local policy and a local bearer-token file under `~/.aegis/`, plus a `.privacyignore` in the selected project unless one already exists. The `.aegis` directory is a legacy storage namespace retained for compatibility. Review the generated policy and ignore rules before connecting an agent. Do not commit local config, token, or audit files.

In the same shell, set the upstream provider key without placing it in command history, then start the proxy:

```sh
read -r -s -p "OpenRouter API key: " AEGIS_OPENROUTER_API_KEY
printf '\n'
export AEGIS_OPENROUTER_API_KEY
blue-ice start
```

Keep this process running. The service listens at `http://127.0.0.1:8080` by default. In a separate terminal, configure your client to use `http://127.0.0.1:8080/v1` and the local token in `~/.aegis/local-token`. The local token authenticates to Blue Ice Project; it is not the provider's API key.

The `init` command can offer to store a provider key in an available OS keyring. Use that option only if the selected system keyring has a secure, working backend. The Python CLI also supports `blue-ice start --port 8081` and `blue-ice start --config /path/to/private-config.yaml`. It refuses non-loopback bind addresses.

## Install on Linux, macOS, and Windows

Blue Ice is a local Python application. The gateway itself works on Linux, macOS, Windows, and Windows Subsystem for Linux (WSL) as long as Python 3.12 or newer is available. Use a virtual environment so the gateway and its dependencies remain isolated from the operating system.

### Linux

Install Python and the repository with your distribution's package manager, then create the virtual environment:

```sh
# Debian/Ubuntu example; use the equivalent packages for your distribution.
sudo apt update
sudo apt install -y python3.12 python3.12-venv python3-pip git
git clone https://github.com/EliisWilis/blue-ice-project.git
cd blue-ice-project
python3.12 -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install .
```

### macOS

Install Python with [Homebrew](https://brew.sh/) or use the official Python installer. Homebrew users can run:

```sh
brew install python@3.12 git
git clone https://github.com/EliisWilis/blue-ice-project.git
cd blue-ice-project
python3.12 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install .
```

### Windows PowerShell

Install Python 3.12+ from [python.org](https://www.python.org/downloads/windows/) or the Microsoft Store, and install Git from [git-scm.com](https://git-scm.com/download/win). In PowerShell:

```powershell
git clone https://github.com/EliisWilis/blue-ice-project.git
Set-Location blue-ice-project
py -3.12 -m venv .venv
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install .
```

If PowerShell activation is restricted by local policy, invoke the environment directly instead of changing a permanent policy:

```powershell
.\.venv\Scripts\blue-ice.exe --help
```

Windows stores the local token and policy under the current user's home directory. Keep the default loopback binding; do not use `--host 0.0.0.0` or expose the service through a public firewall rule. WSL users should follow the Linux commands inside WSL and run the coding agent in the same WSL/network namespace when using `127.0.0.1`.

### Initialize and start on any OS

After installation, use an absolute project path. The project directory is the policy boundary used by path checks; it does not grant Blue Ice filesystem sandboxing:

```sh
blue-ice init --project-root /absolute/path/to/your/project --provider openrouter
blue-ice provider use openrouter --model openrouter/auto
blue-ice start
```

On Windows PowerShell, use a Windows path:

```powershell
blue-ice init --project-root 'C:\Users\you\src\my-project' --provider openrouter
blue-ice provider use openrouter --model openrouter/auto
blue-ice start
```

Keep the terminal running. The local service is available at `http://127.0.0.1:8080`; health can be checked at `http://127.0.0.1:8080/healthz`. The default local token is at `~/.aegis/local-token` on Unix-like systems and under the equivalent user home directory on Windows. Do not commit that token, generated policy, or audit files.

### Upgrade or uninstall

From an activated virtual environment, update the checkout and reinstall the package:

```sh
git pull --ff-only
python -m pip install --upgrade .
```

To remove the application, delete the checkout and `.venv`. Remove `~/.aegis/` only after backing up or intentionally deleting its local token, policy, and audit files. Python package uninstall is optional because the virtual environment can be deleted as a unit:

```sh
python -m pip uninstall blue-ice-project
```

## Configure providers and credentials

Provider keys are loaded from provider-specific environment variables or the OS keyring. Keys are not accepted as CLI arguments and are not supported as YAML fields. Keep key values out of source code, shell history, issue reports, and logs.

| Provider | Environment variable |
|---|---|
| OpenAI | `AEGIS_OPENAI_API_KEY` |
| OpenRouter | `AEGIS_OPENROUTER_API_KEY` |
| Groq | `AEGIS_GROQ_API_KEY` |
| Google | `AEGIS_GOOGLE_API_KEY` |
| Cerebras | `AEGIS_CEREBRAS_API_KEY` |
| Custom provider named `vendorx` | `AEGIS_CUSTOM_VENDORX_API_KEY` |
| Ollama | No cloud API key; loopback endpoint only |

For a different built-in provider, initialize or select it and set its corresponding key variable in the service shell. For example:

```sh
blue-ice provider use openai --model '<model-id-supported-by-your-account>'
read -r -s -p "OpenAI API key: " AEGIS_OPENAI_API_KEY
printf '\n'
export AEGIS_OPENAI_API_KEY
blue-ice start
```

Register a custom endpoint only if you control or trust it:

```sh
blue-ice provider add vendorx \
  --url https://api.vendor.example/v1/chat/completions \
  --models-url https://api.vendor.example/v1/models \
  --model vendor-model
```

If, and only if, the upstream implements the native Responses API, register its separate native endpoint:

```sh
blue-ice provider add vendorx \
  --url https://api.vendor.example/v1/chat/completions \
  --responses-url https://api.vendor.example/v1/responses \
  --model vendor-model
```

`--models-url` is optional when the provider uses the matching OpenAI-compatible `/models` route. `provider add` selects the new provider in local policy. Its HTTPS endpoint URLs are stored in the private policy file; the API key remains in the environment or keyring and is never accepted as a command-line argument. Blue Ice sends that upstream key to both configured provider endpoints, so an explicit `--models-url` must be operated by the same provider you trust. Custom hosts are checked for public DNS answers, but the address is not pinned to the HTTP connection, so DNS rebinding/TOCTOU remains a residual risk. Use only trusted endpoints.

### How the gateway router selects a provider

Select the active upstream on the Blue Ice service, not separately in each agent. For example, `blue-ice provider use openrouter --model openrouter/auto` routes requests from every local agent through that configured OpenRouter destination. The agent's model ID must be accepted by the active provider. The current router uses one selected upstream at a time; it does not provide per-agent upstream routing, key rotation, cross-provider fallback, or automatic failover. After changing providers, set that provider's key in the service environment or keyring and restart `blue-ice start`.

The example policy [`config.example.yaml`](config.example.yaml) contains no API keys. Defaults include a 2,000,000-byte request limit, an 8,000,000-byte response limit, local auth enabled, registry checks disabled, and LLM Guard disabled. Optional fields include `allowed_domains`, custom providers, audit/token paths, and the project root. Use a private config file; never add credentials to YAML.

### Model discovery for agents

`GET http://127.0.0.1:8080/v1/models` asks the selected upstream for its model catalog using the provider credential held by the Blue Ice service. The local agent only needs the separate Blue Ice token. The `blue-ice-node models` command displays the same result. The list contains model IDs, not capability guarantees; a provider can expose models that do not support every tool, streaming mode, or API route.

An agent that queries the OpenAI-compatible `/v1/models` route may display the upstream model IDs. Some clients—including configurations that require an explicit model list—do not automatically query that route; add the returned model ID in the agent's own provider settings when needed. When an upstream does not implement model listing (`404`, `405`, or `501`), Blue Ice returns only the configured model so existing client setup can still proceed. This does not make every agent's native protocol compatible.

Agents that need to discover the gateway contract can call the authenticated `/v1/blue-ice/capabilities` endpoint. It reports the selected provider and model, API paths, native Responses availability, buffered streaming behavior, tool-call pass-through, and enabled guard controls. It never returns provider credentials, prompts, responses, audit records, or filesystem paths.

### Codex MCP tools

Blue Ice also exposes a read-only MCP server for Codex. MCP is an additional tools channel; it does not replace the model gateway. Codex model traffic still uses the native Responses API at `/v1/responses` when the selected provider supports it.

For a local Codex process, use the STDIO transport:

```toml
[mcp_servers.blue_ice]
command = "blue-ice"
args = ["mcp"]
enabled = true
```

When Blue Ice is already running, the authenticated Streamable HTTP transport is available at `http://127.0.0.1:8080/mcp`:

```toml
[mcp_servers.blue_ice]
url = "http://127.0.0.1:8080/mcp"
bearer_token_env_var = "BLUE_ICE_TOKEN"
enabled = true
```

Set the local token in the environment without placing it in `config.toml`:

```sh
export BLUE_ICE_TOKEN="$(cat "$HOME/.aegis/local-token")"
```

The initial MCP tools are read-only: capability discovery, model listing, metadata-only audit reading, installed-skill listing/reading, project-path policy checks, and deterministic security checks. MCP does not expose arbitrary shell execution, provider credentials, prompts, responses, or secret mappings. The MCP contract is tested locally; no Codex binary version is claimed as end-to-end verified yet.

## Use the TypeScript/Node terminal client

The Node client is an optional plain-text TypeScript front end. It uses ordinary text labels, with no decorative terminal symbols or ANSI styling. It does not read or handle provider API keys. Its `models` command reads the private local token file and calls only `127.0.0.1`; other commands delegate to the Python CLI.

From the repository root, after installing the Python package:

```sh
cd cli-node
npm ci
npm run build
npm link
blue-ice-node help
blue-ice-node models
```

The installed command is `blue-ice-node` so it does not collide with the Python `blue-ice` executable that the Node front end uses for delegated commands. `models` accepts `--port N` if the local proxy uses a non-default port. The Python service must be initialized and running first.

## Connect an agent or OpenAI-compatible client

Install the agent using its official instructions in the [detailed agent guide](docs/agent-integrations.md), then point it at `http://127.0.0.1:8080/v1` if it supports a local OpenAI-compatible endpoint. Give the agent the **local Blue Ice token** from `~/.aegis/local-token`; keep the upstream OpenAI/OpenRouter/Groq/Google/Cerebras/custom-provider key in the Blue Ice service environment or OS keyring. Never paste the upstream provider key into an agent configured to call Blue Ice.

For clients that support these environment names, a common local-token setup is:

```sh
export OPENAI_BASE_URL='http://127.0.0.1:8080/v1'
export OPENAI_API_KEY="$(cat "$HOME/.aegis/local-token")"
```

Client variable names and authentication behavior differ. Use each agent's documented secret mechanism, and verify that it sends `Authorization: Bearer <local-token>` to the gateway. Run the client on the same machine/network namespace as Blue Ice; a remote agent cannot reach the host's loopback address by default.

The current documented integration paths are:

- **Chat Completions endpoint configuration documented:** Hermes Agent, OpenClaw, Cline, Continue, and Qwen Code. This describes their configuration options; tool calls, streaming, local Bearer-header behavior, or model features can still need verification for the installed version.
- **Conditional setup:** OpenCode, Kilo Code, Roo Code, Aider, and Goose because important details such as exact route, local-token header handling, streaming, or native tool calls are not established for Blue Ice.
- **Responses-only and conditional:** Codex CLI and Codex desktop require a native Responses endpoint and compatible streaming, continuation, and tool behavior. Codex Security CLI has separate authentication and configuration and is not verified.
- **Not directly compatible with the current API:** Claude Code documents the Anthropic Messages protocol; Gemini CLI documents the Gemini API protocol. Blue Ice does not expose those APIs.
- **Unclear:** Cursor's custom-base-URL path does not establish reliable loopback access or safe local-token forwarding, and its request protocol can vary by model.

### Agent connection matrix

Use the official installation method for the agent, then apply the connection pattern below. The gateway URL is the same on Linux, macOS, Windows, and WSL; only the shell syntax for setting environment variables changes. The token in every row is the **local Blue Ice token**, never an upstream provider key.

| Agent | Connection pattern | Current status | Notes |
|---|---|---|---|
| Codex CLI / Codex desktop | Native Responses at `/v1/responses` plus MCP at `/mcp` | Conditional | Use the MCP STDIO or authenticated HTTP setup above. The provider must expose native Responses; model traffic and MCP tools are separate. |
| Hermes Agent | OpenAI Chat Completions at `/v1` | Documented, untested | Configure the custom base URL and local token according to the agent guide. |
| OpenCode | OpenAI-compatible provider at `/v1` | Conditional | Verify the exact request path and Bearer header for the installed adapter. |
| OpenClaw | `openai-completions` provider at `/v1` | Documented, untested | Keep the token in its environment or secret file, not in a shared project config. |
| Claude Code | Anthropic-shaped `/v1/messages` adapter | Implemented, untested | Only the mapped text/tool subset is covered; configure the local token as its gateway credential. |
| Gemini CLI | Gemini-shaped `generateContent` adapter | Implemented, untested | Verify that the CLI sends the local token to the configured gateway rather than to Google directly. |
| Kilo Code | OpenAI Compatible provider at `/v1` | Conditional | Confirm Bearer authentication, streaming, and tool-call behavior. |
| Cline | OpenAI Compatible provider at `/v1` | Documented, untested | Store the token in user-level settings or an environment-backed secret. |
| Roo Code | OpenAI Compatible provider at `/v1` | Conditional | Native tool calling and the selected protocol still require client-version testing. |
| Continue | OpenAI provider at `/v1` | Documented, untested | Set `useResponsesApi: false` unless a native Responses provider is configured. |
| Cursor | Custom base URL | Unclear | Do not place the local token in a cloud BYOK field unless the client documents local forwarding. |
| Aider | `OPENAI_BASE_URL` and `OPENAI_API_KEY` | Conditional | Use the local token for `OPENAI_API_KEY`; keep `.env` files outside the repository. |
| Goose | OpenAI Compatible custom provider | Conditional | Use its local credential store and verify the emitted Authorization header. |
| Qwen Code | OpenAI provider at `/v1` | Documented, untested | Keep the local token in its user-level environment configuration. |
| Codex Security CLI | Separate security application | Not verified | It has separate scanner authentication and configuration; ordinary Codex setup is not proof of support. |

For exact install links, config files, credential locations, protocol details, and per-client caveats, use the [agent installation and compatibility guide](docs/agent-integrations.md). A client can be installed successfully and still fail against Blue Ice because of a route, protocol, model, streaming, or authentication mismatch.

**No end-to-end integration test was completed for any agent in this list.** “Documented” means the client documentation describes a relevant configuration path, not that Blue Ice is certified or tested with that client. The [agent installation and compatibility guide](docs/agent-integrations.md) includes official install links, exact provider/key separation, configuration examples, protocol notes, and verification caveats for 15 clients.

## Troubleshooting

### `401 unauthorized` or the agent cannot connect

Confirm that Blue Ice is running, the client uses `http://127.0.0.1:8080/v1`, and the client sends `Authorization: Bearer <local-token>`. Read the token from `~/.aegis/local-token` (or the equivalent Windows user-home path) and do not substitute the upstream provider key. For MCP HTTP, set `BLUE_ICE_TOKEN` and use `/mcp`, not `/v1/mcp`.

### `501` from `/v1/responses`

The selected provider does not have a registered native Responses endpoint. Use Chat Completions with an agent that supports it, select the built-in `openai` provider, or register a trusted custom provider with `--responses-url`. Blue Ice intentionally does not perform a lossy protocol translation.

### The model list is empty or missing the expected model

Run `blue-ice provider list`, confirm the active provider and model with `blue-ice provider use`, and call the authenticated `/v1/models` route. If the upstream does not implement `/models`, Blue Ice returns the configured model as a fallback. A listed model is not a guarantee that the model supports tools, streaming, or Responses.

### MCP STDIO starts and immediately exits

Run `blue-ice mcp --help` from the same virtual environment used by the agent, then test the command manually with a temporary configuration. For a desktop agent, use the absolute path to the executable when its environment does not inherit the activated shell. STDIO is a protocol process: do not start it as a background HTTP server and do not write diagnostic text to its standard output.

### MCP HTTP returns `404`, `413`, or `500`

Use `POST http://127.0.0.1:8080/mcp` with the local bearer token. `413` means the bounded request-size policy rejected the payload. Check the service terminal and metadata-only audit output for sanitized diagnostics; provider credentials, prompts, responses, and secret mappings are intentionally not logged.

### The provider request is blocked

Review the project root, `.privacyignore`, configured allowed domains, request/response size limits, egress policy, and optional LLM Guard state. When LLM Guard is enabled, scanner initialization or runtime failure blocks requests by design. Do not disable security controls merely to make an unverified client appear compatible.

## Commands

The Python CLI is `blue-ice`. The TypeScript/Node front end is `blue-ice-node` after `npm link`.

| Command | Purpose |
|---|---|
| `blue-ice --help` | Show available commands in plain text. |
| `blue-ice init --project-root PATH --provider NAME` | Create private policy and local token files; `--force` replaces policy settings, not an existing key. |
| `blue-ice start [--host 127.0.0.1] [--port 8080] [--config PATH]` | Start the loopback-only API service. |
| `blue-ice mcp [--config PATH]` | Serve read-only MCP tools over STDIO for local coding agents. |
| `blue-ice provider list [--config PATH]` | List built-in and registered provider names without credential data. |
| `blue-ice provider use NAME [--model MODEL] [--config PATH]` | Select one built-in or registered provider explicitly. |
| `blue-ice provider add NAME --url URL [--models-url URL] [--responses-url URL] [--model MODEL] [--keyring]` | Register a trusted HTTPS OpenAI-compatible provider and optional model-catalog URL; API keys are never command-line arguments. |
| `blue-ice audit [--limit 1..500] [--config PATH]` | Display recent metadata-only audit records; default limit is 50. |
| `blue-ice-node models [--port N]` | Query and print models exposed by the local `/v1/models` endpoint. |

For help on an individual command, run `blue-ice COMMAND --help`, for example `blue-ice provider add --help`. The Python executable is required for delegated commands from the Node client.

## Security-module maturity

The project was audited against a 20-module target. **None of the 20 modules is complete.** The status below distinguishes an active but partial control from a missing target; a helper file alone does not mean that a feature is integrated into the live proxy.

| # | Module | Status | What exists / important boundary |
|---:|---|---|---|
| 1 | PID-bound session proof | Partial | Local bearer auth is on by default; no PID-bound proof or transport. |
| 2 | RAM-only vault, memory lock, zero-fill | Partial | Request-scoped mappings are cleared; no reliable locked-memory or zeroization guarantee. |
| 3 | Project path blast-radius sandbox | Partial | Recognized path references are checked; this is not an OS/filesystem sandbox. |
| 4 | Git history/staged-diff secret guard | Missing | No Git history or index inspection. |
| 5 | Indirect prompt-injection stripping | Missing | No provenance-aware injection/Unicode sanitizer. |
| 6 | Secret, PII, and entropy redaction | Partial | Pattern and entropy heuristics with placeholders; detection is incomplete. |
| 7 | AST code anonymizer | Partial | Opt-in helper exists but is not integrated into ingress; renaming is not scope-aware. |
| 8 | Topology/comment scrubber | Missing | No integrated topology or comment scrubber. |
| 9 | Differential privacy on constants | Missing / not implemented as proposed | No differential privacy. Reversible numeric scaling is not differential privacy and must not be described as such. |
| 10 | Synthetic cryptographic honey token | Partial | Opt-in helper exists but is not wired into the proxy by default. |
| 11 | Split inference across providers | Partial | Planning helper only; no two-provider request orchestration. |
| 12 | Traffic padding and temporal jitter | Missing | No traffic-obfuscation control. |
| 13 | Hybrid local/cloud prompt splitter | Partial | Optional local summarizer helper is not part of the request pipeline. |
| 14 | ZDR routing and quota radar | Partial | Direct routing and bounded same-provider retries; no ZDR guarantee, key rotation, cross-provider fallback, or integrated quota radar. |
| 15 | Hallucinated-package guard | Partial | Optional response-text checks for PyPI/npm; does not intercept actual install commands. |
| 16 | Semantic egress firewall | Partial | Integrated heuristic checks on buffered output; not an execution sandbox. |
| 17 | Encoded-secret smuggling detector | Missing | No Base64/hex output comparison detector. |
| 18 | Git snapshot and rollback | Missing | No workspace snapshot/rollback or filesystem write control. |
| 19 | De-anonymizer and transparency audit | Partial | Exact secret placeholders can be restored; other mapping types are not wired into the app. |
| 20 | Cryptographic output provenance signer | Missing | No output signing or provenance verification. |

See the full [security module matrix](docs/security-module-matrix.md) for evidence, limitations, and follow-up priorities. Do not advertise this project as “20/20 modules complete,” a zero-trust sandbox, or a differential-privacy system.

## Security, privacy, and operational limits

- **Provider data still leaves the machine.** Redaction is incomplete; all remaining request content is sent to the selected provider. Provider retention is governed by that provider and the account’s settings. Local metadata-only audit does not mean zero upstream retention. The gateway forwards Responses fields such as `store` and `previous_response_id`; it does not force `store: false`.
- **Localhost is not a boundary against the same account.** The service uses plain HTTP on loopback. A same-user process or malware with access to the local token can call it. There is no application-level rate limit. Do not expose it to a LAN or public network.
- **Heuristics can miss or block content.** Path rules, secret patterns, entropy thresholds, prompt scanning, command/link inspection, and package metadata checks have false positives and false negatives. They are not substitutes for least-privilege agent permissions or an OS sandbox.
- **Responses are buffered.** Inspection delays delivery and uses memory up to the response byte limit. SSE is replayed after inspection, not forwarded incrementally.
- **Custom DNS is not pinned.** Public DNS is validated, but validation and connection are not atomic; DNS rebinding/TOCTOU remains a residual risk.
- **Optional checks have costs and limits.** LLM Guard is archived upstream and disabled by default. Registry checks are disabled by default and send queried package names to public PyPI/npm endpoints. Provider privacy preferences are not guarantees.
- **Auditing fails closed, but is not tamper-proof.** A failed audit write withholds the response and surfaces `503 audit_unavailable`; it cannot create a record while storage is unavailable. Metadata logs still need local protection.
- **No dedicated secret-scanner binary or CI/pre-commit secret scan is configured.** The prior review included a manual high-confidence pattern scan of workspace text files, not Git-history scanning. Do not assume repository history has been audited.

Read [security review notes](docs/security-review.md) for residual risks and [the full module matrix](docs/security-module-matrix.md) for module-by-module findings.

## Development and checks

```sh
python -m pip install -e '.[dev]'
pytest
ruff check src tests
ruff format --check src tests
python -m compileall -q src tests

cd cli-node
npm ci
npm run build
node dist/index.js help
```

The Node package can also be linked locally as `blue-ice-node` with `npm link`. These checks are useful regression tests; passing them does not prove the software is vulnerability-free. Report reproducible security issues without including real credentials or private prompt content.

## Project documentation

- [LLM Guard notes](docs/llm-guard.md)
- [Security review](docs/security-review.md)
- [20-module security matrix](docs/security-module-matrix.md)
- [Agent integration guide](docs/agent-integrations.md)
- [Codex gateway/protocol research](docs/codex-gateway-research.md)
- [A2A protocol reference and implementation boundary](docs/a2a-reference.md)
- [Contributor guide](CONTRIBUTING.md)
- [Provider setup examples](examples/README.md)
- [Repository promotion drafts](docs/repository-promotion-drafts.md)
- [Suggested good-first-issue drafts](docs/issue-ideas.md)
- [Complete launch playbook](docs/launch-playbook.md)
- [Example configuration](config.example.yaml)
- [MIT license](LICENSE)

## License

Blue Ice Project code is released under the [MIT License](LICENSE). Bundled upstream skills retain their respective licenses and attribution under [`licenses/`](licenses/).
