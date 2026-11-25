<div align="center">
  <img src="assets/blue-ice-logo.png" alt="Blue Ice Project logo" width="108" />
  <h1>Blue Ice Project</h1>
  <p>A local OpenAI-compatible privacy gateway for coding agents</p>
  <p>
    <img src="https://img.shields.io/badge/Python-3.12%2B-3776AB?logo=python&logoColor=white" alt="Python 3.12 or newer" />
    <img src="https://img.shields.io/badge/Node.js-20%2B-339933?logo=nodedotjs&logoColor=white" alt="Node.js 20 or newer for the TypeScript CLI" />
    <img src="https://img.shields.io/badge/License-MIT-007EC6" alt="MIT License" />
    <img src="https://img.shields.io/badge/Status-Alpha-orange" alt="Alpha software" />
  </p>
</div>

Blue Ice Project is an early-stage local proxy that sits between a coding client and one explicitly selected AI provider. It offers bounded, configurable checks for requests and responses. It is defense in depth, not a complete security boundary, sandbox, certified gateway, or guarantee of confidentiality or zero data retention.

## Contents

- [What it does](#what-it-does)
- [Tech stack](#tech-stack)
- [Supported APIs and providers](#supported-apis-and-providers)
- [Quick start](#quick-start)
- [Configure providers and credentials](#configure-providers-and-credentials)
- [Use the TypeScript/Node terminal client](#use-the-typescriptnode-terminal-client)
- [Connect an agent or OpenAI-compatible client](#connect-an-agent-or-openai-compatible-client)
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
| `GET /v1/models` | Configured local service | Requires the local bearer token by default; reports models exposed by the selected configuration. |
| `POST /v1/chat/completions` | Supported provider routes | OpenAI Chat Completions-compatible requests; provider and model must be configured. |
| `POST /v1/responses` | Native Responses only | Available for built-in `openai` or a custom provider with an explicitly registered native `responses_url`. Other providers return `501`; no lossy Chat Completions-to-Responses translation is attempted. |

Built-in Chat Completions destinations are **OpenAI, OpenRouter, Groq, Google, Cerebras, and loopback-only Ollama**. Custom providers may be registered with trusted HTTPS Chat Completions URLs. A custom Responses URL is optional and must be explicitly supplied for an upstream that implements the native Responses API.

Having an OpenAI-compatible base URL does not prove that a client uses a supported route, authentication header, streaming format, tool-call format, or model feature. Client examples are not certification or end-to-end test results. See [agent integration status](docs/agent-integrations.md).

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
  --model vendor-model
```

If, and only if, the upstream implements the native Responses API, register its separate native endpoint:

```sh
blue-ice provider add vendorx \
  --url https://api.vendor.example/v1/chat/completions \
  --responses-url https://api.vendor.example/v1/responses \
  --model vendor-model
```

`provider add` selects the new provider in local policy. Its HTTPS endpoint URL is stored in the private policy file; the API key remains in the environment or keyring. Custom hosts are checked for public DNS answers, but the address is not pinned to the HTTP connection, so DNS rebinding/TOCTOU remains a residual risk. Use only trusted endpoints.

### How the gateway router selects a provider

Select the active upstream on the Blue Ice service, not separately in each agent. For example, `blue-ice provider use openrouter --model openrouter/auto` routes requests from every local agent through that configured OpenRouter destination. The agent's model ID must be accepted by the active provider. The current router uses one selected upstream at a time; it does not provide per-agent upstream routing, key rotation, cross-provider fallback, or automatic failover. After changing providers, set that provider's key in the service environment or keyring and restart `blue-ice start`.

The example policy [`config.example.yaml`](config.example.yaml) contains no API keys. Defaults include a 2,000,000-byte request limit, an 8,000,000-byte response limit, local auth enabled, registry checks disabled, and LLM Guard disabled. Optional fields include `allowed_domains`, custom providers, audit/token paths, and the project root. Use a private config file; never add credentials to YAML.

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

**No end-to-end integration test was completed for any agent in this list.** “Documented” means the client documentation describes a relevant configuration path, not that Blue Ice is certified or tested with that client. The [agent installation and compatibility guide](docs/agent-integrations.md) includes official install links, exact provider/key separation, configuration examples, protocol notes, and verification caveats for 15 clients.

## Commands

The Python CLI is `blue-ice`. The TypeScript/Node front end is `blue-ice-node` after `npm link`.

| Command | Purpose |
|---|---|
| `blue-ice --help` | Show available commands in plain text. |
| `blue-ice init --project-root PATH --provider NAME` | Create private policy and local token files; `--force` replaces policy settings, not an existing key. |
| `blue-ice start [--host 127.0.0.1] [--port 8080] [--config PATH]` | Start the loopback-only API service. |
| `blue-ice provider list [--config PATH]` | List built-in and registered provider names without credential data. |
| `blue-ice provider use NAME [--model MODEL] [--config PATH]` | Select one built-in or registered provider explicitly. |
| `blue-ice provider add NAME --url URL [--responses-url URL] [--model MODEL] [--keyring]` | Register a trusted HTTPS custom provider; API keys are never command-line arguments. |
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
- [Example configuration](config.example.yaml)
- [MIT license](LICENSE)

Blue Ice Project code is MIT licensed. Bundled upstream skills retain their respective licenses and attribution under [`licenses/`](licenses/).
