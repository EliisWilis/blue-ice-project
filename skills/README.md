# Project skills

`reverse-engineer-anything` is the REA skill used for shipped artifacts and runtime evidence. It is intentionally not used for ordinary source-repository analysis.

The `agency-*` directories are imported from [WebWakaHub/manus-agency-skills](https://github.com/WebWakaHub/manus-agency-skills). They are prompt/operating skills, not executable runtime dependencies and do not register MCP servers or install providers by themselves.

The runtime gateway remains provider-neutral. Coding agents use the authenticated OpenAI-compatible API documented in `docs/agent-integrations.md`; skills do not receive or store upstream API keys.
