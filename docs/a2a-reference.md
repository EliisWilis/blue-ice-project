# A2A reference

Blue Ice uses the [official A2A repository](https://github.com/a2aproject/A2A) as the protocol reference for possible agent-to-agent delegation. The local reference studied at this stage is pinned to commit `a506d01`.

A2A and MCP have different boundaries:

- MCP connects a model or agent to tools and a context server.
- A2A connects agents for delegation, task lifecycle, streaming, and work results.
- The Responses API remains the model-traffic path from Codex to Blue Ice.

A2A is not currently a required runtime dependency, and no A2A facade is active in the gateway. Any facade implementation must wait for a clear delegation requirement and have its own authentication, authorization, bounded task state, audit metadata, egress checks, and contract tests. Do not claim full A2A support merely because the reference repository is available.
