# Good first issue drafts

These are proposals, not published GitHub issues. Create them only when a maintainer is ready to review contributions. Apply the `good first issue` label and add `documentation` or `tests` where appropriate.

## Add model-catalog edge-case tests

**Suggested labels:** `good first issue`, `tests`

Add a focused test for `GET /v1/models` that verifies duplicate model IDs are returned only once and malformed rows are ignored. Reuse the fake provider patterns in `tests/test_app.py`; do not make a live provider call or use real credentials.

**Done when:** the test passes locally, covers at least one duplicate and one malformed row, and does not require network access.

## Document one custom OpenAI-compatible provider

**Suggested labels:** `good first issue`, `documentation`

Add a short setup example for one provider or gateway that implements OpenAI Chat Completions with Bearer authentication. Link to its official endpoint documentation, show the Chat Completions URL and model-list URL if it differs from the conventional route, and name the required environment-variable pattern without inventing a real key.

**Done when:** the example uses clearly synthetic host/model values or the provider's documented public endpoints, contains no credentials, distinguishes documented behavior from tested behavior, and is linked from `examples/README.md`.

## Clarify an agent's model selection steps

**Suggested labels:** `good first issue`, `documentation`

Choose one coding agent and document how a user configures a local OpenAI-compatible base URL, supplies the Blue Ice local token through that client's documented secret mechanism, and selects a model returned by `/v1/models`. Include official documentation links and note any behavior that has not been tested with Blue Ice.

**Done when:** the steps identify the client version or documentation date, keep the upstream provider key out of the agent configuration, and make no unsupported compatibility claim.
