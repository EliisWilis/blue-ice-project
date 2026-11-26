# LLM Guard: setup and verified behavior

Blue Ice ships LLM Guard as an opt-in extra because upstream `llm-guard==0.3.16` is archived. It is not automatically installed, and enabling it does not turn heuristic scanning into a security guarantee. See the [upstream status and compatibility notes](llm-guard.md).

## Install and enable

The project requires Python 3.12 or newer. The pinned LLM Guard release declares support only through Python 3.12, so use Python 3.12 for this optional extra:

```sh
python -m pip install '.[llm-guard]'
```

In the private local configuration file (normally `~/.aegis/config.yaml`), set:

```yaml
llm_guard_enabled: true
```

Restart `blue-ice start` after changing the configuration. The default adapter creates input `Secrets` and output `Sensitive` scanners. Scanner initialization or runtime failure blocks the request; the proxy does not silently skip an enabled scanner. Install and initialize the scanners in a trusted environment with network access available: first initialization may fetch language/model resources. Do not put provider keys in the YAML file.

For development tests, install both extras with:

```sh
python -m pip install -e '.[dev,llm-guard]'
pytest -q
```

The optional dependency brings additional NLP/ML packages and model resources. Review the resulting dependency and resource footprint before enabling it in production.

## Behavior and limits

When enabled, Blue Ice scans request strings before forwarding and scans buffered assistant output before releasing it. Scanner rewrites are returned for ordinary Chat Completions and non-streaming Responses. The Responses streaming path cannot safely apply output rewrites to replayed events; it withholds a stream if a scanner says rewriting was necessary. Scanner rejection blocks content, while scanner failure returns an unavailable/error response. LLM Guard is not a native adapter for Claude, Gemini, Codex, or other agent protocols: it is one optional scan stage in Blue Ice's existing supported request paths.

The scanner does not prove that prompts are safe, detect every secret or sensitive value, provide an OS sandbox, or guarantee privacy from the selected upstream. Keep the project's other controls and least-privilege agent permissions enabled.

## Verification performed in the development sandbox

On 2026-11-25, `llm-guard==0.3.16` was installed with the development extra under Python 3.12. The actual default scanner set initialized as `Secrets` and `Sensitive`; one harmless input and one harmless output passed with no rewrite. Gateway regression tests use injected scanner outcomes to verify input sanitization, scanner rejection before a provider call on both Chat Completions and Responses, and fail-closed behavior on scanner outage. The tests do not claim a live provider/agent end-to-end test, broad detection precision/recall, or comprehensive security assurance.

The tested commands were `pytest -q`, `ruff check src tests`, `ruff format --check src tests`, and `python -m compileall -q src tests`.

## References

- [LLM Guard repository and archived status](https://github.com/protectai/llm-guard)
- [LLM Guard on PyPI](https://pypi.org/project/llm-guard/)
- [Blue Ice LLM Guard notes](llm-guard.md)
