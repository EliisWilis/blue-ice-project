# ProtectAI LLM Guard reference

Blue Ice Project treats LLM Guard as an optional input/output scanner, not as the proxy, provider router, credential vault, or a zero-retention guarantee.

The upstream repository README says that LLM Guard scans prompt inputs and model outputs through scanner families, and explicitly warns that the project has been archived and is no longer actively developed or maintained.[1] GitHub metadata lists the repository as archived and the license as MIT.[2] PyPI lists `0.3.16`, released May 19, 2025, as the latest release; the files in that release have no PyPI provenance metadata.[3] Because the dependency is archived, Blue Ice Project does not install it by default. If an operator explicitly chooses the optional adapter, the dependency is pinned to `llm-guard==0.3.16`; pinning does not make an archived package maintained or audited. The adapter calls the documented `scan_prompt` and `scan_output` APIs; when enabled, scanner initialization or runtime failure blocks the request.

A privacy preference sent to a provider does not establish that the provider retains no data. Blue Ice Project redacts detected material before forwarding, but the remaining prompt is still transmitted to the selected provider. The optional PyPI package states Python `>=3.10,<3.13`; its extra is therefore intended only for Python 3.10 through 3.12, even though the base project supports newer Python versions.[3]

## Upstream references

[1]: https://github.com/protectai/llm-guard "ProtectAI LLM Guard repository and README"
[2]: https://api.github.com/repos/protectai/llm-guard "ProtectAI LLM Guard repository metadata"
[3]: https://pypi.org/project/llm-guard/ "LLM Guard release metadata on PyPI"
