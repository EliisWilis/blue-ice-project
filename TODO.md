# TODO

## Capability discovery untuk seluruh coding agent
- [x] Endpoint authenticated `GET /v1/blue-ice/capabilities` tersedia.
- [x] Response menjelaskan `GET /v1/models`, Chat Completions, dan Responses tanpa mengekspos API key, prompt, output, audit, atau filesystem path.
- [x] Response menyatakan bahwa streaming dibuffer sebelum inspeksi, tool call diteruskan tetapi output tetap melalui egress checks, dan LLM Guard fail-closed saat aktif.

## Debugging dan validasi
- [x] Semua test yang sudah ada tetap lulus: 50 passed.
- [x] Ruff check, Ruff format check, compileall, dan git diff --check lulus.
- [x] Error typing nyata pada egress firewall dan custom routing diperbaiki tanpa mengubah perilaku runtime; mypy source lulus.
- [x] Test baru mencakup authentication dan shape capability response.

## Skill repository
- [x] 71 skill agency dari `WebWakaHub/manus-agency-skills` tersedia di `skills/agency-*` tanpa `.git` atau credential.
- [x] REA skill tersedia di `skills/reverse-engineer-anything` dan tetap dipakai hanya untuk shipped artifact/runtime evidence, bukan source-repository analysis.

## Native agent protocol adapters
- [x] Anthropic Messages adapter tersedia di `POST /v1/messages` untuk text, system, tool-use, tool-result, redaction, egress inspection, audit, dan buffered SSE replay.
- [x] Gemini GenerateContent adapter tersedia di `POST /v1beta/models/{model}:generateContent` untuk mapped content/system/generation fields, redaction, egress inspection, audit, dan buffered SSE replay.
- [x] Contract tests untuk converter dan endpoint native lulus; live binary-agent tests remain open and are not claimed as certification.

## MCP integration for Codex
- [x] MCP JSON-RPC server read-only tersedia melalui command `blue-ice mcp` pada STDIO dan endpoint authenticated `POST /mcp` pada listener loopback.
- [x] Tools MCP awal mencakup capabilities, model discovery, metadata-only audit, installed-skill listing/reading, project-path policy checks, dan deterministic security checks tanpa arbitrary shell execution.
- [x] MCP request-size limit, local bearer auth, project-root boundary, privacyignore checks, bounded skill/audit reads, dan sanitized errors diuji.
- [x] README dan agent compatibility guide mendokumentasikan pemisahan MCP tools dari `/v1/responses` model traffic Codex.
- [x] Contract tests MCP lulus; end-to-end verification dengan binary/version Codex tertentu masih terbuka dan tidak diklaim sebagai kompatibilitas tersertifikasi.
- [ ] A2A facade untuk delegasi antar-agent belum diaktifkan; A2A tetap menjadi extension point/reference dan bukan dependency runtime wajib.
