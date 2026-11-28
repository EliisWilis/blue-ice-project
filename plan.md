# Blue Ice Project — fitur agent API dan debugging

## Tujuan
Memusatkan kontrak AI API yang dipakai seluruh coding agent melalui satu gateway OpenAI-compatible, tanpa menambahkan provider tersembunyi, fallback diam-diam, atau melemahkan LLM Guard.

## Implementasi
- Pertahankan tiga kontrak publik yang sudah berjalan: `GET /v1/models`, `POST /v1/chat/completions`, dan `POST /v1/responses`.
- Tambahkan `GET /v1/blue-ice/capabilities` sebagai discovery endpoint authenticated yang hanya mengembalikan metadata non-rahasia tentang provider terpilih, model, protokol, streaming buffering, tool-call pass-through, dan status guard.
- Tambahkan test kontrak endpoint dan test bahwa authentication tetap berlaku.
- Perbaiki error static typing pada egress firewall dan custom provider routing.
- Import seluruh skill dari `manus-agency-skills` ke `skills/agency-*` tanpa metadata `.git`; pertahankan `skills/reverse-engineer-anything` sebagai skill REA proyek.

## Batasan keamanan
API key upstream tetap hanya di proses gateway/keyring. Endpoint capability tidak mengembalikan credential, prompt, response, filesystem path, atau audit content. LLM Guard tetap opt-in dan fail-closed ketika aktif.

## Struktur
- `src/aegis/app.py`: route dan pipeline security.
- `src/aegis/routing/privacy_router.py`: allowlisted provider transport.
- `src/aegis/egress/egress_firewall.py`: output policy checks.
- `tests/`: regression dan contract tests.
- `skills/`: skill proyek, REA, dan skill agency yang diimpor.
- `docs/agent-integrations.md`: protocol caveats dan konfigurasi agent.
