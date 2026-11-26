# Audit perbedaan kode dan gap integrasi protokol

Tanggal kajian: 26 November 2026. Repo lokal berada pada commit dasar `644bb22e8f2411d230689c095a9eab3688121767`; perubahan yang dicatat di bawah belum di-commit atau di-push.

## Perubahan lokal yang sudah ada

Perubahan terdahulu menambahkan LLM Guard sebagai dependency opsional, adapter dengan fail-closed behavior, tes integrasi, README gap analysis, matriks keamanan, riset kompatibilitas 15 coding agents, panduan integrasi agent, serta salinan delapan skill agency dan REA. Semua file tambahannya terlihat sebagai untracked pada Git, sehingga belum menjadi bagian dari commit.

Perubahan kode lokal yang diaudit pada sesi ini mencakup tiga hal. Path guard memeriksa sampai dua tahap URL-decoding dan memblokir beberapa system root, `.git`, `.privacyignore`, serta nama file kredensial Git. Package guard mengubah exception tak terduga menjadi `verification_unavailable` agar tidak hilang, dan parsing `pip install` diperbaiki supaya kata `install` tidak dianggap nama package. Tes baru mencakup autentikasi endpoint, path sensitif, kegagalan registry, serta alur LLM Guard. Saat diperiksa, 63 tes lulus; Ruff lint dan format, compileall, serta `git diff --check` juga lulus.

Kode saat ini memiliki FastAPI gateway untuk OpenAI Chat Completions dan Responses native OpenAI/custom yang eksplisit. Pipeline Chat/Responses membuffer respons sebelum pemeriksaan dan replay SSE sesudahnya. Provider cloud yang aktif tunggal dipilih dari konfigurasi. Tidak ditemukan implementasi server MCP, endpoint Anthropic Messages, Gemini-native API, atau facade A2A. README lama yang menyebut dukungan agent tertentu menjelaskan pola konfigurasi, bukan uji kompatibilitas end-to-end.

## Perbedaan kontrak protokol yang memengaruhi desain

Codex gateway meminta endpoint Responses `/v1/responses`, mempertahankan item/tool-call semantics, serta SSE yang diteruskan inkremental sampai event terminal. Keberadaan route Responses saja tidak cukup untuk menyatakan Codex kompatibel; perlu uji terhadap client, model, auth, tool round-trip, continuation, dan error nyata [1] [2]. Ini berbeda dari Codex app-server, yang merupakan JSON-RPC terpisah.

Claude Code menggunakan Anthropic Messages, bukan Responses maupun Chat Completions. Gateway format Anthropic harus mempertahankan body dan header yang berkembang, query string, event SSE beserta urutannya, ping, dan error yang dapat muncul di tengah stream. Mengubah atau meredaksi body dapat memutus pasangan fitur beta/header dan field body. Karena itu adapter terjemahan ke OpenAI bukan reverse proxy transparan dan harus mengiklankan batas fitur secara ketat [3] [4] [5].

Gemini API dan Gemini CLI juga berbeda. Gemini API menyediakan beberapa kontrak: Interactions API dengan lifecycle stateful, legacy GenerateContent, serta Live melalui WebSocket. Gemini CLI memiliki mode ACP melalui JSON-RPC di stdio; bukti resmi yang ditemukan tidak menetapkan bahwa ACP mengarahkan trafik inferensi CLI ke base URL gateway [6] [7] [8]. Implementasi harus menyatakan permukaan mana yang didukung dan tidak boleh menyebut ACP sebagai adapter API Gemini.

MCP adalah protokol JSON-RPC client/server dengan transport tersendiri. Untuk server lokal, stdio mensyaratkan stdout hanya berisi frame protokol. Streamable HTTP memiliki aturan header/body, Origin, autentikasi, dan SSE per request. MCP Tasks, subscriptions, dan MRTR merupakan kemampuan/ekstensi yang perlu dinegosiasikan dan diuji, bukan fitur otomatis dari endpoint MCP [9] [10] [11]. Implementasi awal paling aman ialah satu transport lokal dan tool allowlist yang dibatasi project root; tool filesystem harus melakukan validasi filesystem sungguhan, bukan hanya memakai path detector teks.

Untuk implementasi Python, SDK resmi MCP saat kajian ini ada pada lini v2; dokumentasinya menunjukkan `MCPServer`, decorator `@mcp.tool()`, serta `run(transport="stdio")`. Stdout adalah jalur protokol dan bukan tempat menulis log. PyPI mencatat rilis `mcp` 2.3.0 pada 2 Oktober 2026 [14] [15] [16].

A2A v1.0.0 memiliki Agent Card, binding endpoint yang dideklarasikan, pesan Part, task state, error, serta SSE untuk streaming. Task ID harus diotorisasi per caller. Push notification dan URL file membuka risiko egress/SSRF. Versi v0.3 dan v1 tidak identik; facade awal harus memilih satu versi dan satu binding, lalu hanya mengiklankan kemampuan yang benar-benar diimplementasikan [12] [13].

SDK Python resmi A2A menyediakan factory route JSON-RPC dan Agent Card serta `DefaultRequestHandler` dan `AgentExecutor`. PyPI mencatat `a2a-sdk` 1.3.1 kompatibel dengan A2A 1.0. Implementasi awal repo ini memakai binding JSON-RPC v1, dengan input/output `text/plain` saja dan kemampuan streaming/push dinyatakan nonaktif [17] [18] [19].

## Urutan implementasi yang aman

Pertahankan satu lapisan security preflight bersama untuk auth lokal, validasi ukuran, pemeriksaan path, secret redaction, scanner opt-in, allowlist tujuan, inspeksi egress, dan audit metadata-only. Jangan mengubah semantik protokol menjadi bentuk teks generik. Pisahkan codec/adapter tiap protokol dan pertahankan ID, tool/result correlation, content blocks, status lifecycle, serta event terminal.

Untuk streaming, ada batas desain yang harus diputuskan: pemeriksaan egress saat ini membutuhkan buffering penuh, sedangkan Codex dan Claude Code mengharapkan relay SSE inkremental. Jangan menyebut replay setelah buffering sebagai incremental streaming. Tahap pertama dapat mempertahankan fail-closed buffering dan mendokumentasikan keterbatasannya; dukungan streaming sebenarnya memerlukan inspeksi per frame dengan stateful checks dan kebijakan yang mencegah frame berbahaya bocor sebelum keputusan dibuat.

Implementasi bertahap dalam repo dimulai dengan native pass-through Anthropic Messages dan Gemini GenerateContent yang terpisah, lalu MCP stdio read-only untuk project, kemudian A2A v1 JSON-RPC text-only sebagai facade opsional. Responses/Codex tetap harus melalui tes klien end-to-end tersendiri; Gemini CLI ACP tetap fitur terpisah dan belum diimplementasikan.

Tes kontrak sintetis kini tersedia untuk forwarding Anthropic/Gemini, MCP stdio, dan A2A JSON-RPC; tes tersebut menggunakan fake upstream/in-process transport dan tidak membuktikan kompatibilitas end-to-end dengan klien pihak ketiga. Semua adapter tetap berstatus **belum terverifikasi terhadap klien AI eksternal**.

## Validasi implementasi lokal (26 November 2026)

Setelah pemulihan `tests/test_a2a_facade.py` (tes Agent Card, auth `/a2a` dan `/a2a/`, delegasi `SendMessage`, pemisahan kredensial, serta iklan URL CLI IPv4/IPv6), hasil pengujian penuh adalah **80 passed**. Ruff lint, Ruff format check, `compileall`, dan `git diff --check` lulus. `blue-ice --help` dan `blue-ice mcp --help` berhasil. `npm ci` melaporkan 0 kerentanan pada empat paket yang diaudit, dan build TypeScript CLI berhasil. Demo offline juga lulus menggunakan respons provider sintetis tanpa panggilan AI atau jaringan eksternal.

Hasil ini membuktikan jalur uji lokal yang tercakup saja. Belum dilakukan pengujian terhadap akun/provider live, versi klien Codex/Claude Code/Gemini CLI aktual, interoperabilitas MCP dari agent nyata, deployment A2A jarak jauh, atau semantic/tool round-trip lintas agent. SSE native Anthropic/Gemini masih dibuffer penuh untuk inspeksi sebelum replay; fitur ini bukan streaming inkremental. Karena itu hasil tersebut tidak mendukung klaim kompatibilitas penuh atau keamanan menyeluruh.

## Referensi

[1]: https://developers.openai.com/codex/enterprise/gateway-compatibility "Codex Gateway compatibility requirements"
[2]: https://developers.openai.com/codex/enterprise/connect-to-a-gateway "Connect Codex to a gateway"
[3]: https://code.claude.com/docs/en/llm-gateway-protocol.md "Claude Code gateway compatibility protocol"
[4]: https://platform.claude.com/docs/en/api/messages/create "Anthropic Messages API"
[5]: https://docs.anthropic.com/en/api/messages-streaming "Anthropic Messages streaming"
[6]: https://aistudio.google.com/api-reference/interactions-api "Gemini Interactions API"
[7]: https://aistudio.google.com/api-reference/generate-content/generate-content "Gemini GenerateContent API"
[8]: https://github.com/google-gemini/gemini-cli/blob/main/docs/cli/acp-mode.md "Gemini CLI ACP mode"
[9]: https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/stdio "MCP stdio transport"
[10]: https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/streamable-http "MCP Streamable HTTP transport"
[11]: https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization "MCP authorization"
[12]: https://a2a-protocol.org/v1.0.0/specification/ "A2A Protocol Specification v1.0.0"
[13]: https://a2a-protocol.org/latest/topics/streaming-and-async/ "A2A streaming and asynchronous operations"
[14]: https://py.sdk.modelcontextprotocol.io/ "Official MCP Python SDK v2 documentation"
[15]: https://py.sdk.modelcontextprotocol.io/run/ "MCP SDK transports and stdio execution"
[16]: https://pypi.org/project/mcp/ "MCP Python SDK package release metadata"
[17]: https://a2a-protocol.org/latest/tutorials/python/4-agent-executor/ "A2A Python AgentExecutor interface"
[18]: https://a2a-protocol.org/latest/tutorials/python/5-start-server/ "A2A Python JSON-RPC route factory"
[19]: https://pypi.org/project/a2a-sdk/ "A2A Python SDK package release metadata"
