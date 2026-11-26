# Kompatibilitas API Blue Ice dengan klien agent

Penilaian ini membandingkan 15 klien dengan API Blue Ice: tersedia `POST /v1/chat/completions` dan `GET /v1/models`; jalur Responses hanya tersedia untuk OpenAI native atau endpoint Responses yang didaftarkan eksplisit; hanya satu upstream aktif. Pemeriksaan kode proyek menegaskan kedua mode stream dibuffer: Chat Completions diteruskan ke upstream dengan `stream: false` lalu dibuat ulang sebagai satu chunk SSE, sedangkan Responses SSE dibaca penuh sebelum replay. Jadi Blue Ice tidak mengirim token secara incremental.

Secara praktis, **Hermes, OpenCode, OpenClaw, Kilo Code, Cline, Roo Code, Continue, Aider, Goose, dan Qwen Code** memiliki jalur konfigurasi Chat Completions yang didokumentasikan atau bersyarat. Namun, mereka tidak mendapat streaming token incremental dari Blue Ice saat ini; perlu uji apakah mode tanpa stream atau SSE yang baru selesai masih dapat dipakai. Auth, route, model, dan tools juga belum diuji end-to-end. **Codex CLI/Desktop dan Codex Security CLI** memerlukan Responses API dengan streaming incremental; Blue Ice tidak cocok langsung. **Claude Code** memerlukan Anthropic Messages, sedangkan **Gemini CLI** memakai Gemini-native API. Untuk **Cursor**, dokumentasi tidak cukup untuk memastikan route, auth, atau akses ke endpoint lokal.

Tidak ada hasil yang menyatakan uji end-to-end Blue Ice dengan klien mana pun telah dilakukan. “Dokumented conditional” berarti mekanisme atau jalur klien didukung dokumentasi dan secara konseptual dapat dipasangkan dengan Blue Ice, bukan jaminan integrasi berjalan. Tidak ada jaminan kompatibilitas 100%. Endpoint, konfigurasi UI, auth, kemampuan model, serta perilaku klien dapat berubah menurut versi; lakukan validasi pada versi dan deployment yang benar-benar digunakan.

## Matriks 15 klien

## Status per klien

- **Codex CLI & Codex di aplikasi desktop ChatGPT** — ``not_directly_compatible``. **Jalur:** Responses: `POST /v1/responses`, `wire_api = "responses"`. Base URL lokal dan bearer credential dapat dikonfigurasi, tetapi `/v1/chat/completions` saja tidak memenuhi protokol yang dibutuhkan. SSE Responses harus incremental; buffering Blue Ice tidak sesuai persyaratan tersebut. Belum diuji E2E. [1], [2], [3].
- **Codex Security CLI** — ``not_directly_compatible``. **Jalur:** Responses: `POST /v1/responses`. Memerlukan custom provider Responses; base URL tidak mengubah protokol Chat Completions. Bearer dapat diatur melalui konfigurasi credential, tetapi streaming/tool calling dan scan penuh Blue Ice belum dibuktikan. Belum diuji E2E. [4], [5].
- **Hermes Agent** — ``documented_conditional``. **Jalur:** OpenAI Chat Completions: `POST /v1/chat/completions`. Dokumentasi mendukung custom OpenAI-compatible endpoint, transport `chat_completions`, model dan key/header. Blue Ice membuffer Chat SSE dan mengirim ulang satu chunk selesai, bukan incremental; uji apakah Hermes menerima perilaku ini atau dapat memakai mode tanpa stream, dan verifikasi tool calls. Belum diuji E2E. [6], [7].
- **OpenCode** — ``documented_conditional``. **Jalur:** OpenAI-compatible Chat Completions. Custom provider OpenAI-compatible sesuai secara konseptual; definisikan model, arahkan `baseURL`, dan atur credential/header. Blue Ice tidak memberi SSE incremental; penerimaan chunk selesai tertunda, auth on-wire, tools, dan pola paralel belum dibuktikan. Belum diuji E2E. [8], [9], [10].
- **OpenClaw** — ``documented_conditional``. **Jalur:** `api=openai-completions`, `POST /v1/chat/completions`. Custom provider dan bearer/custom auth didokumentasikan. `GET /v1/models` dapat dipakai untuk discovery, tetapi Blue Ice hanya mengirim chunk SSE setelah respons lengkap; pastikan perilaku itu dapat diterima dan uji round trip tools. Belum diuji E2E. [11], [12], [13].
- **Claude Code** — ``not_directly_compatible``. **Jalur:** Anthropic Messages: `POST /v1/messages`. Blue Ice Chat Completions/Responses tidak menyediakan format Anthropic Messages. Perlu adapter yang menerjemahkan pesan, streaming SSE incremental, tools dan hasil tool. Buffer penuh Responses tidak memenuhi ekspektasi streaming Messages. Belum diuji E2E. [14], [15], [16].
- **Gemini CLI** — ``not_directly_compatible``. **Jalur:** Gemini-native `:generateContent` / `:streamGenerateContent`. Gemini CLI menggunakan API dan bentuk tools Gemini-native, bukan OpenAI Chat Completions/Responses. Perlu adapter Gemini-native; custom base URL dan header Bearer saja tidak menerjemahkan protokol. Belum diuji E2E. [17], [18], [19].
- **Kilo Code** — ``documented_conditional``. **Jalur:** OpenAI-compatible Chat Completions. Pilih OpenAI Compatible, base URL Blue Ice dan model yang benar; dokumentasi mendukung custom header untuk token. Blue Ice menunda SSE hingga respons lengkap dan tidak memberi delta incremental; penerimaan ini dan dukungan tool calls perlu diuji. Belum diuji E2E. [20], [21], [22].
- **Cline** — ``documented_conditional``. **Jalur:** OpenAI Compatible / Chat Completions. Base URL lokal dan provider OpenAI Compatible didokumentasikan. Pemetaan API Key ke header bearer dan route outbound persis tidak tegas; custom headers disebut dalam konteks remote/enterprise. Blue Ice hanya mengirim SSE setelah hasil lengkap, sehingga pengalaman streaming incremental tidak didukung; tools dan E2E belum diuji. [23], [24], [25].
- **Roo Code** — ``documented_conditional``. **Jalur:** OpenAI Compatible / Chat Completions. Provider OpenAI-compatible, model dan custom headers tersedia. Blue Ice tidak mengirim streaming incremental; penerimaan chunk lengkap, route aktual, bearer header, tool calls dan batas satu upstream terhadap paralelisme perlu diuji. Belum diuji E2E. [26], [27].
- **Continue** — ``conditional``. **Jalur:** Provider `openai`, Chat Completions; paksa `useResponsesApi: false` bila perlu. `apiBase` dan bearer `apiKey` didokumentasikan. Model/config tertentu dapat memilih Responses secara default. Kedua rute stream Blue Ice tidak incremental; penerimaan stream tertunda, GET `/v1/models`, dan tools perlu diuji. [28], [29], [30].
- **Cursor** — ``conditional``. **Jalur:** Custom OpenAI-compatible base URL; route spesifik tidak dipastikan. Dokumentasi yang ditinjau tidak mengunci path outbound, discovery, format bearer, atau kesesuaian loopback lokal. Request Cursor melewati backend Cursor untuk final prompt building sebagaimana dirangkum pada temuan; karena itu jangan menganggap `127.0.0.1` Blue Ice otomatis dapat dijangkau. Perlu verifikasi langsung pada fitur/build yang digunakan. Belum diuji E2E. [31], [32], [33].
- **Aider** — ``documented_conditional``. **Jalur:** OpenAI-compatible endpoint melalui LiteLLM. Base endpoint dan model OpenAI-compatible didukung; literal route tidak dinyatakan pada dokumentasi yang diperiksa. Token dapat dimasukkan sebagai API key, tetapi header auth arbitrer tidak terverifikasi. Aider memiliki `--no-stream`; bila streaming dipakai, Blue Ice hanya menghasilkan satu chunk setelah respons selesai. Workflow edit standar tidak bergantung pada native tool calling Blue Ice. Belum diuji E2E. [34], [35], [36].
- **Goose** — ``documented_conditional``. **Jalur:** OpenAI-compatible `v1/chat/completions`. Custom provider dapat memakai format OpenAI-compatible dan endpoint lengkap; custom header bearer tersedia pada konfigurasi CLI/file, bukan langsung dari Desktop. Discovery tidak dipastikan; Blue Ice membuffer SSE Chat, jadi dukungan streaming incremental tidak ada, sedangkan penerimaan chunk selesai dan tools perlu diuji. Belum diuji E2E. [37], [38], [39].
- **Qwen Code** — ``documented_conditional``. **Jalur:** OpenAI-compatible Chat Completions, `wireApi: chat-completions`. Custom OpenAI provider, `baseUrl`, `envKey`, model ID dan Chat Completions didokumentasikan. Jangan memilih `responses` kecuali route Responses yang tepat terdaftar. Blue Ice tidak mengirim SSE incremental; penerimaan stream tertunda, tools dan auth aktual perlu diuji. Belum diuji E2E. [40], [41], [42].


### Makna status

- **`not_directly_compatible`**: protokol yang didokumentasikan klien berbeda dari endpoint Blue Ice yang tersedia; koneksi langsung tidak didukung oleh temuan ini tanpa implementasi route/adapter yang sesuai.
- **`documented_conditional` / `conditional`**: dokumentasi klien menyediakan jalur yang secara protokol dapat dipasangkan dengan endpoint Chat Completions Blue Ice, dengan syarat konfigurasi dan kemampuan server/model cocok. Itu bukan hasil uji integrasi.
- **E2E**: tidak ada uji end-to-end Blue Ice dengan klien-klien ini yang dilaporkan. Penilaian adalah pencocokan dokumentasi resmi masing-masing vendor terhadap fakta implementasi Blue Ice yang diberikan. Beberapa dokumentasi vendor menyebut contoh koneksi/provider lain; contoh itu bukan bukti integrasi Blue Ice.

## Syarat umum integrasi dan kesenjangan

### Syarat yang perlu dipenuhi

1. **Pilih protokol yang memang dilayani.** Jalur yang paling langsung bagi mayoritas klien dalam daftar adalah OpenAI-compatible Chat Completions pada `/v1/chat/completions`. Menyetel base URL tidak mengubah format wire protocol. Untuk klien Responses, Anthropic Messages atau Gemini-native, diperlukan route atau adapter protokol yang sesuai.
2. **Pastikan alamat jaringan benar.** `127.0.0.1` hanya menunjuk ke host/network namespace tempat proses klien berjalan. Klien dan Blue Ice perlu berada di lingkungan yang dapat saling menjangkau; jangan menyamakan localhost klien dengan host lain atau backend jarak jauh.
3. **Konfigurasikan bearer token dengan aman dan eksplisit.** Sejumlah klien mendukung env key/API key atau custom header, tetapi pemetaan persisnya berbeda. Gunakan mekanisme yang terbukti menghasilkan header yang diharapkan; hindari secret statis di konfigurasi bila env substitution tersedia.
4. **Tetapkan model secara eksplisit bila perlu.** Beberapa klien memerlukan ID model terdaftar atau metadata model khusus. Keberadaan `GET /v1/models` yang hanya berisi ID tidak otomatis memenuhi katalog metadata tertentu maupun membuktikan bahwa klien akan memanggilnya.
5. **Streaming incremental masih merupakan gap pada kedua rute.** Kode Blue Ice memaksa upstream Chat Completions berjalan dengan `stream: false`, lalu mengirim satu chunk SSE setelah pemeriksaan. Responses SSE juga dibaca penuh sebelum replay. Karena itu tidak satu pun rute saat ini memberikan token incremental; uji mode non-stream klien atau implementasikan forwarding incremental yang tetap aman sebelum mengklaim dukungan.
6. **Uji tool/function calling dan putaran lanjutannya.** Kompatibilitas membutuhkan kecocokan schema, format panggilan, ID, hasil tool dan pesan lanjutan untuk protokol yang digunakan. Dukungan tools di UI atau model tidak membuktikan endpoint Blue Ice mendukung round trip tersebut.
7. **Uji pola konkurensi.** Satu upstream aktif adalah batas operasional Blue Ice yang diberikan. Belum ada bukti bahwa klien tertentu selalu serial atau bahwa semua pola agent, paralelisme, dan panggilan tool berurutan berjalan baik dengan batas itu.

### Kesenjangan bukti yang tersisa

- Tidak ada tes nyata yang mengirim request dari salah satu dari 15 klien ke Blue Ice; autentikasi, route final, loopback, status code/error, maupun respons belum terverifikasi end-to-end.
- Kedua rute SSE dibuffer sampai respons lengkap: Chat Completions diubah menjadi satu chunk SSE, sedangkan Responses SSE diparse/diinspeksi penuh sebelum replay. Belum diketahui klien mana yang dapat memakai mode non-stream atau menerima perilaku tertunda tersebut.
- Dukungan tool calling Blue Ice pada Chat Completions—termasuk schema masuk, tool-call response, ID, hasil tool dan kelanjutan—tidak ditetapkan.
- Discovery `GET /v1/models`, format katalog model, dan kebutuhan discovery berbeda antar klien; tidak boleh diasumsikan semua klien memanggil route itu atau menerima daftar ID sederhana.
- Format header auth API-key/bearer dan dukungan custom headers berbeda menurut klien, versi, dan jenis konfigurasi. Beberapa klien tidak menjamin pemetaan bearer secara eksplisit.
- Route, UI, pilihan model, default protokol, dan perilaku provider dapat berubah mengikuti versi klien maupun model. Bukti dokumentasi bukan pengganti pengujian terhadap build aktual.

## Prioritas pengembangan API Blue Ice

Urutan berikut memprioritaskan cakupan kompatibilitas klien berdasarkan temuan ini, bukan estimasi upaya implementasi.

1. **Jadikan OpenAI Chat Completions benar-benar kokoh dan terdokumentasi.** Ini adalah jalur bersama yang dapat digunakan secara kondisional oleh banyak klien dalam daftar. Definisikan payload request/response, model ID, error, bearer auth, serta URL base yang direkomendasikan dengan jelas. Validasi `GET /v1/models` dan dokumentasikan apakah discovery didukung serta format hasilnya.
2. **Sediakan streaming SSE incremental untuk Chat Completions.** Ini menutup kesenjangan utama pada jalur yang paling luas. Uji event/delta, akhir stream, error dan penggunaan tool-call chunks, jangan hanya mengandalkan hasil akhir yang dibuffer.
3. **Lengkapi dan uji tool/function calling OpenAI end-to-end.** Pertahankan struktur tool, argumen, ID, balasan tool, dan putaran lanjutan. Pastikan model upstream yang dipilih benar-benar mendukungnya.
4. **Selesaikan perilaku auth dan konfigurasi model yang interoperabel.** Dokumentasikan bearer token dan header, dukungan environment secret, model alias/katalog, serta perilaku discovery. Ini mengurangi ketidakpastian integrasi lintas klien tanpa mengubah protokol.
5. **Tambahkan jalur Responses API yang kompatibel bila dukungan Codex menjadi sasaran.** Endpoint harus memenuhi kontrak Responses, termasuk SSE inkremental, event akhir/error/failure dan siklus tools. Daftarkan secara eksplisit dan dokumentasikan model/routing; sekadar menyediakan base URL atau Chat Completions tidak cukup.
6. **Pertimbangkan adapter Anthropic Messages dan Gemini-native hanya bila cakupan klien tersebut dibutuhkan.** Adapter perlu menerjemahkan payload, respons, streaming dan tools secara penuh; token/header atau base URL khusus saja tidak memberi kompatibilitas protokol.
7. **Uji deployment lokal dan batas konkurensi sebagai bagian matriks kompatibilitas.** Verifikasi loopback dalam host/container nyata dan perilaku satu-upstream untuk request simultan, agent multi-langkah, serta tool calls.

### Usulan validasi rilis

Untuk setiap klien/profil yang ingin dinyatakan kompatibel, jalankan tes pada versi klien dan model yang dicatat: (a) auth dan request minimum ke route tepat, (b) model ID dan discovery, (c) SSE yang diamati per chunk, (d) tool call beserta hasil/lanjutan bila dipakai, (e) error dan akhir respons, (f) network namespace loopback, dan (g) pola request serial/paralel. Catat konfigurasi serta versi dan perbarui matriks ketika route/UI/default vendor berubah. Hingga validasi ini dilakukan, status yang tepat adalah dukungan dokumentasi bersyarat atau ketidakcocokan langsung seperti diringkas di atas—bukan jaminan 100%.

## Sumber dan cakupan

Sumber di setiap uraian klien merujuk dokumentasi vendor yang relevan. Kesimpulan dibatasi oleh versi dokumen dan tanggal acuan 2026-11-25; Qwen Code mencatat dokumentasinya terakhir diperbarui 2026-11-13. Dokumen dan implementasi klien dapat berubah.

## References

[1]: https://developers.openai.com/codex/models "Codex models"
[2]: https://developers.openai.com/codex/enterprise/gateway-compatibility "gateway compatibility"
[3]: https://developers.openai.com/codex/config-file/config-advanced "advanced config"
[4]: https://developers.openai.com/codex/security/cli "Codex Security CLI"
[5]: https://developers.openai.com/codex/security/cli/reference "reference"
[6]: https://hermes-agent.nousresearch.com/docs/integrations/providers "Providers"
[7]: https://hermes-agent.nousresearch.com/docs/user-guide/configuration "configuration"
[8]: https://opencode.ai/docs/providers/ "Providers"
[9]: https://opencode.ai/docs/models/ "models"
[10]: https://opencode.ai/docs/config/ "configuration"
[11]: https://docs.openclaw.ai/gateway/config-tools/custom-providers "Custom providers"
[12]: https://docs.openclaw.ai/gateway/local-models "local models"
[13]: https://docs.openclaw.ai/concepts/streaming "streaming"
[14]: https://code.claude.com/docs/en/llm-gateway-protocol.md "Gateway protocol"
[15]: https://code.claude.com/docs/en/llm-gateway-connect.md "gateway connection"
[16]: https://platform.claude.com/docs/en/api/messages/create "Messages API"
[17]: https://github.com/google-gemini/gemini-cli/blob/main/docs/reference/configuration.md "Gemini CLI configuration"
[18]: https://ai.google.dev/api/generate-content/generate-content "GenerateContent"
[19]: https://ai.google.dev/api/generate-content/stream-generate-content "streamGenerateContent"
[20]: https://kilo.ai/docs/ai-providers/openai-compatible "OpenAI-compatible provider"
[21]: https://kilo.ai/docs/code-with-ai/agents/custom-models "custom models"
[22]: https://kilo.ai/docs/desktop/settings/ai "desktop AI settings"
[23]: https://docs.cline.bot/provider-config/openai-compatible "OpenAI-compatible provider"
[24]: https://docs.cline.bot/api/chat-completions "API Chat Completions"
[25]: https://docs.cline.bot/enterprise-solutions/configuration/remote-configuration/openai-compatible/admin-configuration "remote admin configuration"
[26]: https://docs.roocode.com/providers/openai-compatible "OpenAI-compatible provider"
[27]: https://roocodeinc.github.io/Roo-Code/features/api-configuration-profiles/ "API configuration profiles"
[28]: https://docs.continue.dev/customize/model-providers/top-level/openai "OpenAI provider"
[29]: https://docs.continue.dev/customize/deep-dives/model-capabilities "model capabilities"
[30]: https://docs.continue.dev/guides/how-to-self-host-a-model "self-host a model"
[31]: https://cursor.com/docs/settings/api-keys "API keys"
[32]: https://cursor.com/docs/models-and-pricing "models and pricing"
[33]: https://cursor.com/docs/enterprise/network-configuration "network configuration"
[34]: https://aider.chat/docs/llms/openai-compat.html "OpenAI-compatible"
[35]: https://aider.chat/docs/config/api-keys.html "API keys"
[36]: https://aider.chat/docs/config/options.html "options"
[37]: https://goose-docs.ai/docs/getting-started/providers/ "Providers"
[38]: https://goose-docs.ai/docs/guides/config-files/ "config files"
[39]: https://goose-docs.ai/docs/guides/environment-variables/ "environment variables"
[40]: https://qwenlm.github.io/qwen-code-docs/en/users/configuration/model-providers/ "Model providers"
[41]: https://qwenlm.github.io/qwen-code-docs/en/users/configuration/auth/ "auth"
[42]: https://qwenlm.github.io/qwen-code-docs/en/users/configuration/settings/ "settings"
