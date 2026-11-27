# A2A reference

Blue Ice menggunakan [repository resmi A2A](https://github.com/a2aproject/A2) sebagai reference protocol untuk kemungkinan delegasi antar-agent. Reference lokal yang dipelajari pada tahap ini dipin pada commit `a506d01`.

A2A dan MCP memiliki batas berbeda:

- MCP menghubungkan model/agent ke tools dan context server.
- A2A menghubungkan agent ke agent untuk delegasi, task lifecycle, streaming, dan hasil pekerjaan.
- Responses API tetap menjadi jalur model traffic Codex ke Blue Ice.

A2A belum menjadi dependency runtime wajib dan belum ada facade A2A yang aktif di gateway. Implementasi facade harus menunggu kebutuhan delegasi yang jelas serta memiliki authentication, authorization, bounded task state, audit metadata, egress checks, dan contract tests sendiri. Jangan mengklaim dukungan A2A penuh hanya karena repository reference tersedia.
