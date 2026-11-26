# Agency skills installed for Blue Ice

Source: [WebWakaHub/manus-agency-skills](https://github.com/WebWakaHub/manus-agency-skills)

Pinned source commit: `2a7d53cf7f3030a1fd1e3d3860d490bceb7eea0a`. The source README states the collection derives from `agency-agents` and is MIT-licensed; this shallow clone contains no standalone LICENSE file.

Eight skills used for this project are vendored under both `skills/` and `.agents/skills/` to match the repository's existing dual skill layout: AI Engineer, Backend Architect, Security Engineer, Technical Writer, API Tester, Reality Checker, Test Results Analyzer, and Agents Orchestrator.

Trailing whitespace was normalized in the vendored copies to keep the delivery patch clean; skill instructions and substantive wording were left unchanged.

REA (`reverse-engineer-anything`) was already present under both skill roots before this installation. Its own guidance says not to run REA readiness or provider commands for ordinary source-repository analysis; no reverse-engineering engine was installed or invoked.
