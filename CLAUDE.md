# Maintainer notes for Claude

Read `CHATGPT.md` for the shared contribution and security checklist, then
`docs/roadmap.md` and `docs/assessment.md`. These rules apply equally to work
performed here.

- Start from the current verified repository head and inspect the affected
  implementation. Recheck current official security guidance and advisories
  when changing dependencies, permissions, cryptography or build tooling.
- Inspect third-party source and scripts for malware and vulnerabilities
  before execution or reuse. Preserve licences and source attribution.
- Keep changes small enough to review. Test normal behaviour and failure
  paths, then double-check the final diff for bugs and security regressions.
- Keep secrets and user input out of logs. Treat local management endpoints,
  certificate stores and transferred files as trust boundaries.
- Write useful UK English comments with a restrained, dry programmer's voice.
  Track future ideas with the roadmap IDs; record the version and evidence
  when they become implemented behaviour.
- Keep assistant-specific material inside these two root maintainer files.
  Public change notes should contain the version and a brief factual change.
- Update both version files and `docs/changes.md` for each completed change
  set. Publish only real progress with accurate dates, authorship and checks.
- Preserve other work, verify the pushed head and report blockers directly.
  Neither a green build nor another fork's commit title proves security.
