# Maintainer notes for ChatGPT

Work from the latest verified branch head. Read `docs/roadmap.md`,
`docs/assessment.md` and the relevant source before changing anything. Plans
describe intended behaviour; they are not evidence that a feature works.

## Changes and review

- Complete one coherent improvement at a time. Look for a simpler fix before
  replacing a subsystem. Preserve existing licence and copyright notices.
- Review imported source, dependencies, build scripts and install hooks for
  malicious behaviour and vulnerabilities before running or adopting them.
  Record the exact source revision and the applicable file licences.
- Check current official documentation, support policies and security
  advisories when choosing dependencies, cryptography or runner images.
  Recheck at implementation time; a version number in a plan is not a policy.
- Trace trust boundaries, permissions, allocation failures, integer overflow,
  bounds, cancellation, ownership and threading. Keep input and clipboard
  contents, credentials and private keys out of logs and diagnostics.
- Test the changed behaviour and its failure paths. Re-read the final diff
  for bugs and vulnerabilities after tests. Say which platforms and checks
  were actually exercised; distinguish unavailable checks from passes.
- Check reconnects, sleep, session changes, held modifiers and emergency
  return behaviour when changing input routing. Never weaken authentication
  to make a compatibility test pass.

## Notes and follow-through

- Use concise UK English. Explain the reason, constraint or useful future
  direction beside the relevant code. A little dry humour is enough.
- Use `FUTURE(BX-nnn)` for a roadmap item. Update its status, implementing
  version, evidence and remaining limitations when it lands. Remove obsolete
  future comments and retain explanations that still help maintainers.
- Keep implementation notes and public documentation about the software.
  Keep assistant-specific instructions and references in this file and
  `CLAUDE.md` only; do not add them to source, commits, branches or PR text.
- For each completed change set, update both version files and the fork
  changelog. Use a short commit subject: version plus concrete change.
- Publish verified progress regularly. Preserve real dates and authorship;
  do not manufacture commits or delay an urgent fix for a tidier activity graph.
- Fetch before publishing, preserve concurrent work, and verify the remote
  head afterwards. Record unfinished checks honestly and leave a clear next
  task. A roadmap checkbox needs evidence, not enthusiasm.

Use the connected maintainer identity. Do not invent names, email addresses,
sign-offs, test results or security assurances. Scheduled work follows the
same review rules as an interactive session.
