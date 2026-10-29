# barrier-x changes

## 2.4.7-snapshot — 29 October 2026

- Gave event queues ownership of their lazily allocated event-type providers.
- Serialised first access so concurrent callers receive the same provider.
- Added teardown coverage for all twenty providers and concurrent first access.

The 2.4.6 hosted lifecycle checks exposed 192 bytes leaked across eight provider
allocations on failure paths. The leak check remains enabled; this fixes the
ownership rather than suppressing the report.

Checks: 175 unit tests, four localhost transfer tests and all eight CTest
checks passed. The server command-line checks were retried after restoring a
local generated binary's executable permission. All forty targeted tests passed
ASan/UBSan locally; leak inspection remains restricted here and enabled in CI.
GUI and Windows/macOS execution remain unverified.

## 2.4.6-snapshot — 29 October 2026

- Checked TLS session allocation and transport attachment in both roles.
- Stopped failed setup jobs without entering a handshake or retrying allocation.
- Retained the transport BIOs across non-blocking handshake retries.
- Added six regressions covering failure, missing/closed state and retry preservation.

The previous code passed a null session onward after allocation failure and
replaced transport BIOs on every retry. Both were reproduced before the fix.
Concurrent shutdown, peer trust migration and platform validation remain open.

Checks: 173 unit tests, four localhost transfer tests and all eight CTest
entries passed. The 38 lifecycle/storage tests passed ASan/UBSan locally with
leak inspection disabled for the previously recorded environment restriction.
Hosted run 40859533634 passed Release and normal Debug checks, but its leak
check failed on inherited event-type provider ownership. Fixed in 2.4.7. GUI
and Windows/macOS execution remain unverified.

## 2.4.5-snapshot — 29 October 2026

- Replaced deprecated RSA generation with EVP and 3072-bit keys.
- Checked certificate fields, signatures and every output step.
- Wrote new identities through an exclusive temporary file before replacement.
- Created POSIX key files with mode 0600 and non-inheritable descriptors.
- Preserved existing identities on generation, write, flush, sync and replacement failure.
- Added twelve certificate-storage tests and extended sanitiser coverage.

Existing valid certificates are not automatically regenerated. Their permission
migration and Windows ACL hardening remain open; this update does not claim
owner-only Windows access. The parent profile directory must be trusted.

Checks: 167 unit tests, four localhost transfer tests and all eight CTest
entries passed. The network lifecycle and certificate-storage subsets passed
ASan/UBSan locally (32 targeted tests). Local leak inspection remains restricted;
hosted leak scanning stays enabled. GUI and Windows/macOS execution are unverified.

## 2.4.4-snapshot — 29 October 2026

- Kept POSIX poll storage owned when thread cancellation throws.
- Added a deterministic interrupted-poll regression to the sanitiser subset.

The previous raw allocation could be skipped by an exception before its manual
delete. This update covers that path without suppressing leak reports.

Checks: 155 unit tests, four localhost transfer tests and command-line checks
passed. The 20-test network lifecycle subset passed ASan/UBSan locally with
the previously documented local leak-inspection limitation. The 2.4.3 hosted
Debug/Release run passed, including leak scanning; this follow-up has its own run.

## 2.4.3-snapshot — 29 October 2026

- Required TLS 1.2 or newer; retained TLS 1.3 negotiation.
- Added real handshake tests for accepted and rejected versions in both roles.
- Fixed POSIX wake-up pipe ownership, descriptor cleanup and thread-reference races.
- Made wake-up writes non-blocking and descriptors close on exec.
- Added a target-thread ownership/closure test with 10,000 wake-ups.
- Fixed detached stdin handling and restoration of non-blocking stream flags.
- Added five stream tests and wired four localhost transfer checks into CTest/CI.

The first hosted sanitiser run exposed the inherited wake-up leaks. This update
addresses those findings; local leak scanning remains restricted. The TLS tests
first reproduced acceptance of TLS 1.0 and 1.1 against the previous implementation.
Peer authentication migration and the Windows dependency replacement remain open.

Checks: 154 unit tests, including real TLS-version handshakes, and four localhost
transfer tests. ASan/UBSan cover the network lifecycle subset; local leak scanning
remains restricted. Hosted leak checking stays enabled.

## 2.4.2-snapshot — 29 October 2026

- Fixed crashes during SSL cleanup before initialisation and context allocation failure.
- Kept socket ownership during setup and preserved listener exception types.
- Rejected SSL reinitialisation and invalid certificate-loading state.
- Fixed GCC 13 header dependencies and successful help/version exit codes.
- Added nine lifecycle tests, CTest checks and a pinned Linux build workflow.

Checks: client/server built on Ubuntu 24.04 with GCC 13; 144 unit tests and
six CTest entries passed. Lifecycle tests passed AddressSanitizer/UBSan with
leak detection disabled because local process inspection is restricted.
Hosted CI retains leak detection. GUI, other operating systems, real TLS peers
and concurrent session shutdown remain unverified.

## 2.4.1-snapshot — 29 October 2026

- Added source notes linked to a development backlog and completion criteria.
- Recorded build, input, sharing and interface improvements from the proposed plans.
- Corrected baseline assumptions and identified SSL lifecycle failures for follow-up.
- Kept both build version declarations in step. Runtime behaviour is unchanged.

Checks: source changes compared after removing comments; version declarations
matched; roadmap references and whitespace checked. CMake is unavailable in
the current environment, so no application build or runtime tests were run.
