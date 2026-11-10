# barrier-x changes

## 2.4.30-snapshot - 10 November 2026

- I replace the removed Qt middle-button and date-format APIs.
- I keep Unicode key formatting compatible with Qt 6 integer overloads.
- I restore service socket-error reporting through typed signal connections.

## 2.4.29-snapshot - 10 November 2026

- I stop forcing a macOS sysroot into the compiler flags.
- I enable OpenGL support in the Windows Qt SDK.
- I record the Qt configure options beside its pinned source inputs.

## 2.4.28-snapshot - 10 November 2026

- I check POSIX peer-trust ancestors from the filesystem root.
- I create missing trust folders privately through checked directory handles.
- I bound intermediate link resolution and reject unsafe owners or write access.
- I stabilise Qt patch extraction and disable disposable-checkout maintenance.

## 2.4.27-snapshot - 10 November 2026

- I serialise competing SSL closes and synchronise shutdown/readiness flags.
- I keep log timestamps in per-call storage during concurrent logging.
- I preserve the default screen identifier in translated interfaces.
- I extract Qt security patches against their fetched parents.

## 2.4.26-snapshot - 10 November 2026

- I add explicit Qt 5/6 selection and replace obsolete regular-expression APIs.
- I update screen-editor rendering for Qt 6 and retain Qt 5 comparison builds.
- I honour the selected OpenSSL SDK on Intel and Apple Silicon macOS.
- I add native Windows GUI and macOS validation jobs.
- I retain modifier overrides when dragging screens and reject malformed drag data.
- I reject configuration syntax in dragged names and prevent copies overwriting tiles.
- I remove typed key values and dynamic mapping details from input diagnostics.

## 2.4.25-snapshot - 9 November 2026

- I anchor POSIX peer-trust reads and replacement files to an open folder handle.
- I refuse linked or foreign-owned trust folders, and folders writable by other users.
- I retry interrupted writes, complete short writes and check flushing before publication.
- I keep failed-save cleanup in the original folder if its path moves.

## 2.4.24-snapshot - 9 November 2026

- I create Windows peer-trust replacements with protected owner/System permissions.
- I check writes and flushing, then publish through the retained file handle.
- I refuse replacements which would take ownership of another user's file.

## 2.4.23-snapshot - 9 November 2026

- I check peer approvals are saved before reconnecting.
- I merge existing approvals under a lock and replace the file atomically.
- I refuse malformed, oversized or unsafe trust files without discarding them.
- I show trust-store failures on every dashboard page and allow a fresh attempt.

## 2.4.22-snapshot - 8 November 2026

- I organise the dashboard into Connection, Screen layout and Settings.
- I keep status and connection actions visible on every page.
- I add scrollable pages and a persistent identity-recovery shortcut.
- I retain the selected page, window size and existing connection settings.

## 2.4.21-snapshot - 8 November 2026

- I show identity setup failures in the control panel with a Retry action.
- I clear stale fingerprints and rebuild missing public fingerprints on request.
- I check public fingerprint writes and publish them through a temporary file.
- I preserve unsupported existing identities and reject fingerprint-file symlinks.

## 2.4.20-snapshot - 8 November 2026

- I replace peer approval's Yes/No buttons with explicit Trust and Reject actions.
- I make rejection the default and add full public SHA-256 copying.
- I refuse approval when the SHA-256 fingerprint is missing or malformed.

## 2.4.19-snapshot - 7 November 2026

- I put connection status and Start/Stop above the configuration controls.
- I clarify server/client roles, address entry and discovery guidance.
- I add plain address and full public SHA-256 copy controls.
- I keep Stop available during connection attempts and preserve status on language changes.
- I retain the running role for status and fingerprint approval while editing configuration.
- I improve keyboard access and let the control panel resize.

## 2.4.18-snapshot - 7 November 2026

- I remove the GUI's HTTP Bonjour download and installer execution path.
- I make DNS-SD discovery optional and keep manual connection controls usable.
- I preserve the saved discovery preference while its backend is unavailable.
- I ignore late discovery results in manual mode and close service-query handles.
- I reconcile the reader when discovery availability changes and remove idle listener threads.

## 2.4.17-snapshot - 6 November 2026

- I raise the CMake baseline to 3.20 for current build tools.
- I select external OpenSSL 3.5 LTS libraries for Windows builds.
- I retire Windows helpers that copied old DLLs or downloaded unchecked SDKs.
- I refuse obsolete installer generation and support imported Google Test targets.
- I add a working plan, dependency notes and concrete external review requests.

## 2.4.16-snapshot - 6 November 2026

- I add Windows identity checks through a temporary LocalSystem service.
- I cover console-user ownership, foreign keys and failed permission or token checks.

## 2.4.15-snapshot - 3 November 2026

- I create Windows identity files with protected owner and LocalSystem permissions.
- I restrict existing identity permissions through the handle used for reading.
- I reject foreign owners, reparse points, hardlinks, alternate streams and oversized files.
- I prevent concurrent writes and renames while reading the checked identity.

## 2.4.14-snapshot - 2 November 2026

- I restrict existing POSIX identity files to mode 0600 through their open descriptor.
- I reject foreign ownership, linked/non-regular files and identities larger than 1 MiB.
- I load a matching certificate/key pair from one checked snapshot.
- I clear handled identity-load errors before later TLS operations.
- I preserve unreadable or malformed GUI identities and fingerprint the validated certificate.

Windows ACL migration remains unfinished.

## 2.4.13-snapshot - 2 November 2026

- I replace Windows service TCP management with a local named pipe and checked caller tokens.
- I require the active console logon for logs and administrator approval for command changes.
- I bind engine access to the retained child process and verify the service identity in both clients.
- I recheck queued command permissions and require approval again for legacy saved commands.
- I cancel pending pipe I/O during shutdown and bound its input, output and connection counts.
- I report administrator requirements in the interface and remove whole command strings from service diagnostics.

## 2.4.12-snapshot - 2 November 2026

- I require one greeting before dispatching management commands.
- I reject commands from engine connections and close repeated or changed greetings.
- I publish connection flags atomically and skip output once disconnection is observed.

Caller credentials are still unchecked; a claimed GUI role remains forgeable.

## 2.4.11-snapshot - 2 November 2026

- I reject secure reads and writes without a ready, approved session.
- I return zero transferred bytes on rejected, retrying or failed operations.
- I reject invalid buffers and lengths before calling OpenSSL.
- I clear stale thread errors before application I/O so retry decisions use the current result.

## 2.4.10-snapshot - 1 November 2026

Sec update

Fragmented messages no longer block the GUI.
Oversized and malformed messages are rejected.
Reconnects reset partial data and restore log reading.
Protocol errors reach the GUI’s error display.

## 2.4.9-snapshot - 1 November 2026

- Kept client sockets unready until SHA-256 pin verification succeeds.
- Marked rejected peer connections fatal and cleared their readiness.
- Released peer-certificate references on successful and failed fingerprint checks.
- Corrected the accepting-side certificate error to identify the client.
- Added five peer-trust and certificate-ownership regressions.

Checks: 193 unit tests and seven localhost tests passed, along with 58 targeted
ASan/UBSan tests. A later normal retry lost its generated executable and produced
no test output; that retry is not counted. Hosted Debug/Release and leak checks passed in run 41348051339.
Local leak inspection and platform/GUI checks remain outstanding.

Trust defaults, local command authorisation and concurrent shutdown remain open.
These tests control TLS completion and certificate retrieval while exercising
real certificate digests and trust files; they are not two-machine TLS tests.

## 2.4.8-snapshot — 29 October 2026

- Buffered partial engine IPC frames without dispatching incomplete messages.
- Limited commands to 64 KiB; retained the 1 MiB log-message limit.
- Rejected malformed headers, roles, elevation flags and embedded command NULs.
- Stopped reading after a protocol error without emitting a null message.
- Supplied the missing elevation argument when encoding commands.
- Added thirteen regressions and registered three localhost IPC round trips.

Caller authentication remains unfinished. This changes the C++ engine readers;
the separate Qt GUI reader is not covered. Limits apply per frame, not to total
connections, event backlog or queued log output. No handshake identity is proof
of a local user.

Checks: 188 unit tests, four transfer tests, three localhost IPC round trips
and all ten CTest entries passed. All 53 targeted lifecycle/storage/IPC tests
passed ASan/UBSan locally. Local leak inspection remains restricted; hosted
leak checks stay enabled. Windows/macOS and interactive GUI checks remain open.

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
