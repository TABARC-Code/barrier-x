# barrier-x changes

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
