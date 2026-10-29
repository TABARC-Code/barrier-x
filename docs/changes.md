# barrier-x changes

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
