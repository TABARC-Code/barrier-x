# Working plan

6 November 2026. I start from the verified 2.4.16 snapshot. The detailed backlog
and landed versions live in [roadmap.md](roadmap.md); build evidence stays in
[build.md](build.md). This is the order I'd work through, rather than another
list of things I'd quite like to finish eventually.

| Order | Work | State and finish point |
| --- | --- | --- |
| 1 | Windows TLS and engine build, BX-005 | In progress for 2.4.17. Replace bundled OpenSSL selection, build both engines and run their tests on Windows. Refuse the installer while it still selects old DLLs. |
| 2 | Qt and discovery libraries, BX-005 | Planned. Check supported Qt versions, source licences and advisories. Replace the Bonjour SDK assumption, then build and exercise the GUI with the same TLS libraries. Manual connection must remain usable. |
| 3 | Windows packaging, BX-005/BX-024 | Planned. Collect the actual runtime DLLs and notices, check libssl/libcrypto versions, provider modules and search paths, then test installation, upgrade and removal on a clean machine. No borrowed DLL pile. |
| 4 | SSL shutdown, BX-001 | Open. Reproduce a read or write interrupted by close, then cover reconnect and repeated shutdown under concurrency checks. Keep ownership and cancellation explicit. |
| 5 | Trust and key recovery, BX-002/BX-004/BX-007 | Partial. Preserve existing keys and pins during permission repair. Explain a missing console identity separately from foreign ownership. Replacement needs an explicit action and a warning about changed pins. |
| 6 | Protocol and sharing limits, BX-006/BX-010/BX-011 | Planned. Bound total queued bytes and simultaneous transfers, then add clipboard/file direction controls, acceptance, cancellation and honest progress. Check malformed lengths and unsafe destinations before adding formats. |
| 7 | Input recovery, BX-007/BX-009/BX-019 | Planned. Release held keys on loss of connection. Show focus, pause and local-return controls; test sleep, lock and console switching. A process being alive doesn't tell me where my keyboard went. |
| 8 | Monitor layout and Wayland, BX-008/BX-014 | Later. Add crossing previews and keyboard access to the existing layout editor. Design portal/libei capabilities from measured compositor behaviour before promising support. |

## Libraries and checks

I pin Windows OpenSSL to the supported 3.5 LTS line, with 3.5.9 as the current
minimum. The build script checks the official archive's SHA-256 before extraction.
Google Test 1.15.2 is pinned by commit for the C++14 test build. It isn't an
application runtime dependency. Exact revisions and reviewed files go in the
[dependency notes](dependencies.md). Updates need a fresh advisory check, not just a changed number.

The next audit covers DLL loading and provider/configuration paths, service
identity across session changes, certificate storage and peer approval. After
that I'll follow clipboard and transfer buffers through allocation, queueing,
parsing and cancellation. Anything unexamined stays open. A short scan won't
be labelled a complete security audit.

## External review wanted

I'd like another Windows maintainer to check the service token rules and the
installer's DLL/CRT selection on a clean desktop, including UAC, logout and user
switching. The source checks and hosted runner don't cover that whole path.

Before distributing new dependency bundles, I also want the OpenSSL linking
exception and the selected Qt/discovery licences checked together. I retain the
licence texts and source references; this note doesn't settle every downstream
licensing question. Release signing and provenance remain BX-024.

## Things worth borrowing

I checked Deskflow at `b29f16f937b3a375085ce202ef484a1d7c776fa8` and Input Leap
at `34a34fb20b93113a6b26052cb5a54f9be2327775`. These are proposals. I haven't
imported their source or run their scripts.

- Input Leap's [Qt-major selection](https://github.com/input-leap/input-leap/blob/34a34fb20b93113a6b26052cb5a54f9be2327775/src/gui/CMakeLists.txt) is a useful migration pattern. I'd stage Qt 6 separately, check the supported SDK and licences, then exercise reader reconnects, identity creation, translations and layout. Its Qt 6 build uses C++17; that change needs its own build evidence.
- Deskflow's [runtime collection](https://github.com/deskflow/deskflow/blob/b29f16f937b3a375085ce202ef484a1d7c776fa8/src/apps/CMakeLists.txt) and [Qt deployment](https://github.com/deskflow/deskflow/blob/b29f16f937b3a375085ce202ef484a1d7c776fa8/src/apps/deskflow-gui/CMakeLists.txt) are better candidates than a fixed DLL list. I'd add a dependency manifest and reject unresolved/conflicting files. Its runtime dependency sets need CMake 3.21+, above this change's 3.20 baseline. The inspected build files carry MIT notices; those must stay if code is reused.
- I'd make discovery an optional backend with a manual-connection fallback. Input Leap still requires Bonjour in the reviewed Windows GUI build. [Native Windows browsing](https://learn.microsoft.com/en-us/windows/win32/api/windns/nf-windns-dnsservicebrowse) is worth investigating, with Windows 10+ capability checks, bounded records and safe callback cancellation. A discovered address still needs peer approval.

I wouldn't copy Input Leap's [2019 Bonjour download](https://github.com/input-leap/input-leap/blob/34a34fb20b93113a6b26052cb5a54f9be2327775/.github/workflows/builds.yml) or [historical WiX DLL list](https://github.com/input-leap/input-leap/blob/34a34fb20b93113a6b26052cb5a54f9be2327775/dist/wix/Product.wxs) unchanged. The download has no pinned digest, and that list still names the old OpenSSL DLLs. Its Qt 6 discovery code also casts narrow strings to wide pointers; that's no encoding conversion. These bits need separate review, rather than inheriting their problems along with their useful ideas.
