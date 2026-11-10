# Working plan

10 November 2026. The five-area completion programme is in
[completion-plan.md](completion-plan.md). Local development is 2.4.26-snapshot;
the published test branch remains 2.4.24 until the next verified checkpoint.

The detailed backlog
and landed versions live in [roadmap.md](roadmap.md); build evidence stays in
[build.md](build.md). This is the order I'd work through, rather than another
list of things I'd quite like to finish eventually.

| Order | Work | State and finish point |
| --- | --- | --- |
| 1 | Windows TLS and engine build, BX-005 | Implemented in 2.4.17 for x64 Release: external OpenSSL 3.5.9, client/server/service builds and ten CTest entries passed. The legacy installer remains refused; GUI and packaging follow below. |
| 2 | Qt and discovery libraries, BX-005 | Partial, 2.4.18. DNS-SD is optional; manual connection preserves its address and saved discovery preference. I remove HTTP installer downloads and idle listener threads. Windows Qt GUI builds, supported SDK/advisory selection and live discovery failure handling remain next. |
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
- I make discovery optional in 2.4.18, with a manual-connection fallback. A replacement backend remains a proposal. Input Leap still requires Bonjour in the reviewed Windows GUI build. [Native Windows browsing](https://learn.microsoft.com/en-us/windows/win32/api/windns/nf-windns-dnsservicebrowse) is worth investigating, with Windows 10+ capability checks, bounded records and safe callback cancellation. A discovered address still needs peer approval.

I wouldn't copy Input Leap's [2019 Bonjour download](https://github.com/input-leap/input-leap/blob/34a34fb20b93113a6b26052cb5a54f9be2327775/.github/workflows/builds.yml) or [historical WiX DLL list](https://github.com/input-leap/input-leap/blob/34a34fb20b93113a6b26052cb5a54f9be2327775/dist/wix/Product.wxs) unchanged. The download has no pinned digest, and that list still names the old OpenSSL DLLs. Its Qt 6 discovery code also casts narrow strings to wide pointers; that's no encoding conversion. These bits need separate review, rather than inheriting their problems along with their useful ideas.


## Control panel, 2.4.19

I keep the existing server/client layout and move status and Start/Stop above
it. Role-specific wording distinguishes a listening server from a connected
client. A role edited during a connection takes effect after stop/start; the
status keeps the role captured for the current attempt. I add visible discovery
guidance, plain address copying and a full public SHA-256 copy action.

Keyboard labels, explicit tab order, selectable identifiers and a resizable
window land in this step. I retain the platform's widget colours and fonts.
This isn't a screen-reader or contrast compliance claim. Explicit peer/focus
events, platform accessibility review and Windows GUI validation remain BX-007.


## Peer approval, 2.4.20

I replace Yes/No with Trust server/client and Reject. Rejection keeps the
default focus; copying the full public SHA-256 value leaves the decision open.
Missing or malformed SHA-256 values cannot be approved. The existing engine
still owns certificate verification and the trust store.

Next I want clearer trust/storage errors and peer identity supplied by the
engine. A discovered name is still just an address-book suggestion. Native
Windows/macOS and screen-reader review remain open.


## Identity errors, 2.4.21

I show setup failures beside the fingerprint and offer Retry. A failed identity
read hides stale copy values. Missing public fingerprints can be rebuilt from
the retained identity. Unsupported existing keys now stay in place for deliberate
repair instead of being silently replaced.

I publish the local public fingerprint file through checked QSaveFile writes,
with direct overwrite fallback disabled. Symlink and non-regular destinations
are rejected. Checked peer-trust saves are next; parent traversal and concurrent
path changes still need review. Retry remains synchronous.


## Dashboard, 2.4.22

I split the interface into Connection, Screen layout and Settings. Status and
Start/Stop stay above the pages. Inactive role controls collapse, the computer's
identifiers stay available, and a persistent identity notice links back to
recovery. Screen layout retains its existing editor and configuration-file mode.
Settings opens the existing preferences dialog and log.

Pages scroll at smaller sizes and keep their selected tab and window geometry.
The engine doesn't need to know which tab I've opened. Native desktop and
screen-reader checks remain open.

| Iteration | Changed area |
| --- | --- |
| 2.4.19 | Clearer control panel and copy actions |
| 2.4.20 | Explicit peer approval and rejection defaults |
| 2.4.21 | Identity errors, Retry and checked public fingerprint saves |
| 2.4.22 | Three-page dashboard and navigation |
| 2.4.23 | Checked peer trust reads, merged saves and visible failures |
| 2.4.24 | Windows protected trust replacement, native checks passed |
| 2.4.25 | POSIX final-folder checks and anchored replacement |


## Peer approvals, 2.4.23

I re-read approvals under a non-blocking lock after confirmation, merge the new
SHA-256 pin and check atomic publication before restarting the client. Invalid
or unreadable stores stop the attempt with a visible error. Legacy SHA-1 entries
stay in the file; new approvals require a complete SHA-256 fingerprint.

The Windows creation checks pass in 2.4.24. POSIX final-folder anchoring and
injected write/publication checks follow in 2.4.25. The lock coordinates
cooperating GUI writers only. Earlier ancestor traversal and clearer permission
repair guidance remain open.

## Reviewed actions, BX-031

I keep four named, reviewed actions as a separate proposal. The target must
check each action ID and grant; elevated commands need their own permission.
A one-off script editor needs deliberate unlocking and approval of the exact
script and target. Clipboard input stays input. I won't call a pile of warning
buttons a security model. Scheduler integration, timeouts, cancellation,
revocation and redacted results need a design before any execution code lands.


## Windows trust replacement, 2.4.24

I route Windows peer approvals through a protected owner/System sibling file.
The helper checks the old target, bounds writes to 1 MiB, flushes the new file
and renames it through its retained handle. Temporary names use exclusive
creation with bounded retries. I attempt handle-based deletion on failure.
The GUI still holds its update lock around the read, merge and replacement.

I add native checks for creation ACLs, replacement bytes, read-only publication
failure and cleanup, size limits and unsafe targets. I also extend service
checks: System may replace its own file, but mustn't turn a console user's file
into a System-owned one. Seventeen file scenarios and five service scenarios
pass on the Windows runner in run 42564987233. Windows Qt integration still
needs a native build and run. POSIX publication changes below.


## POSIX trust folder, 2.4.25

I open the final folder without following a link, check its owner and write
permissions, and retain its descriptor for reads, temporary creation, rename
and failed-save cleanup. Other users mustn't be able to replace its entries.
The save completes short writes, retries interruptions and checks file flushing
before publication. Shared profiles which allow group writes now require
deliberate permission repair; I don't change directory owners or modes silently. I check that the folder path still matches before merging
and immediately before rename.

Earlier ancestors are still trusted. A same-user rename after the last path
check can leave a successful save in the retained folder; it cannot redirect
that save into the replacement folder. The Qt lock can remain in a moved folder.
Directory metadata isn't synchronised for crash recovery. macOS and Windows Qt
integration, hostile ancestor traversal and broader concurrent storage changes
remain open. The engine's own trust reader is unchanged.

## Before merging

I still need native Windows Qt build/approval coverage and a review of earlier
parent traversal. Full TLS shutdown concurrency remains BX-001; a storage patch
doesn't close it. Runtime packaging and clean-machine install/upgrade/removal
remain BX-005/BX-024. Four reviewed actions stay planned under BX-031.
