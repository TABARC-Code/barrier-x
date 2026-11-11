# Platform, storage and actions work plan

10 November 2026. I preserve the local 2.4.25 changes and use the existing test
branch for native checks. Master stays unchanged until the implementation and
its evidence are ready for review. This is an implementation plan, not a release
claim.

| Order | Work | Implementation | Completion check |
| --- | --- | --- | --- |
| 1 | Windows Qt GUI and macOS, BX-005/BX-007 | Select Qt explicitly, remove obsolete GUI APIs, add native build and GUI/reader tests on both platforms | Windows and macOS compile the engine and GUI, exercise identity/approval/reconnect tests, and record exact SDK/toolchain inputs. Desktop permissions and interactive input need separate checks. |
| 2 | Earlier parent directories, BX-004 | Traverse from a retained trusted root, validate each component and create missing folders relative to checked handles | Refuse unsafe owners, writable ancestors, unsafe links and explicit parent traversal. Inject component replacement and failed directory creation. Keep files and cleanup anchored. Cover platform-specific path conventions. |
| 3 | Concurrent SSL shutdown, BX-001 | Reproduce close during application I/O; make state and ownership changes race-safe and close idempotent | Deterministic read/write versus close, repeated close and failure tests; real paired sessions, timeout/reconnect and sanitiser evidence where available. |
| 4 | Packaging and clean installation, BX-005/BX-024 | Collect actual runtime libraries, notices and manifests; build relocatable bundles and bounded installation/removal scripts | A separate clean runner installs, launches, upgrades and removes each package without build SDKs or developer PATH entries. Preserve identities/settings. Check dependency search paths and missing libraries. Signing needs a real signing identity. |
| 5 | Reviewed actions and scheduling, BX-031 | Target-owned four-slot registry, authenticated requests, exact-content approval, separate elevation and scheduling grants, cancellation and bounded output | Deny unknown/changed scripts, wrong targets, expired/replayed approval and unauthorised scheduling. Exercise real benign actions, timeout/cancellation and restart. Clipboard input never executes. |

## Order and boundaries

I finish build portability before relying on a platform pass for later changes.
Storage and shutdown precede a command runner. An approval dialog cannot confer
permissions which the target hasn't granted. Elevated actions use the target's
existing operating-system policy; I won't store an administrator password.

The action registry has four named slots. The target records the reviewed script
hash, interpreter, target identity, time/output limits and permitted caller.
Changing the script invalidates its approval. One-off scripts require deliberate
unlocking and approval of their exact bytes and target. Scheduling is a separate
persistent permission, with revocation and a clear next-run display. Ordinary
clipboard and keyboard events carry no action-execution meaning.

I keep script contents, credentials and private keys out of diagnostic logs.
Execution records contain identifiers, public hashes, timing and result metadata.
Remote transport must authenticate the target and caller before command dispatch;
an address or discovered display name is not identity proof.

## Status

| Area | Evidence available | Still missing |
| --- | --- | --- |
| 2.4.24 native storage and engine | Windows storage/service/pipe checks, Windows Release engine, Linux Debug/Release and selected sanitisers passed on 1f21f179 | Windows Qt GUI, macOS and complete installation checks |
| 2.4.25 POSIX trust folder | 84 GUI unit and 25 dashboard cases passed in each discovery mode locally | Earlier ancestors, native macOS and hosted checks for this version |
| 2.4.26 GUI portability | Local Qt 5.15.15 build; 84 GUI unit and 29 dashboard cases | Windows Qt/macOS stop at SDK patch application; corrected in local 2.4.27, not yet a native pass |
| 2.4.27 SSL shutdown | Five new local concurrency cases pass with ThreadSanitizer, including paired TLS application I/O | Real network/multiplexer shutdown and native concurrency |
| 2.4.28 POSIX GUI trust ancestors | Eleven new regressions; root-relative checks and private creation implemented | Windows/engine paths, macOS extended ACLs, path-based lock and crash durability remain open |
| 2.4.29 native build settings | macOS SDK build established in 2.4.28; sysroot and Windows OpenGL failures reproduced in hosted logs and settings corrected | Corrected native application builds, GUI tests and packaging remain unverified |
| 2.4.30 Qt API compatibility | Both local Qt majors compile; thirteen CTest entries pass under each | Native Windows/macOS GUI results, desktop use and packaging |
| 2.4.31 identity-read ancestors | Shared POSIX walker; unsafe/link/missing/replaced-parent regressions | Identity creation/publication, engine trust loading, Windows parents and macOS ACLs |
| 2.4.32 POSIX identity writer | Handle-relative creation, publication and cleanup; checked GUI folder creation; thirteen Qt 6 CTest entries, 99 Qt 5 GUI cases and 37 ASan/UBSan storage cases pass locally | Native validation, Windows parents, public fingerprints, extended ACLs, concurrent generation and crash durability |
| 2.4.35 native log controls | macOS GUI/engine and five selected CTest entries pass in run 42930635192; the Windows GUI compiles and all five log-control dashboard cases pass in run 42930635323 | Interactive use, extended ACLs, full retention suite and installation; Windows still fails known key round trips and one trust-context dashboard case |
| 2.4.36 native log checks | Twelve Windows log scenarios pass in run 42981547370; macOS passes six selected suites including retention in run 42981547400 | Windows parents, extended ACL review and installed-application tests |
| 2.4.37 service log checks | Windows native run 42993099755 passes log retention, deletion, resumed writes and all allowed/refused ownership cases | Installed-application and interactive use |
| 2.4.38 Windows private-file parents | Linked-parent refusal passes in native run 43103242776; same-user rename disproves the intended sharing-based pin | Replace the false pin assumption; owner/ACL policy and installed-application paths |
| 2.4.39 Windows parent authority | Code compiles in run 43105163943; all storage targets refuse the runner's shared temporary ancestry before their fixtures | Use a private test boundary; inherited deny-ACE policy and installed-application paths |
| 2.4.40 Windows private fixture boundary | Native fixtures use private Local AppData while retaining an explicit world-writable-parent refusal case | Native execution and installed-application paths |
| Reviewed actions | Design only | Registry, target enforcement, transport, GUI, scheduling and negative tests |

I update this table as evidence arrives. A workflow file or a successful compiler
invocation alone doesn't prove an installation works on a clean machine.
