# barrier-x development plan

Updated 6 November 2026. Starting point: upstream-derived commit
`653e4badeb88f61de901581667d4465d7b1e2d52` on `master`.
Current development version: **2.4.17-snapshot**.

The aim is dependable control across several computers, with a clear account
of which device receives input and what it may share. Security, recovery and
usable configuration come before extra transports or a new interface toolkit.

The current order of work and external review requests are in
[working-plan.md](working-plan.md).

## Tracking ideas in the code

`FUTURE(BX-007)` links a source comment to an entry below. The comment explains
the local constraint; this document records scope and completion evidence.

States are **Planned**, **Investigate**, **In progress**, **Deferred** and **Implemented**.
An implemented item records its first version, tests and remaining limitations.
When part of an item lands, record that part without closing the whole item.
The changelog preserves the history; old promises need not live in comments
forever. Version numbers advance with completed change sets, including this
planning update. A snapshot is not a tested release.

## Foundation and first improvements

| ID | State | Work | Completion evidence |
| --- | --- | --- | --- |
| BX-000 | Implemented, 2.4.1-snapshot | Source planning notes, corrected assessment, backlog and version tracking | Comment-only source comparison, both version declarations matched, whitespace check; no application build claimed |
| BX-001 | In progress, 2.4.2-snapshot | SSL wrapper ownership, cleanup before initialisation, context allocation failure, repeated close and exception propagation implemented | Thirty-one SSL tests, including injected context/session/transport failures; session allocation, transport attachment and retry preservation added in 2.4.6; application I/O state/count guards added in 2.4.11 with seven regressions; real concurrent shutdown remains to check; see build.md |
| BX-002 | In progress, 2.4.3-snapshot | TLS 1.2 minimum implemented; TLS 1.3 remains available. Readiness now follows pin approval (2.4.9); trust-setting migration remains planned | Real memory-BIO handshakes reject TLS 1.0/1.1 and accept 1.2/1.3 in both roles; five controlled peer-trust regressions added in 2.4.9; pairing migration and real network tests still required |
| BX-003 | Implemented, 2.4.13-snapshot | Windows named-pipe caller credentials, administrator command policy, retained child identity and queued-request checks | Ten native Windows checks passed, including a second local user; six service adapters compiled with the SDK. Portable authority and sanitiser checks passed. Interactive UAC, installed-service/session transitions and full Windows desktop validation remain unverified; see local-management.md |
| BX-004 | In progress, 2.4.5-snapshot | EVP RSA-3072 generation, checked certificate construction and sibling-file publication implemented; new POSIX files use mode 0600 | Twenty-five storage tests, three engine-loader regressions and three GUI identity tests cover generation, existing POSIX mode migration, ownership/links, checked-handle loading and failure preservation (2.4.14). Windows protected owner/LocalSystem ACL creation and handle-based migration added in 2.4.15; fourteen native storage checks passed in run 41719122150, covering another local user, links and failed migration. Five LocalSystem service scenarios passed in run 42149125814 (2.4.16), including the actual console user and failed token/permission checks; live console switching, full Windows/macOS storage integration and parent traversal remain open |
| BX-005 | In progress, 2.4.2-snapshot | GCC 13 header fixes, optional test dependencies, CTest registration and pinned Linux CI workflow implemented | Ubuntu CLI and unit build established; Debug/Release CI added; Qt GUI and Qt IPC checks added in 2.4.10; Windows x64 Release engine builds and ten CTest entries established with checksum-pinned OpenSSL 3.5.9 in 2.4.17; CMake baseline 3.20, imported test targets and obsolete Windows helper/installer refusal added. Windows GUI/Debug, macOS and packaging remain outstanding |
| BX-006 | Investigate | Bound protocol, clipboard and transfer accumulation; retain input responsiveness | Follow receive paths, fuzz malformed lengths/sequences, test queued-byte limits and cancellation; distinguish measured limits from assumptions |
| BX-007 | Planned | Connection and pairing UX: discovered, approved, connected, focused, paused, failed | Status comes from engine state; distinct trust-rejection and network-loss errors; accessible controls; tested local-return path and key release on disconnect |

The Linux harness and a Windows SDK management-channel job are established.
The Windows transport now checks caller credentials and passed its native SDK
suite. Interactive installed-service/session checks remain unverified. POSIX
existing-key permissions now migrate on identity read. Windows identity ACLs are
protected at creation and through the read handle. Full platform builds, service
storage integration and the remaining concurrent SSL shutdown paths follow. Review relevant patches
from other forks individually; importing a whole fork would import its mistakes
as well. See `assessment.md` for the starting evidence and corrections.

## Modern input and workspace

| ID | State | Work | Completion evidence |
| --- | --- | --- | --- |
| BX-008 | Planned | Wayland capture and emulation behind explicit capabilities, using portal/libei interfaces where supported | Separate sending/receiving results per compositor, version and permission state; reconnect after session restart or permission loss; clipboard reported separately |
| BX-009 | Planned | Destination-specific modifiers, chord rules and adjustable tap/hold; consider KeyStitch's design | Key-down/up symmetry, switch mid-chord, disconnect, repeat and timeout tests; presets and rule precedence explained in the editor |
| BX-010 | Planned | PNG and negotiated clipboard formats, per-device direction/type/size limits, pause and send-once | Text, HTML and existing bitmap remain usable; oversized and malformed formats rejected; explicit policy works in both directions |
| BX-011 | Planned | File offers with acceptance, destination, progress, cancellation and retry | Bound paths and sizes; reject traversal and unsafe destinations; define symlink/overwrite behaviour; large transfers do not starve input |
| BX-012 | Investigate | Capability negotiation and measured interoperability with selected peer versions | Both server/client directions tested for each feature and TLS policy; document unavailable features; no silent security downgrade |
| BX-013 | Investigate | Relative motion for pointer-grabbing applications, side buttons, scaling and latency | Reproduce existing failures, measure before/after, test representative 3D apps and desktop use; document unsupported raw-input paths |
| BX-014 | Planned | Monitor canvas, saved workspaces, undo/import/export and optional context-based selection | Preserve old configuration; show real monitor offsets and crossing previews; keyboard access; network names never act as identity proof |
| BX-015 | Deferred | Multiple controllers with explicit ownership and a local override | Specify lease/revocation and handover; release all held input; test competing requests, failure and reconnection before extending the protocol |
| BX-016 | Investigate | Unicode text entry separate from physical-key forwarding | Specify composition and input-method behaviour; test grapheme sequences, CJK and non-BMP text; retain shortcut/raw-key behaviour where text injection is unsuitable |
| BX-017 | Deferred | Optional relay transport for peers on different networks | Threat model, authenticated peer identity, replay/reconnect tests, bounded relay resources; no custom cryptography or relay-visible plaintext claims without verification |

I am also keeping three recovery details on the list: show held modifiers and
local-return controls beside the focused device (BX-007/BX-009), show sharing
limits before accepting an offer (BX-010/BX-011), and discard pending offers
rather than silently replay them after reconnect (BX-011/BX-019). These are
proposals; backend behaviour and accessibility checks still need evidence.

For identity recovery (BX-007), I want clear ownership/mode errors and an
explicit repair/replace action which explains changed peer pins. Windows files
owned by a group or another user need deliberate ownership repair; I do not
silently take them over. This remains
planned. Diagnostic exports should contain public fingerprints and exclude
private-key files (BX-023).

For the ownership-recovery interface (BX-007), I also want an unavailable
console-token lookup distinguished from a foreign file owner. A generic repair
prompt would send the user after the wrong permission. This remains proposed;
2.4.16 adds service coverage without changing the reader's error policy.

The desktop interface will remain Qt initially. Improve engine status and the
management boundary before replacing the presentation layer. A running process
is a fairly low bar for a useful status indicator.

## Operations and longer-term ideas

| ID | State | Work | Completion evidence |
| --- | --- | --- | --- |
| BX-018 | Investigate | CLI/TUI management, then an optional browser configuration editor | One authenticated local management API and validated configuration schema; browser access requires its own origin/CSRF/authentication design, with no new network listener by default |
| BX-019 | Investigate | Service installation, session recovery, screensaver/lock policy and media-key routing | Extend existing service/synchronisation code; test each OS and session separately; benchmark scheduling before raising priority |
| BX-020 | Deferred | A bounded Rust prototype for a parser or other suitable module | Equivalent behaviour, fuzzing, FFI ownership review, build/packaging costs and performance measured; migration is a decision, not a language quota |
| BX-021 | Deferred | Optional extension system and alternate GUI | Define a demonstrated need, permission boundaries, latency budget and maintenance cost before selecting WASM, Tauri or QML |
| BX-022 | Deferred | Hardware security-key forwarding research | Validate the OS device model, origin/user-presence expectations and threat model; generic HID packets are not a complete FIDO forwarding design |
| BX-023 | Deferred | Operational history and diagnostics | Start with connection/focus/failure metadata and redacted exports; content logging or keystroke replay needs a separate explicit design and user decision |
| BX-024 | Planned | Release provenance, dependency inventory and private security-reporting route | Document actual reporting route, hashes, build inputs and platform checks; set up signing only when the identity and verification process exist |
| BX-025 | Implemented, 2.4.3-snapshot | POSIX wake-up pipes now belong to the target thread and close with it; creation/reference changes serialised; full pipes do not block callers | Descriptor ownership/closure regression, 10,000 wake-ups and hosted Debug/Release checks including leak scanning passed in run 40815018907 |
| BX-026 | Implemented, 2.4.3-snapshot | Detached stdin/EOF handling and saved descriptor flags fixed | Five pipe/EOF/flag regression tests; actual localhost transfer tests now run without the inherited stdin assertion |
| BX-027 | Implemented, 2.4.4-snapshot | Poll descriptor storage now unwinds safely when cancellation throws | Deterministic interrupted-poll test and hosted Debug/Release checks including leak scanning passed in run 40815563644 |
| BX-028 | Implemented, 2.4.7-snapshot | Event queues own their lazy event-type providers; first construction is serialised | Two new tests cover all twenty providers, repeated lifetimes and concurrent first access. Normal and ASan/UBSan checks passed locally; hosted Debug/Release and leak checks passed in run 40860940285 |
| BX-029 | Implemented, 2.4.8-snapshot | Incremental, bounded engine IPC frames, strict validation and correct command elevation encoding | Thirteen regressions and three localhost round trips passed; local ASan/UBSan passed. Split/coalesced frames, both limits, invalid fields/directions and proxy dispatch covered; Qt reader hardening follows in 2.4.10; caller authentication and aggregate queue limits remain open |
| BX-030 | Implemented, 2.4.10-snapshot | Non-blocking bounded Qt service reader, reconnect recovery and explicit protocol errors | Full Linux GUI build, 58 existing GUI tests and the Qt socket suite passed; QtTest reported 39 passes including suite hooks, also under local ASan/UBSan. Windows/macOS and interactive desktop validation remain open |

## Next four weeks

This is an order of work, not a promise that every platform will be finished
on a particular Friday. Each session takes the next bounded task from the
latest verified head and records what was checked.

1. Establish the build, reproduce lifecycle failures, fix them and add relevant
   regression tests. Keep tests that expose real failure paths.
2. Review TLS, key storage and local command access. Apply small fixes with
   explicit compatibility consequences and negative tests.
3. Improve pairing/status and disconnected-device behaviour. Prototype keyboard
   rules only after key-release and reconnect behaviour are understood.
4. Continue the highest unfinished priority. Prepare the Wayland capability
   design and monitor editor from measured backend behaviour.

Publish completed, reviewed work at its real time. An urgent security fix takes
precedence over the usual spacing between updates. If tests or access are
blocked, record the blocker and preserve the work without claiming it shipped.

## Research sources

These are references, not dependencies or endorsements. Inspect the exact
revision, file licences and relevant tests before importing code.

- [Barrier-enhanced comparison](https://github.com/zzt5678/barrier-enhanced/compare/653e4badeb88f61de901581667d4465d7b1e2d52...9e4a25bf9bedbc53d3aaf8c9b65414b121130a54): candidate build, TLS, clipboard and input patches; review independently.
- [KeyStitch remap guide](https://github.com/johneybi/keystitch/blob/master/doc/key-remaps.md): destination rules and documented tap/hold/chord limitations.
- [Deskflow](https://github.com/deskflow/deskflow): platform/backend and interoperability research; inspect the current source layout rather than assume old filenames.
- [Lan Mouse](https://github.com/feschber/lan-mouse): capture/emulation separation and capability reporting. Its GPL-3.0 licence requires compatibility review before code reuse.
- [Hydra](https://github.com/PacAnimal/hydra): profiles, terminal management and shared-control ideas; documented behaviour still needs implementation review.
- [Conduit](https://github.com/noxio-dev/Conduit): early relative-motion research, with explicit development limitations.
- [Seamgate](https://github.com/digital-michael/seamgate) and [Flowdesk](https://github.com/helloxkk/flowdesk): investigate migration and frontend trade-offs if a concrete need emerges.
