# barrier-x development plan

Updated 29 October 2026. Starting point: upstream-derived commit
`653e4badeb88f61de901581667d4465d7b1e2d52` on `master`.
Current development version: **2.4.1-snapshot**.

The aim is dependable control across several computers, with a clear account
of which device receives input and what it may share. Security, recovery and
usable configuration come before extra transports or a new interface toolkit.

## Tracking ideas in the code

`FUTURE(BX-007)` links a source comment to an entry below. The comment explains
the local constraint; this document records scope and completion evidence.

States are **Planned**, **Investigate**, **Deferred** and **Implemented**.
An implemented item records its first version, tests and remaining limitations.
When part of an item lands, record that part without closing the whole item.
The changelog preserves the history; old promises need not live in comments
forever. Version numbers advance with completed change sets, including this
planning update. A snapshot is not a tested release.

## Foundation and first improvements

| ID | State | Work | Completion evidence |
| --- | --- | --- | --- |
| BX-000 | Implemented, 2.4.1-snapshot | Source planning notes, corrected assessment, backlog and version tracking | Comment-only source comparison, both version declarations matched, whitespace check; no application build claimed |
| BX-001 | Planned | Harden SSL resource lifecycle: cleanup before initialisation, failed context allocation, repeated close and error propagation | Regression tests exercise these paths without crashing or using an invalid context; sanitiser run where available |
| BX-002 | Planned | Define TLS minimum and peer authentication policy; test both roles and migrate trust settings | Reject unsupported TLS, unknown and changed identities; verify approved peers; failed or missing trust storage never silently grants access |
| BX-003 | Planned | Authenticate local management commands and authorise the caller | Unauthorised local users cannot change daemon commands or read privileged state; exercise service/session boundaries and endpoint permissions |
| BX-004 | Planned | Replace deprecated certificate APIs, protect key files and handle generation/write failures | Supported OpenSSL build, restrictive creation permissions, checked return values, no partial certificate accepted after failure |
| BX-005 | Planned | Reproducible builds, maintained dependencies and a small useful CI matrix | Build and existing tests on available platforms; exact dependency and runner revisions; record missing platform checks before packaging claims |
| BX-006 | Investigate | Bound protocol, clipboard and transfer accumulation; retain input responsiveness | Follow receive paths, fuzz malformed lengths/sequences, test queued-byte limits and cancellation; distinguish measured limits from assumptions |
| BX-007 | Planned | Connection and pairing UX: discovered, approved, connected, focused, paused, failed | Status comes from engine state; actionable errors; accessible controls; tested local-return path and key release on disconnect |

BX-001 and BX-005 are the next implementation tasks. Establish a build and
regression harness before changing the trust policy. Review relevant patches
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
