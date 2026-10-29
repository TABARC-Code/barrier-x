# Starting assessment

29 October 2026; source baseline `653e4badeb88f61de901581667d4465d7b1e2d52`.
This records the starting source, not a completed security audit. Follow-up
changes are recorded below and in `changes.md`; baseline findings are historical.
The supplied Path A/B/C proposals informed `roadmap.md`; their deadlines,
severity labels and proposed release numbers are not adopted as verified facts.

## Findings that need implementation work

- `SecureSocket::freeSSLResources()` dereferences `m_ssl`, although both
  constructors initialise it to null. Reproduce cleanup before `initSsl()` and
  test repeated close; track as BX-001.
- `SecureSocket::initContext()` calls `SSL_CTX_set_options()` before checking
  the result of `SSL_CTX_new()`. Its later error logging does not stop context
  use. Allocation failure needs a defined path back to the caller (BX-001).
- The Windows build selects bundled OpenSSL libraries; their header identifies
  1.0.2l from 2017. Replace these through a reviewed dependency/build change
  rather than merely updating a header (BX-005).
- The TLS setup disables SSLv3 but does not set an explicit minimum TLS version.
  Actual negotiation depends on the linked library and configuration. Define
  and test a supported policy, rather than infer a working attack (BX-002).
- GUI settings default client-certificate checking to false and can disable
  encryption. Review migration, both connection roles and compatibility before
  changing defaults (BX-002).
- The local management listener accepts loopback connections. Trace command
  authorisation and Windows service execution before assigning exploitability
  or severity. Loopback is not caller authentication (BX-003).
- Certificate generation uses the deprecated RSA API and writes a private key
  using an ordinary file open. Review creation permissions, atomic replacement,
  result checking and supported EVP APIs (BX-004).
- File sending queues chunks and uses static transfer state. Trace receive
  bounds, queue pressure, read failures and concurrent cancellation before
  generalising it into file copy/paste (BX-006, BX-011).

## Corrections to the supplied proposals

| Proposal or assertion | Evidence and planning consequence |
| --- | --- |
| Clipboard is text-only | `IClipboard::EFormat` already includes text, HTML and bitmap. Extend rather than rebuild those features. |
| A 32 kB clipboard maximum | `StreamChunker` uses 32 kB chunks. That alone is not a total transfer bound. Inspect receiving and allocation paths. |
| Relative injection needs adding | Protocol 1.2 and `XWindowsScreen::fakeMouseRelativeMove()` already provide a relative path, including `XTestFakeRelativeMotionEvent`. Reproduce the actual capture/grab failure. |
| Screensaver sync and a Windows service are new features | `kMsgCScreenSaver`, server settings and Windows daemon/service code already exist. Their practical limits still need testing. |
| Ignoring chain validation means unknown certificates are accepted | The baseline performs a later SHA-256 fingerprint database check; an unmatched fingerprint returns false. Review pinning, pairing and role-specific policy together. |
| SHA-1 support proves a trust bypass | The inspected trust decision uses `db.is_trusted(fingerprint_sha256)`. SHA-1 calculation/logging is not evidence of acceptance. Review migration and remove obsolete handling deliberately. |
| Deprecated RSA generation proves a vulnerable key or an OpenSSL 3 build failure | Deprecation alone proves neither. Availability depends on headers/build policy. Replace APIs and test key handling without inventing an exploit. |
| TLS needs another protocol MAC | Authenticated TLS already provides transport integrity. Define the threat model; forbid unwanted plaintext rather than bolt on homemade cryptography. |
| Rebase onto another fork closes the audit | Imported changes need review, failure tests and compatibility checks. A commit title is not a closure report. |
| Switch to Qt 6, Rust or a web frontend immediately | Each adds migration and packaging costs. Tie the change to an actual requirement and validate the boundary first. |
| Change the licence freely because the projects are related | Retain notices and inspect the terms of each reused file and dependency. Fork status does not grant relicensing rights. |

No runtime fix is included in 2.4.1-snapshot. The source edits are planning
comments. Application, multi-machine and platform tests remain outstanding.
The review also does not certify third-party repositories or their binaries
as free from malware; inspect relevant code and scripts before using them.

## Follow-up: 2.4.2-snapshot

The two lifecycle failures above were reproduced as segmentation faults using
new regression tests against the unpatched socket implementation. Cleanup now
tolerates absent state, context allocation failure throws before use, and the
factory retains ownership until setup succeeds. Reinitialisation is rejected.
The listener preserves the original exception type during cleanup.

This does not close the TLS policy, IPC authentication, key-file handling or
session allocation work. See `build.md` for the checked environment and tests.

## Follow-up: 2.4.3-snapshot

The TLS floor is now explicit and covered by real version-negotiation tests in
both roles. Pairing and trust policy remain separate outstanding work.
Hosted leak scanning exposed incorrect wake-up pipe ownership and missing
cleanup in the inherited POSIX implementation; target-thread storage, cleanup
callbacks and serialised reference changes address those findings. Completion
depends on the follow-up leak-check result, not the patch description.

## Follow-up: 2.4.5-snapshot

Two storage regressions were reproduced against the old generator: mode 0666
under a permissive umask, and replacement of an existing identity despite a
certificate-write failure. New certificates use checked EVP RSA-3072 generation
and a private POSIX temporary file, then replace the destination only after
successful write, flush, synchronisation and close. Failure tests also cover
the replacement operation itself and require the old contents to survive.

This is generation hardening. Existing valid files may still have legacy
permissions, and Windows files still inherit their directory ACL. Both remain
explicit BX-004 follow-up work. No change to peer trust policy is claimed.

## Follow-up: 2.4.6-snapshot

Session allocation failure was reproduced as a crash, and a deterministic
retry test showed queued BIO data being discarded by repeated descriptor
attachment. Session creation and attachment are now checked together, retained
only on success and reused during retries. Missing context, closed sockets and
failed setup return a fatal result before any handshake call. Both roles have
failure coverage and real non-blocking socket retry tests. This does not close
concurrent shutdown, input-state synchronisation or peer trust migration.
