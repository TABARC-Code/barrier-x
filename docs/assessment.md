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

## Follow-up: 2.4.7-snapshot

Hosted leak checking of the new setup-failure paths found event-type providers
allocated by `EventQueue` and never freed. Provider slots now use owning smart
pointers, with complete types available at out-of-line queue destruction.
Lazy construction is serialised by the existing queue mutex. Tests exercise
every provider across repeated queue lifetimes and concurrent first access.
Callbacks must still stop before queue destruction; this change does not
introduce concurrent teardown or certify all event-queue operations.

## Follow-up: 2.4.8-snapshot

The engine IPC proxies treated any non-zero header read as four bytes and
ignored failed body reads. Invalid headers could still enqueue a null message.
The old generic string reader already had a 1 MiB bound; this update adds a
smaller command-specific bound and incremental framing, not a first-ever
string length limit. A missing variadic elevation argument in the C++ command
writer is also corrected and checked against exact wire bytes. Authentication
and authorisation remain BX-003 work, independent of parser validity.

## Follow-up: 2.4.9-snapshot

Five regressions failed against 2.4.8: client readiness was visible before
fingerprint approval and remained set after rejection, rejection did not mark
the socket fatal, and fingerprint checking did not release its peer-certificate
reference. Readiness now follows successful SHA-256 pin and certificate checks.
Disconnection clears readiness and marks failure; automatic ownership releases
the certificate reference even if a digest operation throws.

Matching pins succeed in both authenticated roles; untrusted peers, SHA-1-only
trust entries, absent certificates and injected digest failure remain rejected.
This is state and ownership hardening, not evidence of an exploitable trust
bypass in the previous event loop, nor completion of trust-default migration.

## Follow-up: 2.4.10-snapshot

The Qt reader waited indefinitely inside the GUI event callback, ignored failed
reads and allocated from a signed, unchecked wire length. Incremental reads now
return to the event loop while waiting, preserve partial frames, validate an
unsigned length against the existing 1 MiB log limit and stop after malformed
input. Complete UTF-8 messages are decoded once, after the body arrives.

The socket input buffer is bounded and message bursts yield after 64 frames.
Disconnection discards partial state, reconnect starts afresh and protocol
errors reach the existing GUI error signal. Socket ownership now includes the
reader. Stop/restart and callback-driven destruction have regression coverage.
Caller authentication and total retained log history remain unresolved.

## Follow-up: 2.4.11-snapshot

I reproduced a null-state read crash before initialisation and stale byte counts
without a session. Controlled session tests also showed application I/O entering
OpenSSL before approval and after a fatal flag. Both methods now reject those
states under the existing SSL mutex and report zero bytes unless I/O succeeds.
I reject invalid arguments and bypass empty operations, keeping retry buffers
with the caller. I clear the thread error queue before each application I/O call,
as required for reliable SSL_get_error classification.

This adds a low-level guard; it does not establish an exploit in the existing
job loop. Cross-thread readiness/fatal flags and concurrent shutdown still need
review. Local management caller authentication remains unfinished (BX-003).

## Follow-up: 2.4.12-snapshot

I traced GUI commands through IpcClientProxy and IpcServer to the Windows
DaemonApp, registry settings and MSWindowsWatchdog launch path. The proxy
accepted commands before a greeting, let engine connections send them, and
allowed repeated greetings to change the connection role. I now close those
sequences before command dispatch. Each new connection starts with no role.

The shared role/disconnection flags are atomic, and new writes stop once the
disconnection flag is observed. This does not solve concurrent object teardown.
Five proxy regressions cover the role policy; four live socket cases verify
closure without dispatch, alongside the valid GUI command round trip.

I have not authenticated callers. A local process can still claim to be a GUI,
receive logs and request a command, including its elevation flag. The daemon
also restores the saved command on startup. I have recorded the actual launch
and storage boundaries in local-management.md so the transport change includes
both live commands and persisted settings. Windows execution remains unverified.

## Follow-up: 2.4.13-snapshot

I replaced the installed Windows service's TCP endpoint with a named pipe.
The descriptor permits data exchange for interactive callers, without granting
them pipe-instance creation rights; remote clients are rejected. After a bounded
greeting I obtain the client token using checked identification-level pipe
impersonation, restore the thread identity, and compare the current console
logon. Commands require an unrestricted administrator token as well. Both
clients compare the pipe server PID with the running Barrier service in SCM.

Engine callers must match the service's retained child-process handle. I create
the child suspended, register that handle and then resume it, avoiding the
registration race. Authenticated peer state survives queued requests through
shared ownership; disconnection, session/logon changes and replaced children
invalidate later checks. DaemonApp repeats the command check before side effects.
Previously saved commands need fresh administrator approval; I publish a saved
approval marker only after both command and elevation values are written.
I also reject failed/empty command parsing and avoid constructing a string from
a missing log-filter argument. Whole command strings are removed from service diagnostics.

The portable explicit-port test constructors retain TCP, but the installed
service does not fall back to it and refuses commands without a credential
check. Native GUI command changes now require the active console user to start
the interface with administrator approval. Mixed old/new clients are unsupported.
Foreground service debugging is not an alternative authenticated service identity.

The native module and six integration units cross-compile with MinGW. The SDK
job exercises real Windows pipes and tokens; results are recorded in build.md.
Full Windows desktop linking still depends on replacing inherited desktop/TLS
build dependencies. I have not validated installed registry ACLs, interactive
lock/unlock, UAC, session switching or packaging on a Windows desktop.

## Follow-up: 2.4.14-snapshot

I reproduced two engine-loader failures against 2.4.13: it followed an identity
symlink and left a mode-0666 private-key file unchanged. POSIX loading now opens
without following the final symlink, checks the effective owner and a single
regular-file link, and uses fchmod on that same descriptor before reading.
I verify the resulting mode and metadata, then read at most 1 MiB plus a limit
sentinel into a snapshot which is cleansed after parsing. Existing key bytes
and fingerprints survive the permission change.

Certificate and private-key parsing use that one snapshot, with a matching-key
check before installing anything in the SSL context. The GUI uses the same
reader and fingerprints its validated in-memory certificate. Rejected existing
identities remain on disk with an error. The existing GUI policy for replacing
weak keys remains unchanged. Passphrase entry from these event-driven paths is unsupported.

I added thirteen storage regressions, three engine-loader cases and three GUI
identity cases. A rejected encrypted key left OpenSSL errors queued during
integration; the loader now clears that handled failure before a later TLS call. A path-replacement test changes the directory entry during
permission migration and requires the original open file's pair to be installed.
The parent directory must still be trusted; I have not hardened traversal of
parent components. Owner-only POSIX mode cannot revoke existing open handles
or restore secrecy if a legacy key was previously copied. Windows ACL migration,
non-local filesystem ACL policy and macOS/Windows storage checks remain open.


## Follow-up: 2.4.15-snapshot

I replaced Windows CRT-only identity creation with CreateFileW and an explicit,
protected DACL granting the current process user and LocalSystem full access.
The file gets these permissions before any key bytes are written. The owner is
set explicitly, including when an elevated token would otherwise choose a group.
A failed post-creation check marks the empty file for deletion through its handle.

Existing identities open without final reparse traversal or write/delete sharing.
I check disk-file type, attributes, one link and a 1 MiB limit before reading.
The owner must match the process user. A LocalSystem process may also accept the
active console user's file, using WTSQueryUserToken; failure to identify that user
refuses access. I apply and verify the protected ACL on this same handle before
passing it to the bounded PEM reader. Alternate streams are refused.

I preserve foreign/group ownership and report that explicit repair is needed.
The migration does not rotate the key. The identity directory and parent path
components remain trusted. Permission changes cannot recall previously copied
keys or handles opened before the migration. Full Windows PEM/GUI/engine linking,
installed-service console transitions, macOS storage and non-local filesystem
behaviour remain unverified. The standalone Windows tests exercise the file
helper, not the complete desktop application. No third-party code was imported.


## Follow-up: 2.4.16-snapshot

I added an SDK test executable which installs and starts a temporary LocalSystem
service. It verifies the process SID before exercising the unchanged private-file
helper. The service creates and reads its own dummy identity, checks a caller-owned
identity against the actual console token, rejects a separate user's accessible
file, refuses access when console-token lookup fails and preserves bytes when
WRITE_DAC is denied. The denial ACL targets OWNER RIGHTS, since an owner otherwise
receives implicit permission to change its DACL.

I disable SeTcbPrivilege only inside the test service for the failed-token case,
and restore it afterwards. The service reports a bounded result through SCM status.
The fixture directory is locked to the caller and LocalSystem after the separate
user creates its file, before the privileged service starts. The test checks that
the temporary service registration and local account are removed. All identity
contents are fixed dummy text; real keys and account passwords are not logged.

The suite reports console-user acceptance as skipped if the runner has no matching
active console. This is a test of the storage helper under an installed test
service, not the Barrier service's complete engine/GUI path. Logout, console
switching, UAC, desktop linkage and installer validation remain separate work.
No production permission policy or cryptographic dependency changes in this version.

The Windows 2025 candidate passed all five service scenarios, including active
console-user access, in run 42149125814. The existing fourteen storage and ten
pipe checks passed in the same run. This confirms the tested storage helper's
policy under a real LocalSystem process; it does not close the interactive
session-transition work.


## Follow-up: 2.4.17-snapshot

I replace the Windows CMake selection of bundled OpenSSL 1.0.2 with imported
OpenSSL targets. The Windows SDK must be on the supported 3.5 LTS line, at least
3.5.9. The source archive is checked against the official SHA-256 before building.
This changes dependency selection; it doesn't change peer approval or the TLS
1.2 protocol minimum. The added runtime assertion checks libcrypto's version.
Full libssl/provider provenance and deployment paths still need packaging work.

I refuse installer generation while the historical templates select old DLLs.
The batch build/installer helpers are retired, and the old Azure Windows job is
disabled before its unchecked legacy SDK downloads. Other historical packaging
files remain for reference. The current engine route builds from pinned sources
and has explicit rejection checks for the old SDK and helper paths.

The hosted CMake version rejected the project's 3.4 compatibility declaration.
I raise the baseline to 3.20, remove redundant policy settings and use imported
Google Test/Mock targets where available. The GUI test target now consumes those
selected targets too. The Windows GUI still needs Qt and discovery work; this
change doesn't claim a complete desktop or installer build.

The working plan separates build, library, shutdown, trust/recovery, input and
sharing work. Dependency notes record reviewed entry points, source revisions,
licences and gaps. I ask for external Windows deployment/session review and a
check of distribution licence combinations before installers are published.

The first engine compilation also exposed Windows min/max macros rewriting the
standard-library bounds calls in fingerprint randomart. I define NOMINMAX for
the Windows build, matching the existing native SDK harness.

Current Google Mock also rejected a Windows-only matcher which cast a base
message matcher to a derived log frame. I match the actual frame type and text
instead, preserving the test's assertion without an unchecked downcast.

The x64 Windows Release candidate passed all ten engine CTest entries in run
42264522552, alongside twenty-nine native checks in run 42264522574. The client,
server and service linked with the external OpenSSL SDK. The working plan records
reviewed Deskflow/Input Leap migration and deployment approaches as proposals;
none of their source or scripts was adopted by this change.

Linux Debug/Release, GUI checks and Debug ASan/UBSan with leak detection passed
for the final candidate in run 42264522576. This is verified build progress;
the full application security audit and the desktop/deployment review stay open.


## Optional discovery, 2.4.18

I remove the GUI's HTTP Bonjour MSI download and execution path. DNS-SD is
now a build option; without it, manual hostname entry remains available and
the saved automatic-discovery preference survives. Late discovery callbacks
are ignored in manual mode. Availability refreshes also reconcile the reader,
rather than just changing a checkbox. Windows service-query handles now close
on every inspected exit path.

The discovery advertisement listener only accepts and closes connections. I
remove its worker threads, which could previously be destroyed while running.
Qt's [QTcpServer ownership contract](https://doc.qt.io/archives/qt-5.15/qtcpserver.html#incomingConnection)
lets the listener accept and close sockets in its own thread. No external
source was copied.

The widget recovery test substitutes availability and the lifecycle hook; it
doesn't start or stop Bonjour. Linux availability still means compiled DNS-SD
support, not a live Avahi probe. Live daemon failure, modal provider errors,
Windows GUI execution and Qt migration remain open. Availability is refreshed
when opening or retranslating the window, not polled in the background.


## Control panel, 2.4.19

I move status and Start/Stop above configuration and make the server/client
wording explicit. Stop stays available while connecting, and repeated state
changes no longer add duplicate button connections. Language refreshes retain
current status, identifiers and the expanded fingerprint details. The displayed
running role stays separate from a newly selected role until the next attempt.
The fingerprint prompt and trust-database selection also retain that running
role, rather than following an edited checkbox.

The address copy action uses plain network addresses. The fingerprint action
uses a full 32-byte public SHA-256 value, separately from the shortened display.
Missing or disabled fingerprints clear the stored copy value and old details.
No private-key data is copied. These actions deliberately replace the clipboard
only when clicked; existing clipboard-sharing policy still applies.

The engine still reports state through existing log messages. I haven't added
peer counts, focus detection or new trust policy, and role changes while running
still need stop/start. Live session changes, screen readers and native Windows
and macOS layouts remain to check.


## Peer approval, 2.4.20

I make the approval decision explicit, default to Reject and separate copying
from accepting. Trust remains an explicit button action. The dialog checks
the SHA-256 algorithm and 32-byte length before enabling Trust or Copy; its
accept handler also refuses malformed values. SHA-1 stays a legacy reference.

This changes presentation and invalid-input handling. It doesn't introduce
a new pairing protocol or claim that discovery proves identity. Native
platform focus behaviour and accessibility still need outside review.


## Identity errors, 2.4.21

I connect certificate errors to a plain-text notice and Retry in the control
panel. Failed identity setup clears stale fingerprint controls. Missing or bad
public snapshots can be rebuilt on request. Existing unreadable, malformed and
unsupported identities are preserved. Initial setup can still create an identity
when no file exists.

Local public fingerprints now use checked temporary-file publication through
Qt's QSaveFile, without direct overwrite fallback. Non-regular destinations and
symlinks are refused. This is the local snapshot only; peer trust stores still
need checked publication. Trusted parent directories, race testing and native
Windows/macOS review remain outstanding.


## Dashboard, 2.4.22

I move configuration behind three pages while keeping connection actions and
status visible. Page navigation doesn't issue engine commands. The existing
editor, preferences dialog, configuration values and trust controls stay wired
to their current handlers. Identity failures remain visible above every page
and link back to Retry on Connection.

I add scrolling, saved page/geometry and compact inactive roles. These are
local Qt interface changes. Native Windows/macOS, screen readers and live
engine/discovery transitions still need desktop validation.


## Checked GUI peer approvals, 2.4.23

I replace the GUI's unchecked peer database read/write with a bounded checked
reader and locked atomic save. Confirmation re-reads the current file before
merging, so approvals saved while the dialog is open survive. Read, validation,
lock and publication failures stop the attempt and reach a plain-text dashboard
error. This deliberately refuses malformed or unknown records instead of
silently dropping them. Existing legacy SHA-1 records are retained.

POSIX reads check the open descriptor's owner, regular-file type, single link
and absence of group/world write access; new files use mode 0600. Windows reads
reuse the checked file helper. Native Qt Windows creation ACLs remain unverified:
Qt permission flags aren't evidence of a protected Windows ACL. Parent paths
are still assumed trusted, and the GUI lock cannot coordinate unrelated writers.
The engine's existing database reader is unchanged. This isn't a complete trust
migration or storage audit.


## Windows trust replacement, 2.4.24

I remove the Windows peer-save dependency on Qt permission flags. The new
replacement helper reuses protected owner/System creation, validates an existing
target and retains the new handle through writes, flushing and rename. Existing
foreign owners, links, streams and non-regular files are refused. A System
caller cannot replace a console-owned file with a System-owned sibling.

I compile the helper and pass seventeen storage scenarios plus five service
scenarios on the Windows runner in run 42564987233. This verifies the native
helper, including protected creation, read-only failure cleanup and size limits.
The Linux workspace still has no Windows SDK compiler or Windows runtime; the
runner provides that validation. Windows Qt integration remains unverified.
Parent traversal and changes by non-cooperating writers remain unresolved.
Deletion after failure is attempted through the retained handle; failure of that
cleanup can leave a protected temporary file. Flushing the data before rename
doesn't establish crash durability of directory metadata. Existing permissions
may migrate during target validation even if replacement later fails.


## POSIX final trust folder, 2.4.25

I check the final peer-trust folder through an open descriptor: it must belong
to the current user, be a directory and deny group/world writes. A final-folder
symlink is refused. Reads and replacement publication use openat/renameat
relative to that descriptor; failed-save cleanup uses unlinkat on the same
folder. New files retain mode 0600 and close-on-exec. I complete short writes,
retry EINTR and check fsync before publication.

I don't anchor the earlier ancestor chain. The pre-publication path check
catches a folder already moved or replaced, but a later same-user rename can
still change which folder the engine sees afterwards. The retained descriptor
prevents redirecting publication or cleanup into the new folder. Qt's path-based
lock may remain in the moved folder and coordinates only cooperating writers.
This isn't complete path-race protection or a change to engine trust loading.
File flushing alone doesn't establish directory crash durability.


## Screen dragging and diagnostic privacy, 2.4.26

I bound drag frames and collection lengths before Qt allocates them, reject
invalid source/destination coordinates and trailing bytes, and apply only a
fully parsed screen. The old reader returned before restoring modifier
overrides; dragging an edited screen now preserves them.

Existing diagnostic levels could record character IDs, native key codes and
dynamic mappings. I remove those values across the engine and native input
paths, retaining event/failure descriptions. Static keyboard-map configuration
and registered hotkey configuration remain visible. Timing and routing metadata
remain; this isn't anonymous logging or a complete diagnostic export audit.


## Concurrent SSL shutdown, 2.4.27

I make fatal/readiness flags atomic and serialise public close callers. Close
marks the connection terminal before waiting for in-flight SSL operations. The
existing SSL mutex still protects the session and its release; I remove the
multiplexer job before taking it, preserving the callback lock order. Readiness
observers report false once shutdown begins, including a handshake unwinding
after the fatal flag changed. Concurrent destruction remains invalid object use.

Five new tests cover repeated competing closes and real TLS sessions in both
roles, pausing application reads/writes while two closers wait. I use registered
application threads for calls into the socket layer. A first ThreadSanitizer run
finds shared localtime storage in the logger; I replace it with localtime_r on
POSIX and localtime_s on Windows, then pass all five cases without suppressions.
OpenSSL itself is the system library, not an instrumented build. Real network
multiplexer shutdown, cancellation and native stress checks remain open.


## POSIX GUI trust ancestors, 2.4.28

I walk from an open filesystem root and check every directory's owner and
write bits before using it. Intermediate folders must belong to root or this
user. A root-owned sticky shared parent such as /tmp is allowed; the final
folder must belong to this user and deny other users' writes. I don't change
existing permissions on the user's behalf. Missing folders use mkdirat(0700)
through the checked parent, before any approval or Qt lock file is created.

I reject explicit parent traversal, final-folder links and untrusted link
owners. Checked intermediate links resolve component by component, including
relative targets, with limits of forty links, 256 queued components and 512
steps. Every directory open uses O_NOFOLLOW. The checked target matters too;
a link cannot make a writable ancestor acceptable. I rewalk the chain before
merging and publication, comparing the retained leaf's device/inode. Publication
and failure cleanup remain relative to the retained directory descriptor.

This covers the GUI peer store. Windows and engine identity/trust readers are
unchanged. POSIX ownership/mode checks don't inspect macOS extended ACLs. The
Qt lock remains path-based, directory metadata isn't fsynced, and a same-user
rename after the last check can still leave the published file in the held old
folder. The root/ancestor opens require read access as well as traversal access.
These constraints remain open; this isn't a completed storage audit.

For recovery, I want the interface to identify the failing ancestor and explain
which ownership or access check failed (BX-007). Any repair needs a deliberately
selected folder. A blanket permission change would be a fairly efficient way
to create the next problem. This is a proposal, not an implemented repair flow.
