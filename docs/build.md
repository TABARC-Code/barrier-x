# Build and test

## Linux command-line build

The first verified fork build uses Ubuntu 24.04, GCC 13.3, CMake 3.28.3,
Ninja 1.11.1, GoogleTest/GoogleMock 1.14 and the environment's OpenSSL 3.0.13.
These identify the test environment; they are not a dependency support policy
or a claim that this OpenSSL package is suitable for a new production release.

Install the distribution's development packages:

```sh
sudo apt-get update
sudo apt-get install cmake ninja-build g++ pkg-config libssl-dev \
  libcurl4-openssl-dev libxtst-dev libxrandr-dev libxi-dev \
  libxinerama-dev libgtest-dev libgmock-dev
git submodule update --init ext/gulrak-filesystem
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Debug \
  -DBARRIER_BUILD_GUI=OFF -DBARRIER_BUILD_INSTALLER=OFF \
  -DBARRIER_BUILD_TESTS=ON -DBARRIER_USE_EXTERNAL_GTEST=ON
cmake --build build --target barriers barrierc unittests integtests --parallel 2
ctest --test-dir build --output-on-failure
```

Only the filesystem submodule is needed with external GoogleTest/GoogleMock.
Its tested revision is `614bbe87b80435d87ab8791564370e0c1d13627d` (MIT).
Review dependency sources and scripts before changing revisions. Tests can
be disabled with `BARRIER_BUILD_TESTS=OFF`; that path no longer loads GoogleTest.

The editing environment could not install packages globally. Its build used
distribution packages extracted under a temporary dependency prefix, with
the same project options plus explicit include/library/pkg-config paths.
No temporary dependencies are shipped in the repository.

## Regression coverage

CTest registers the unit suite, a network lifecycle subset, four socket-transfer
integration tests and client/server
`--help`/`--version` checks. Informational commands exit successfully; actual
argument errors still fail. Unit test return codes reach CTest without filtering.

The lifecycle tests cover destruction and repeated close before initialisation,
repeated close after initialisation, rejected reinitialisation, certificate
loading without a context, normal factory creation, failed client/server context
allocation and cleanup after factory failure.

Linux GCC/Clang builds use linker wrapping for deterministic `SSL_CTX_new`,
`SSL_new` and `SSL_set_fd` failures. This changes only the test executable.
Other platforms run the common lifecycle checks but do not claim these
injected-allocation tests.

Before the fix, both `DestroyBeforeInitialisation` and
`ClientContextAllocationFailureThrows` crashed with exit status 139.
The normal unit suite contains 144 tests, including nine lifecycle tests.

Version 2.4.3 adds four TLS-version handshake tests, one POSIX wake-up ownership
test and five non-blocking stream tests (154 unit tests in this Linux build).
The handshake tests use
actual OpenSSL contexts created by `SecureSocket`, connected through paired
memory BIOs. Both roles reject TLS 1.0/1.1 and accept TLS 1.2/1.3. The test
temporarily lowers only its own OpenSSL security levels so version rejection
does not accidentally depend on distribution cipher restrictions. It does not
test pairing, certificate pinning or a real two-machine network session.

The wake-up test verifies that a target thread retains its pipe, the caller's
pipe remains unchanged, writes do not block when full, and both descriptors
close when the target's last reference is released. This follows actual leak
reports from the initial hosted run; leak suppression has not been added.

Non-blocking stream tests cover pipes with data, empty pipes, EOF, invalid
descriptors and restoration of file flags. The integration run exposed an
inherited assertion on EOF from detached stdin, uninitialised terminal state
on non-terminal descriptors and a shadowed saved-flags member; these are fixed.
The four existing network tests passed actual localhost transfers in both
directions. The 2.4.3 network lifecycle subset contains 19 unit tests.

Version 2.4.4 adds deterministic interruption of `poll()` followed by thread
cancellation. Its descriptor array now has automatic lifetime, including when
cancellation throws before normal cleanup. Linux builds contain 155 unit tests
and 20 tests in the network lifecycle subset. The additional linker wrapper
is confined to the test executable.

Version 2.4.5 adds twelve certificate-storage tests (167 Linux unit tests).
They verify a matching RSA-3072 key and SHA-256 self-signature, replacement,
Unicode paths, mode 0600 with a permissive umask, non-inheritable descriptors,
symlink refusal, hardlink preservation and five injected failure points.
Failed operations must preserve the destination and remove their temporary file.
The checks do not dump PEM contents when an assertion fails.

Certificate publication uses an exclusive, randomly named sibling file, checked
PEM writes, flush, file synchronisation, close and rename. This prevents a failed
write from truncating the current identity. It does not promise power-loss
durability for the directory rename, or safety in an untrusted shared directory.
Existing valid identities are not regenerated merely by updating barrier-x.
Their permission migration remains open. Windows uses exclusive CRT creation
with non-inheritable descriptors and retains inherited directory ACLs; Windows
owner-only ACL enforcement and Windows/macOS execution are not yet verified.

Version 2.4.6 adds six session-setup and handshake-retry tests (173 Linux unit
tests, 26 in the network lifecycle subset). Injected allocation and attachment
failures must stop before the handshake, including a repeated attempt. Tests
also reject missing/closed state and preserve a queued memory BIO across retries.
A separate test uses real OpenSSL calls over non-blocking POSIX socket pairs in
both roles, checking WANT_READ retries keep the same attached transport. This
is retry coverage, not a completed two-machine authenticated session. A friend
fixture drives the private handshake entry points synchronously; production
callbacks use the same entry points under the TCP socket mutex.

Version 2.4.7 adds all-provider teardown and concurrent lazy-creation tests
(175 Linux unit tests, 28 in the network lifecycle subset). Each event queue
owns its twenty provider slots, and its mutex serialises first construction.
The concurrency test checks provider identity and event registration; it is not
a ThreadSanitizer result or proof that every queue operation is thread-safe.

## Sanitisers

Use a separate build directory:

```sh
cmake -S . -B build-sanitised -G Ninja -DCMAKE_BUILD_TYPE=Debug \
  -DBARRIER_BUILD_GUI=OFF -DBARRIER_BUILD_INSTALLER=OFF \
  -DBARRIER_BUILD_TESTS=ON -DBARRIER_USE_EXTERNAL_GTEST=ON \
  -DCMAKE_CXX_FLAGS='-fsanitize=address,undefined -fno-omit-frame-pointer' \
  -DCMAKE_EXE_LINKER_FLAGS='-fsanitize=address,undefined'
cmake --build build-sanitised --target unittests --parallel 2
ASAN_OPTIONS=detect_leaks=1 UBSAN_OPTIONS=halt_on_error=1 \
  ctest --test-dir build-sanitised -R '^(ssl-lifecycle|certificate-storage|ipc-framing)$' --output-on-failure
```

The Linux workflow runs Debug and Release builds plus the sanitised lifecycle
subset. It has read-only repository permission, does not retain checkout
credentials, and pins the checkout action by commit. Workflow configuration is
not evidence of a successful hosted run; check the actual run result.

Local result for 2.4.2-snapshot: all 144 unit tests and all six CTest entries
passed. The nine lifecycle tests also passed with AddressSanitizer and UBSan.
LeakSanitizer could not complete process inspection in this environment; that
local run used `detect_leaks=0` after recording the failure. Hosted CI retains
`detect_leaks=1`. A local leak-check pass is not claimed.

The 2.4.2 hosted Debug run found 376 bytes of inherited thread/wake-up storage
leaks. Version 2.4.3 fixes the ownership and reference-counting paths; consult
the new hosted run before treating leak verification as complete.

Verified follow-up: [2.4.3 hosted run 40815018907](https://github.com/TABARC-Code/barrier-x/actions/runs/40815018907)
passed both Debug and Release, including the Debug ASan/UBSan/LeakSanitizer step.
This verifies the tested paths, not all possible thread or network behaviour.

The same checks passed for [2.4.4 run 40815563644](https://github.com/TABARC-Code/barrier-x/actions/runs/40815563644).
The certificate-storage subset is included in hosted sanitiser runs from 2.4.5.
[2.4.5 run 40820964445](https://github.com/TABARC-Code/barrier-x/actions/runs/40820964445)
passed Debug, Release and the sanitised subsets with hosted leak scanning.

[2.4.6 run 40859533634](https://github.com/TABARC-Code/barrier-x/actions/runs/40859533634)
passed normal Debug/Release checks but reported 192 bytes in eight leaked event
providers during the sanitised lifecycle subset. Version 2.4.7 fixes the
inherited ownership and exercises all providers on teardown.

TLS policy API reference:
[OpenSSL minimum protocol version](https://docs.openssl.org/3.0/man3/SSL_CTX_set_min_proto_version/).
Certificate generation reference:
[OpenSSL EVP key generation](https://docs.openssl.org/3.0/man3/EVP_PKEY_keygen/).

TLS session API references:
[OpenSSL session allocation](https://docs.openssl.org/3.0/man3/SSL_new/) and
[descriptor attachment](https://docs.openssl.org/3.0/man3/SSL_set_fd/).

## Outstanding platform checks

Interactive GUI input, two-machine TLS sessions, concurrent shutdown,
Windows/macOS, session/lock-screen behaviour and installers are not covered by
the command-line tests above. Sanitiser coverage is not a security certificate.

## Engine IPC framing

Version 2.4.8 introduces an incremental reader shared by the C++ daemon and
node proxies. It retains partial headers, lengths, bodies and flags between
input-ready events, reads one frame at a time and validates lengths before
buffering payloads. Commands accept at most 65,536 bytes and logs at most
1,048,576 bytes. The latter matches the previous generic protocol limit.
Valid wire formats are unchanged, including empty commands used to stop a node.
Only GUI/node hello values and elevation bytes 0/1 are accepted. Commands
containing NUL are rejected rather than passed to a process-launch boundary.

Thirteen unit regressions cover every split of command/log frames, bytewise
hello, coalesced messages, exact/excess limits, malformed fields and directions,
proxy dispatch/disconnection and both command elevation encodings. CTest also
registers three actual localhost IPC round trips. The IPC unit subset is
included in hosted ASan/UBSan/leak checks.

This does not authenticate callers, authorise process launch, harden the
separate Qt reader or bound aggregate queue/connection resources. Partial
frames remain until completion or disconnection; idle-peer timeouts remain
future work. Windows service execution and the GUI are not validated here.

[2.4.7 run 40860940285](https://github.com/TABARC-Code/barrier-x/actions/runs/40860940285)
passed Debug, Release and sanitised lifecycle/storage tests with leak scanning,
including event-provider teardown.

## Peer approval and certificate ownership

Version 2.4.9 adds five peer-trust regressions (193 Linux unit tests, 33 in the
network lifecycle subset). Controlled handshake completion and reference-counted
certificate retrieval drive the actual socket trust path. Tests use real
self-signed certificates, SHA-256/SHA-1 digests and isolated trust files.
They require matching SHA-256 pins in both authenticated roles, reject missing
or untrusted peers and SHA-1-only trust entries, and inject failure of the
second digest operation. Reference-release counts are checked on success and
rejection, including exception unwinding.

All five tests failed against the previous implementation. Matching-pin tests
also observe readiness during the certificate checks, so merely clearing the
flag after rejection cannot satisfy them. These controls do not exercise real
network authentication, concurrent shutdown or migration of GUI trust settings.
The lifecycle timeout allows for the additional isolated certificate generation.

Ownership reference: [OpenSSL peer certificates](https://docs.openssl.org/3.4/man3/SSL_get_peer_certificate/).
The reference returned by the existing getter must be released; obtaining a
certificate alone does not establish peer approval.

[2.4.8 hosted run 40865885582](https://github.com/TABARC-Code/barrier-x/actions/runs/40865885582)
passed Debug, Release and sanitised lifecycle, certificate-storage and IPC checks
with leak scanning.

## Qt service reader

Version 2.4.10 adds the `gui-ipc` QtTest suite. Enable it with
`-DBARRIER_BUILD_GUI_IPC_TESTS=ON`; it can build independently of the desktop
with Qt Core, Network and Test. Its real localhost sockets run under
QCoreApplication, without a display server. Tests cover every message split,
UTF-8 byte boundaries, empty/coalesced logs, the exact 1 MiB limit, oversized
and high-bit lengths, invalid headers, truncated disconnects, clean reconnects,
start/stop, 64-frame batching and signal handlers that stop or destroy the reader.
The actual GUI client is included in the recovery/error-forwarding tests.

The Linux workflow builds the desktop and GUI unit targets with Qt 5, runs
widget tests using the offscreen platform, and includes `gui-ipc` in the
sanitisers/leak subset. These are build and protocol checks, not an interactive
desktop or Windows service test. The optional service-port constructor parameter
lets tests use an isolated ephemeral port; the normal service port is unchanged.

The old blocking helper has been removed. Framing buffers are reset on connection
changes, socket input uses backpressure, and invalid frames abort without
logging their payload. Retained log-window history is a separate outstanding
resource limit. Caller/service authentication is still BX-003 work.

Qt reference: [socket readiness and blocking calls](https://doc.qt.io/qt-6/qabstractsocket.html).
The implementation is compiled and exercised against Qt 5.15; it does not
require a Qt 6 migration.

The peer-trust follow-up passed hosted Debug/Release and leak checks in
[run 41348051339](https://github.com/TABARC-Code/barrier-x/actions/runs/41348051339).

Local 2.4.10 result: the Linux desktop and engine targets built, all twelve
CTest entries passed, and the Qt socket suite passed ASan/UBSan with local
leak inspection disabled for the documented environment restriction. QtTest
reported 39 passes including suite hooks; the existing GUI suite ran 58 tests
and the engine suite ran 193. Four transfer tests and three IPC round trips
also passed. The existing GUI test registration now resolves its built target
rather than searching for a relative executable.

## Application TLS I/O state

In 2.4.11 I added seven regressions for absent state/session, closure, unapproved
sessions, successful byte counts, retries, fatal errors and invalid arguments.
The Linux linker wrappers count entry to SSL_read/SSL_write; controlled sessions
exercise the production guards and result handling, not real encrypted payloads.
I also seed the thread error queue before successful calls and check it is empty
at OpenSSL entry. The pre-initialisation read crashed against 2.4.10; all four
other selected state/count/argument regressions failed before the fix.

I retained the existing write-buffer retry ownership. OpenSSL requires retries
with the same arguments and does not accept zero-length SSL_write calls:
[write contract](https://docs.openssl.org/3.4/man3/SSL_write/),
[error classification](https://docs.openssl.org/3.4/man3/SSL_get_error/).
Concurrent shutdown and real network payload tests remain separate work.

I built the Linux desktop and engine and passed all twelve CTest entries:
200 engine tests, 58 GUI tests, 39 Qt socket passes including suite hooks,
four transfer tests and three IPC round trips. The 65 lifecycle/storage/IPC
tests passed ASan/UBSan in one process; the Qt socket suite also passed with
sanitisers. Local leak inspection remains disabled because of the previously
recorded process-inspection restriction; hosted CI keeps it enabled.

The workspace produced empty generated objects during linking and later
corrupted executables or removed their execute bits. I removed only malformed
build artefacts, rebuilt them and checked the test output counts. One sanitised
CTest attempt could not launch two subsets; I reran all 65 engine checks in a
single process successfully. I have not checked Windows, macOS or an interactive
desktop in this increment.

## Local management role sequencing

In 2.4.12 I require a single greeting and accept command frames only from the
connection's declared GUI role. Repeated greetings close the stream, including
a second greeting with the same role. Node greetings and valid GUI command
sequences remain supported. These are protocol checks, not caller credentials.

I added five proxy regressions for commands before greetings, node commands,
repeated/changed roles, fragmented greetings and fresh connections. Four
rejection cases failed against the previous proxy; the fragmented valid path
also passed before the change. Four new localhost tests require an actual close
and zero command dispatch. I corrected the existing command round trip to use
a GUI greeting: the engine client advertises a node role and is not a valid
command sender under the documented protocol.

The Linux GUI/engine build and all twelve CTest entries passed: 205 engine
unit tests, 58 GUI tests, 39 Qt socket passes including suite hooks, four
transfer tests and seven IPC socket tests. The 70 targeted engine tests and
39 Qt socket passes also passed ASan/UBSan. I kept local leak inspection disabled
for the recorded process-inspection restriction; hosted leak checks stay enabled.

I reviewed the final diff for rejected-message dispatch, partial state, role
publication, duplicate disconnects and stream ownership. The atomic flags do
not make object teardown safe against arbitrary concurrent callers. No Windows
or macOS execution was available, and I have not checked service tokens, endpoint
ACLs or interactive session changes. See local-management.md for the remaining
credential and saved-command work.

The previous increment passed hosted Debug/Release and leak checks in
[run 41472140694](https://github.com/TABARC-Code/barrier-x/actions/runs/41472140694).

## Windows management credentials

In 2.4.13 I added a standalone Windows SDK harness at src/test/nativeipc.
It compiles the native pipe implementation and six production adapters without
linking the inherited OpenSSL/Bonjour desktop dependencies. The native tests
use real pipe handles and tokens, including a temporary second local user which
is removed afterwards. They also exercise endpoint identity, child registration,
restricted credentials, malformed greetings and cancelled acceptance.

I cross-compiled the native executable and all six integration units with GCC
13.2.0/MinGW. The Linux GUI/engine build passed its unit, socket and GUI checks;
two command-line checks initially could not launch because the workspace removed
the server binary's execute bit. After restoring that bit on the intact ELF,
all four command-line entries passed. The unit suite contains 208 tests, with
73 targeted lifecycle/storage/IPC tests passing ASan/UBSan. The Qt suite reported
39 passes and one explicit skip, also under sanitisers.

Local Unix-domain sockets fail with EPERM (Qt reports unknown error 1). I set
BARRIER_TEST_SKIP_UNIX_SOCKETS=1 only for this environment, so the new local-socket
parser check is not counted as a pass here. Hosted Linux runs do not set that
variable and must execute it. Local leak inspection retains the recorded
process-inspection restriction. The Windows SDK job runs the credential tests;
interactive UAC, installed-service, session-switch and full desktop checks remain
unverified. No complete Windows desktop build is claimed.

The Windows SDK compile and all ten native checks passed in
[run 41480230125](https://github.com/TABARC-Code/barrier-x/actions/runs/41480230125).
The first native run found a fixture error: it restored the administrator token
before writing the supposed restricted greeting. I corrected the impersonation
scope, separated filtered read-only callers from SID-restricted callers, and
verified that the second local user sends while still impersonated. These checks use a foreground
reference token; installed LocalSystem/WTS integration still needs a desktop run.

Hosted Linux Debug/Release and ASan/UBSan with leak scanning passed in
[run 41480229988](https://github.com/TABARC-Code/barrier-x/actions/runs/41480229988).
That run executes the local-socket Qt check without the local skip variable.
The Windows validation branch and final master update share the same code;
only completion evidence and roadmap status were updated afterwards.

## Existing identity permissions and snapshot loading

In 2.4.14 I read identity files through a shared certificate/key loader. On
POSIX it opens with O_NOFOLLOW, O_CLOEXEC and O_NONBLOCK, checks regular-file
status, effective ownership and a single link, and migrates the open file to
mode 0600. A second fstat verifies the result. The same descriptor supplies a
bounded snapshot, so path replacement cannot switch the loaded pair. I parse
both PEM objects from that snapshot and verify that they match before installing
them. OpenSSL 1.1.1+ uses SSL_CTX_use_cert_and_key; older headers retain the two
installation calls after the pair check.

Thirteen new storage cases cover permission migration with preserved bytes and
fingerprints, symlinks, hardlinks, directories/FIFOs, size limits, missing and
mismatched keys, non-interactive encrypted-key rejection, descriptor cleanup,
injected stat/chmod failure and simulated foreign ownership. A rename injected
during fchmod proves the SSL context receives the original open file's pair.
Three engine cases cover mode migration, symlink refusal and clearing handled
crypto errors. Three GUI cases check migration/fingerprint preservation and
error-only completion without replacing a malformed or linked identity.

I reproduced the mode/symlink failures against 2.4.13. During integration, the
encrypted-key failure also reproduced a stale OpenSSL error queue; the loader
now clears its handled errors. The earlier valid identity remains installed
when a replacement pair fails validation.

All twelve Linux CTest entries passed with 224 engine tests, 61 GUI unit tests,
four transfers and seven IPC round trips. The 89 targeted engine checks passed
ASan/UBSan. The Qt IPC suite reported 39 passes and one explicit Unix-socket skip,
also under sanitisers, because this environment denies that socket type. Local
leak inspection remains disabled for the recorded restriction; hosted checks
keep it enabled. No new dependencies or third-party code were imported.

Windows continues to depend on directory ACLs for private-key access, and its
storage behaviour and macOS storage have not been exercised here. The parent
identity directory must be trusted. Existing unreadable mode-0000 files may
require the owner to correct access manually before opening; I do not fall back
to pathname chmod. Certificate-only public fingerprint utilities retain their
existing behaviour. The engine's optional client-certificate policy is unchanged.

References: [Linux fchmod semantics](https://man7.org/linux/man-pages/man2/fchmod.2.html)
and [OpenSSL certificate/key installation](https://docs.openssl.org/3.4/man3/SSL_CTX_use_certificate/).
The previous master passed Linux checks in
[run 41481373455](https://github.com/TABARC-Code/barrier-x/actions/runs/41481373455)
and Windows native IPC checks in
[run 41481373489](https://github.com/TABARC-Code/barrier-x/actions/runs/41481373489).


## Windows identity file ACLs (2.4.15)

I create private identity files with an explicit user owner and protected
owner/LocalSystem DACL, without handle inheritance or sharing. Existing files
open with reparse traversal disabled and READ_CONTROL/WRITE_DAC; the reader
checks ownership, disk-file attributes, link count and size before applying and
verifying the ACL. The same handle becomes the CRT descriptor for PEM input.
I tested permission migration without changing the file contents. A rename
replacement retains the newly created file's protected ACL.

The SDK harness now includes fourteen storage checks: creation in a deliberately
public test folder, migration, collision preservation, hardlinks, symlinks,
directories, the size cap, concurrent writes/renames, replacement, alternate
streams, failed permission changes, a pre-existing writer, extended paths and
another local user. The extra account cannot read the private file; its own
publicly accessible file is rejected by the owner check. The denial fixture
must first prove WRITE_DAC is refused, so an unrelated open failure cannot pass
that assertion. The first denial fixture lacked READ_CONTROL on its setup
handle; that fixture failed before reaching production code and was corrected.

The Linux GUI/engine build and all twelve CTest entries passed locally: 224
engine units, 61 GUI units, four transfers and seven IPC round trips. The Qt
IPC suite reports 39 passes and one explicit Unix-socket skip, since the local
environment denies that socket type. The new Windows helper and its tests also
cross-compile as C++14 with MinGW, including -Wall -Wextra -Werror.

Full Windows desktop linking, PEM integration, installed-service console-user
transitions and macOS storage remain unverified. LocalSystem's extra owner
allowance requires WTSQueryUserToken to succeed; it never accepts an arbitrary
other owner. Legacy files owned by Administrators or another account require
explicit ownership repair. The parent directory must remain trusted. ACL
migration cannot undo earlier disclosure or revoke an existing handle. The
empty temporary file is marked for deletion if a post-creation check fails;
no key is written before the permission check. No dependency or third-party
source was added.

References: [CreateFileW](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew),
[SetSecurityInfo](https://learn.microsoft.com/en-us/windows/win32/api/aclapi/nf-aclapi-setsecurityinfo),
[WTSQueryUserToken](https://learn.microsoft.com/en-us/windows/win32/api/wtsapi32/nf-wtsapi32-wtsqueryusertoken)
and [CRT handle ownership](https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/open-osfhandle).

The final native candidate passed all fourteen file checks and ten existing
pipe checks on Windows 2025 in
[run 41719122150](https://github.com/TABARC-Code/barrier-x/actions/runs/41719122150),
commit `ecfe92e51bd777a2b67e276a9e9bdab5b91aa1bb`. The service adapters also
compiled with the Windows SDK. A strict MinGW compile of SecureUtils.cpp was
blocked by function-pointer conversions in the inherited OpenSSL 1.0.2 applink
C shim. The translation unit compiled with -fpermissive, with warnings from that
shim; this does not establish full Windows application linkage or replace the
old TLS dependency. The new helper/tests compile without that relaxation.
Hosted Linux candidate checks were still queued or running at publication;
the local Linux results above are completed checks.


## LocalSystem storage checks (2.4.16)

I added `native-service-private-files` to the existing Windows SDK harness.
It installs a uniquely named, demand-start test service as LocalSystem and
verifies that SID before touching the dummy identities. The service exercises
its own key creation/read, the runner user's key against the actual console
identity, foreign ownership, failed WTSQueryUserToken lookup and denied
WRITE_DAC. Dummy bytes must survive permission failures unchanged. The foreign
fixture has explicit owner/System access so the check reaches ownership
validation rather than passing because the file could not be opened.

The token-failure case temporarily disables SeTcbPrivilege and verifies the
query fails before requiring the reader to refuse access. The previous token
privileges are restored. The denial fixture uses OWNER RIGHTS because owners
otherwise receive implicit WRITE_DAC. The fixture directory is restricted to
the caller and System before the privileged service starts. The service result
comes from SCM status; no result file, key material or account password is logged.
I mark the service for deletion after starting it, close its handle after it
stops and check that its registration disappears. The second local account is
also deleted explicitly, with fallback cleanup on failure.

Console-user acceptance is conditional on a matching active console token.
The executable prints an explicit skip when that positive case is unavailable,
and still checks refusal. A skipped positive case is not evidence of successful
console-user access. This suite uses the real SCM and WTS APIs, without replacing
those calls or changing the production access policy. It does not run the full
Barrier service, engine or GUI, and it does not simulate interactive logout,
lock/unlock, UAC or user switching. Those checks remain open, as does replacing
the inherited Windows OpenSSL dependency. Native execution requires Windows;
these tests run on the hosted Windows 2025 runner.

References: [WTSQueryUserToken](https://learn.microsoft.com/en-us/windows/win32/api/wtsapi32/nf-wtsapi32-wtsqueryusertoken),
[LocalSystem account](https://learn.microsoft.com/en-us/windows/win32/services/localsystem-account)
and [DeleteService lifetime](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-deleteservice).

The final Windows candidate, `fedf3f124733925df8d13dceb296af1be1fa165e`,
passed all three native CTest entries in
[run 42149125814](https://github.com/TABARC-Code/barrier-x/actions/runs/42149125814):
ten pipe checks, fourteen file checks and five service scenarios. The active
console-user read passed on this runner, with no positive-case skip. The six
existing service integration units also compiled. Earlier candidate failures
were in the denial and inherited-access fixtures; the final assertions still
require the intended access or rejection, with no production policy relaxation.
Hosted Linux checks for the final candidate were still queued at publication.
No local Linux build is claimed for this change.


## Windows engine TLS route (2.4.17)

I build OpenSSL 3.5.9 from its checksum-pinned release archive and Google Test
1.15.2 from its pinned commit. The Windows workflow then configures the full
engine with external SDKs and imported targets. It checks old OpenSSL rejection,
installer refusal and retired batch-helper exit codes before the positive build.
The old Windows Azure download job is disabled. The new dependency cache uses an
exact runner image/script key, with no prefix fallback.

I read OpenSSL's Configure and Windows makefile entries, the Google Test CMake
entry points/utilities and the cache action's restore/save source and metadata.
Source hashes, licences, support/advisory references and review limits are in
[dependencies.md](dependencies.md). OpenSSL's upstream test suite is not run by
this helper; the application suites test integration. The loaded-version assertion
covers libcrypto. It doesn't verify every provider or runtime DLL's hash.

The first Windows candidate built both dependencies, then failed because the
hosted CMake had removed compatibility below 3.5. The baseline is now 3.20;
no compatibility flag hides that failure. The cache retains the checked SDKs
while the engine changes are verified.

This is an x64 Release engine route. Qt, discovery, desktop interaction, Debug
Windows validation, installer deployment and interactive session changes remain
open. Local execution is Linux; no local Windows build is claimed. The final Linux candidate passed Debug and Release builds, including the GUI.

The final Windows engine candidate, `1333aafd920fc570d275a3c310639b53b8603141`,
passed all ten CTest entries in
[run 42264522552](https://github.com/TABARC-Code/barrier-x/actions/runs/42264522552).
The client, server and service linked against the external SDK; the runtime
command reported OpenSSL 3.5.9. Unit, SSL lifecycle, certificate storage, IPC
framing/round trips, transfers and four client/server entry-point checks passed.
The old SDK, installer and retired helper rejection checks passed before the
positive build. CMake/GMock migration also exposed Windows min/max macro clashes
and an invalid matcher downcast; NOMINMAX and a checked frame matcher fix those.
The separate native suite passed all twenty-nine checks in
[run 42264522574](https://github.com/TABARC-Code/barrier-x/actions/runs/42264522574).

Windows failure-injection cases which rely on Unix linker wrapping remain
unavailable in this route. Linking the service isn't an installed desktop test;
those limits above still apply. No Deskflow or Input Leap source was copied or
executed: their inspected Qt/deployment patterns are recorded as proposals in
the working plan, with pinned source links and licence constraints.

The same final candidate passed Linux Debug/Release and the Debug ASan/UBSan
checks with leak detection enabled in
[run 42264522576](https://github.com/TABARC-Code/barrier-x/actions/runs/42264522576).
Both normal configurations passed twelve CTest entries; the sanitised job passed
its four selected entries. I reviewed the final diff after those results. The
implemented version is 2.4.17-snapshot; the working plan keeps Windows GUI,
Debug, packaging and interactive desktop checks open.


## Optional GUI discovery, 2.4.18

I checked candidate `ad1b6e85867096263581687019f3db0f16da54e2` in
[Linux run 42336093923](https://github.com/TABARC-Code/barrier-x/actions/runs/42336093923).
Debug and Release each passed thirteen CTest entries. The Debug job also built
the GUI with `BARRIER_BUILD_DISCOVERY=OFF`, passed its five widget tests and
checked that the executable had no DNS-SD runtime link. The enabled build's
five discovery tests include lifecycle dispatch with substituted availability
and twenty real localhost listener lifetimes. They don't establish real
Bonjour browsing, daemon recovery or automatic application startup. The Debug
ASan/UBSan job also passed its four selected network, storage and IPC entries
with leak detection enabled; it does not sanitise the new discovery widgets.

The same candidate passed the ten Windows engine CTest entries in
[run 42336093965](https://github.com/TABARC-Code/barrier-x/actions/runs/42336093965)
and the three native suites in
[run 42336093963](https://github.com/TABARC-Code/barrier-x/actions/runs/42336093963).
These Windows jobs don't build the GUI. Windows/macOS GUI execution, a
supported Qt SDK, live daemon failure handling and installer deployment remain
open. No dependency was upgraded or imported in this change.
