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


## Local control-panel checks, 2.4.19

I build the updated Qt GUI on Ubuntu 24.04 with Qt 5.15.13 and CMake 3.28.3.
The eleven GUI discovery/control-panel cases pass with DNS-SD enabled and disabled.
Six new cases cover visible guidance, connection/language/role changes, single
Stop dispatch, running-role trust context, copy controls, fingerprint clearing, keyboard traversal and
window growth. I render the actual Qt window offscreen at 100% and 150% scaling;
this is a layout check, not an interactive desktop accessibility assessment.

The broader Debug run passes twelve of thirteen CTest entries. The IPC binary
initially lacks its executable bit; after repairing that local build artefact,
its local Unix-socket listener is denied with `QLocalServer::listen: Unknown
error 1`. An independent Unix-socket probe also fails with errno 1, Operation not permitted.
Its other thirty-nine QtTest cases pass. I don't count that suite as
a pass or alter the transport to accommodate the environment.

The host also denies AF_NETLINK interface enumeration. The address-copy test
therefore checks the unavailable/disabled path here; copying a real populated
interface list still needs desktop validation. Actual public SHA-256 copying
and clearing are exercised against a temporary generated identity. No Windows
or macOS build, release build or sanitiser run is claimed for this change.


## Local peer-approval checks, 2.4.20

I build the GUI and pass all fifteen control-panel/approval cases in both
discovery modes on Linux Qt 5.15.13. Four new cases cover Return/Escape rejection,
explicit approval, full public fingerprint copying without a decision, malformed
SHA-256 refusal and server/client wording. Return also rejects after focus moves
to Trust. The actual dialog renders without clipping at 100% and 150% scaling.

A restored client object was unreadable in the enabled-discovery build. I remove
that generated object/archive and rebuild before counting the successful run.
The earlier Unix-socket restriction remains documented above; I don't rerun or
claim a clean full-engine, sanitiser or native Windows/macOS check for this step.


## Local identity recovery, 2.4.21

I build the GUI and pass 64 GUI unit tests plus 17 control-panel/approval tests
in each discovery mode on Linux Qt 5.15.13. New checks cover failed public-file
publication and retry, weak-key preservation, a public-file symlink to the
identity, stale-value clearing and rebuilding a missing public snapshot without
changing the key. An actual offscreen window shows the error and Retry action.

One generated object was empty and caused a link failure. I remove that object
and rebuild before counting the manual-only run. No native Windows/macOS, full
engine or sanitiser pass is claimed for this step. Short writes, commit failures
and parent-path races have not been injected. The earlier IPC/environment
restrictions remain recorded above.


## Local dashboard checks, 2.4.22

I build both discovery variants and pass 64 GUI unit tests plus 22 dashboard
and approval tests in each. New checks cover navigation without engine actions,
retained configuration modes and saved page/geometry, preferences acceptance
and cancellation, global identity recovery, keyboard traversal and small-window
scrolling. A renamed computer refreshes after preferences are accepted.

I check actual Qt renders at normal and 150% scaling. The default connection
page needs no sideways scrolling, and expanded identity details remain reachable
in a 640×480 window. Platform fonts and colours are retained. The screen editor
and preferences still use their existing dialogs.

Generated build artefacts again needed repair: empty objects and lost execute
permissions produced link/start failures. One empty test object registered zero
cases; I don't count that apparent pass. The final runs verify actual case
counts. The reload fixture also needed its unfinished-wizard state restored so
it stayed offline instead of entering a live Avahi error dialog. These checks
don't validate real provider startup. Native Windows/macOS, screen readers,
full-engine and sanitiser checks remain open for this iteration.


## Local peer trust checks, 2.4.23

9 November 2026. I build the GUI with discovery both disabled and enabled on
Linux Qt 5.15.13. In each build I pass 75 GUI unit tests and 25 dashboard/approval
tests, checking actual case counts rather than CTest's summary alone.

Eleven new storage checks cover missing files, merged and duplicate approvals,
legacy records and CRLF, malformed/unknown entries, the 1 MiB limit, lock failure
and retry, invalid approval data, directories, links, writable permissions and
FIFOs. Three dashboard checks cover failed-save recovery without reconnecting,
malformed-file rejection and another approval saved while the dialog is open.
The reconnect seam counts requests without launching an engine.

I review the final source diff and pass the whitespace check. Parent-directory
races, non-cooperating writers, injected short-write/commit failures, native
Windows/macOS GUI and Windows trust-file creation ACLs remain unverified. I
haven't run the full engine or sanitiser suites for this change. The first build
of the additional modal-dialog regression exposed a const mismatch in its test;
I fix that before the final runs.

The published 2.4.22 Linux, Windows engine and Windows native jobs succeeded
(runs 42444844127, 42444844092 and 42444844071). Those results belong to the
published head, not this local update. No new platform CI run is claimed.


## Local Windows replacement checks, 2.4.24

9 November 2026. I rebuild both Linux GUI discovery variants and pass 75 GUI
unit tests plus 25 dashboard tests in each. These runs exercise the retained
POSIX path and the integration around approval; the Windows replacement helper
is excluded by preprocessing and is not validated by these passes.

The Windows harness now registers seventeen file scenarios, including three
new replacement scenarios. Existing cases also exercise refusal of linked,
foreign, busy, denied and alternate-stream targets. Service cases additionally
check System-owned replacement and refusal to replace a console-owned file.
These changed native checks cannot run in the local Linux workspace; the
hosted results below supersede that platform blocker.

I attempt to configure `src/test/nativeipc`; CMake stops with
`These checks require Windows tokens and named pipes`. This Linux workspace has
no Windows SDK compiler or runtime. Native validation runs on the Windows runner instead. Windows Qt integration
and injected I/O failures still need checking before merging this update to master.
Parent-directory anchoring remains open.

The manual-only build again contains empty generated objects, first for
ActionDialog and then NewScreenWidget. I remove those stopped-build artefacts
and rebuild before the final runs. Both suites register their expected case
counts, and the final whitespace check passes.


## Hosted Windows storage checks, 2.4.24

9 November 2026. On test commit `1f21f179f4b9d920e49b813cc223b662c27fb43e`,
[Windows native run 42564987233](https://github.com/TABARC-Code/barrier-x/actions/runs/42564987233)
compiles the SDK adapters and passes all three CTest entries: ten pipe checks,
seventeen storage scenarios and five temporary-service scenarios. I inspect the
individual case output, including replacement creation, failed publication and
cleanup, exact/over size limits and the active console user's key. No new native
failure needs a source fix.

This validates the helper with actual Windows file permissions and rename
behaviour. It doesn't build the Qt GUI or prove parent-directory anchoring,
arbitrary I/O failure handling, crash durability or installed-service session
transitions. The test branch leaves master unchanged.


## Hosted engine and Linux checks, 2.4.24

On source commit `1f21f179f4b9d920e49b813cc223b662c27fb43e`, Windows engine
run 42564987082 builds x64 Release and passes all ten CTest entries with
OpenSSL 3.5.9. Linux run 42564987085 passes all thirteen CTest entries in both
Debug and Release, the manual-only dashboard's twenty-five cases, and the four
selected ASan/UBSan entries for SSL lifecycle, certificate storage, IPC framing
and Qt IPC. I read the individual job results and logs. These results belong
to 2.4.24; they don't validate later source changes.


## POSIX trust-directory checks, 2.4.25

9 November 2026. I build the GUI in both discovery modes on Linux Qt 5.15.13
and pass 84 GUI unit tests plus 25 dashboard tests in each. The trust suite now
contains twenty cases, nine added for this iteration. I verify actual registered
counts, not just CTest's exit code.

The added cases cover a linked folder, group-write refusal and deliberate repair,
a missing folder, embedded NUL, simulated foreign ownership, and injected write,
zero-write, permission, flush and rename failures. Short writes and EINTR retry
successfully; replacement descriptors carry close-on-exec. Failure cases keep
the old approval bytes and remove their pending files.

A deterministic rename during flushing is detected before publication. Another
rename injected immediately at renameat proves that publication stays in the
held folder while an independently approved replacement folder remains intact.
The moved folder can retain Qt's old lock file. These tests deliberately don't
claim that every concurrent directory rename is detected.

I correct the test link flags after adding fstat wrapping while the initial
build is already running, then rebuild before counting the final passes. The
wrappers are linked only into Linux GUI unit tests, not the application or
other platforms. Windows Qt/macOS builds, earlier ancestor traversal, directory
crash durability and non-cooperating writers remain unverified. I don't claim
new hosted or sanitiser results for 2.4.25.


## Qt portability and input diagnostics, 2.4.26

10 November 2026. I configure and compile the complete manual-only GUI, engine
and tests with GCC 14.2, Qt 5.15.15 and Google Test 1.15 on Debian 13. The SDK
headers and tools are extracted into a user-owned prefix from signed Debian
package indexes; I don't install them over the system runtime.

The GUI passes 84 unit cases and 29 dashboard cases, including retained modifier
overrides and rejection of forged drag coordinates, oversized/truncated frames
and hostile collection lengths. Names/aliases containing configuration syntax
are refused; external copies cannot replace occupied tiles, and internal moves
require the current source payload. The engine unit suite has 225 cases, including
a check that two different characters produce identical mapping diagnostics
with character values absent. This doesn't promise that event timing or failure
metadata carries no information. Native Windows/macOS input capture still needs
validation.

The first full CTest run passes twelve entries and fails the Unix transport case
because this workspace refuses AF_UNIX socket creation with EPERM. The reader
suite passes 39 cases with that one environment-limited case explicitly skipped
using its existing test switch. The hosted jobs must exercise it without that
switch. No new sanitiser result or Qt 6/native platform pass is claimed here.

The native jobs build pinned Qt source with the recorded upstream security
fixes rather than fetching an SDK through the rejected archive extractor. They
remain unverified until their actual results are recorded. Master stays unchanged.


## Shutdown and SDK correction, 2.4.27

10 November 2026. I pass five new shutdown cases with GCC 14.2 and system
OpenSSL 3.5.7: four callers repeatedly close one socket, and each connection
role performs real memory-BIO TLS reads/writes while two closers wait. The
I/O wrapper pauses before the actual OpenSSL call, then releases it; this
checks release ordering without pretending to be a real network test.

I configure a separate Debug engine build with
`-DCMAKE_CXX_FLAGS='-fsanitize=thread -fno-omit-frame-pointer'` and
`-DCMAKE_EXE_LINKER_FLAGS='-fsanitize=thread'`, then run
`unittests --gtest_filter='SecureSocketTests.*Concurrent*'` with
`TSAN_OPTIONS=halt_on_error=1`. The initial run finds a logger localtime race.
After changing to per-call time storage, all five cases pass without
suppressions. I retain the gate timeout and release/join cleanup on worker
creation failure. Concurrent destruction is outside the supported lifetime.

The complete local manual-only build passes all thirteen CTest entries: the
unit suite has 230 cases; the lifecycle selection has 48; GUI units have 84;
the dashboard has 30, including a non-Latin translated-default regression.
The reader passes 39 cases with the single Unix-domain listener case explicitly
skipped because this workspace denies AF_UNIX creation. That limitation is
unchanged; I don't turn an environment skip into native transport evidence.

I pass the SDK shallow-history regression and apply the three real pinned Qt
fixes cleanly to the pinned base. The only production changes are the reviewed
CBOR and two HTTP source files. Workflow syntax checks pass. Native SDK
compilation still needs a successful run.

For the published 2.4.26 commit afbbf860, Linux run 42754926799 passes Debug
and Release (thirteen CTest entries each), the manual dashboard's 29 cases and
the four selected ASan/UBSan entries. Windows engine run 42754926831 passes
its ten engine entries before failing in SDK patch application; macOS run
42754927449 also stops at that step, before application compilation. Windows
native run 42754926728 reports success. These results don't validate 2.4.27.


## POSIX GUI ancestor checks, 2.4.28

10 November 2026. I build the manual-only GUI, engine and tests on Debian 13
with GCC 14.2 and Qt 5.15.15. All thirteen CTest entries pass; the GUI unit
suite has 95 cases, including 31 peer-store cases, and the dashboard has 30.
The reader passes 39 cases with its one Unix-domain listener case explicitly
skipped because this workspace denies AF_UNIX creation.

Eleven new peer-store cases cover unsafe earlier ancestors, creation with an
open umask, explicit parent traversal, checked absolute/relative intermediate
links, unsafe link targets and loops, user-owned sticky ancestors, simulated
foreign link ownership, failed mkdirat, replacement between inspection/open,
changed ancestor permissions before publication, and descriptor release after
256 rejected operations. Existing publication/cleanup failure cases still pass.

In a separate ASan/UBSan GUI build, all 31 peer-store cases pass with
`ASAN_OPTIONS=detect_leaks=0` and `UBSAN_OPTIONS=halt_on_error=1`. The initial
run with leak scanning enabled finishes the cases but LeakSanitizer stops with
`LeakSanitizer does not work under ptrace`. I don't claim a leak-scan pass. The
Linux descriptor-count regression passes separately; it isn't a heap leak scan.

The SDK patch-extraction regression, Python compilation and final whitespace
checks pass. Automatic Git maintenance is disabled only in the disposable
Qt source checkout. Full patch object IDs and disabled external diff/text
conversion drivers pass the updated extraction regression. Successive native
SDK jobs queue so an active validation can finish. Native Qt builds remain
a separate validation requirement.

For preceding commit 3cd43a22 (2.4.27), Linux run 42755993990 passes thirteen
CTest entries in Debug and Release, the manual dashboard's thirty cases and
the four selected ASan/UBSan entries. Windows native run 42755993945 passes
its three entries, including the pipe, storage and temporary-service cases.
macOS run 42755993808 stops during Qt source fetching after the first patch,
before Qt or application compilation. These hosted results don't validate
2.4.28 or close the remaining native GUI checks.


## Native SDK settings, 2.4.29

10 November 2026. macOS run 42758568071 builds and installs the pinned, patched
Qt 6.12 SDK, then application linking fails with `ld: library 'c++' not found`.
I inspect the link command: the inherited empty --sysroot argument consumes
the following legacy Google Test definition. I remove the manual compiler-flag
assignment and select CMAKE_OSX_SYSROOT=macosx in the native job.

Windows run 42755993932 fails while building Qt's Windows platform plugin: an
OpenGL-disabled configuration still references QOpenGLStaticContext and
QOpenGLContext in qwindowswindow.cpp. I enable the SDK OpenGL feature on
Windows. The SDK provenance file now records its configure options. Corrected
Windows/macOS application and runtime checks remain unverified.

Locally, I configure and build the complete Qt 5 manual-only GUI, engine and
tests with GCC 14.2 on Debian 13. All thirteen CTest entries pass, including
95 GUI unit and 30 dashboard cases. The reader passes 39 cases with the same
single Unix listener case explicitly skipped because this workspace denies
AF_UNIX creation. The SDK patch-extraction regression, Python compilation,
workflow syntax and final whitespace checks pass. No native or new sanitiser
pass is claimed for 2.4.29.

For preceding commit 2bcf2971 (2.4.28), Linux run 42758567762 passes thirteen
CTest entries in both Debug and Release, the manual dashboard's thirty cases
and four selected ASan/UBSan entries. Windows native run 42758567687 passes
its three entries, including the file replacement and temporary-service cases.
These results establish the earlier checks, not the corrected native GUI build.


## Qt 5/6 API compatibility, 2.4.30

10 November 2026. Both native 2.4.29 jobs finish SDK construction and reach
GUI compilation. Windows run 42761402300 and macOS run 42761402295 reject
Qt::MidButton, the char16_t QString::arg call and SystemLocaleLongDate. I
replace those uses with APIs accepted by both supported Qt majors.

I configure fresh manual-only Debug builds on Debian 13 with GCC 14.2,
Qt 5.15.15 and Qt 6.8.2 from signed Debian packages extracted into a user-owned
prefix. The complete GUI, engine and test targets compile under both majors.
Two new cases preserve middle mouse as 3 and Unicode code units as four-digit,
lower-case hexadecimal. The GUI suite contains 97 cases and the dashboard 30.

The local reader's Unix-domain listener case is explicitly skipped because
creating AF_UNIX sockets returns EPERM in this workspace. The other reader
cases run. The Debian Qt 6 package is a compatibility tool with unresolved
tracker issues, not a replacement for the pinned patched native SDK. Native
Windows/macOS runtime and packaging checks remain unverified.

Each fresh local Qt-major build passes all thirteen CTest entries. After the
first Qt 6 pass exposes a removed socket-error signal, I use typed errorOccurred
connections and add a real connection-refused case. The final reader runs report
40 passes and one environment skip. The Unix listener skip remains explicit;
these runs don't validate the Windows service transport or native desktop.


## Checked identity-read ancestors, 2.4.31

10 November 2026. I configure the shared POSIX directory helper into the io
library and build the complete Qt 6 manual-only GUI, engine and test targets
with GCC 14.2 on Debian 13. All thirteen CTest entries pass. The engine suite
contains 236 cases, the selected SSL lifecycle suite 48, certificate storage 31,
GUI units 97 and dashboard 30. Selected suites overlap the engine suite; these
aren't additive totals. The reader reports 40 passes and one explicit Unix
listener skip because this workspace denies AF_UNIX socket creation.

I also build and run all 97 Qt 5 GUI unit cases against the shared helper.
All 31 certificate-storage cases pass in a fresh engine-only ASan/UBSan build
with leak detection disabled. This is address/undefined-behaviour evidence,
not a new heap-leak or thread-sanitiser pass. Both local Qt packages are the
compatibility-only Debian SDK described above, not shipping dependencies.

Six new cases cover unsafe earlier ancestors before identity-mode migration,
a linked final folder, a safe intermediate link, embedded NUL/explicit parent
traversal, missing parents and parent replacement during file inspection.
The replacement case preserves the new path's file bytes and mode, retains
the old identity bytes and checks the reader's descriptor closes on refusal.
The GUI trust-store regressions exercise the same extracted traversal code.

I review the final source diff and version declarations; whitespace checks
pass. The 2.4.30 native Windows helper job 42863324722 passes. Its Windows
GUI job remains in progress and macOS is queued at this checkpoint; neither
validates this iteration. Windows parent handling, macOS extended ACLs,
identity creation/publication, engine trust loading and installed desktop
behaviour remain open. The test branch remains separate from master.
