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

GUI builds and interactive input, two-machine TLS sessions, concurrent shutdown,
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
