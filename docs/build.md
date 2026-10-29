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
cmake --build build --target barriers barrierc unittests --parallel 2
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

CTest registers the unit suite, an SSL lifecycle subset and client/server
`--help`/`--version` checks. Informational commands exit successfully; actual
argument errors still fail. Unit test return codes reach CTest without filtering.

The lifecycle tests cover destruction and repeated close before initialisation,
repeated close after initialisation, rejected reinitialisation, certificate
loading without a context, normal factory creation, failed client/server context
allocation and cleanup after factory failure.

Linux GCC/Clang builds use linker wrapping for deterministic `SSL_CTX_new`
failures. This changes only the test executable. Other platforms run the common
lifecycle checks but do not claim these injected-allocation tests.

Before the fix, both `DestroyBeforeInitialisation` and
`ClientContextAllocationFailureThrows` crashed with exit status 139.
The normal unit suite contains 144 tests, including nine lifecycle tests.

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
  ctest --test-dir build-sanitised -R '^ssl-lifecycle$' --output-on-failure
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

## Outstanding platform checks

GUI builds and interactive input, two-machine TLS sessions, concurrent shutdown,
Windows/macOS, session/lock-screen behaviour and installers are not covered by
the command-line tests above. Sanitiser coverage is not a security certificate.
