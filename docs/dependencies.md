# Dependency notes

6 November 2026. This is a review of the build inputs touched by the Windows
TLS work. I haven't audited every library or the complete application.

| Input | Selection | Use and remaining work |
| --- | --- | --- |
| OpenSSL | 3.5.9, commit `45e844fa2a14ec92d146bd8f5778ac130b6625fb` | Windows engine SDK, built from the official release archive. CMake requires 3.5 LTS at 3.5.9 or later. Runtime packaging is still blocked. |
| Google Test / Google Mock | 1.15.2, commit `b514bdc898e2951020cbdca1304b75f5950d1f59` | Windows test builds only. This revision supports the project's C++14 code. Linux uses its packaged test libraries. |
| gulrak filesystem | Submodule `614bbe87b80435d87ab8791564370e0c1d13627d` | Existing filesystem dependency; unchanged here. Parent traversal hardening remains BX-004. |
| Qt and DNS-SD | Existing platform selections | Qt is unchanged. DNS-SD is optional from 2.4.18; OFF omits its GUI sources and libraries. Supported Qt versions, SDK licences/advisories and Windows GUI integration still need checking. |
| GitHub cache action | `caa296126883cff596d87d8935842f9db880ef25` | Build acceleration only. I pin the revision and use an exact image/script cache key, without fallback keys. |

## What I checked

I checked the OpenSSL 3.5 release notes, support policy and published advisories.
The 3.5.9 release includes the September security fixes. The build script verifies
SHA-256 `603f5602e2eef00d77fbd429d34dcd5822bb301757a1bc9cdb24c670f1eb859a`
before extracting its release archive. An unexpected hash stops the build.

I read the selected OpenSSL Configure/Windows build entries and the Google Test
CMake entry points, including their utility module. I also checked the cache
action's restore/save source and metadata. I didn't find an unexpected download
or installation hook in those entry points. That's a limited source review,
not a malware-free guarantee for every transitive tool or generated bundle.
The runner's compiler, Perl and NASM remain hosted image inputs.

OpenSSL uses Apache-2.0; the existing root licence explicitly permits compiling,
linking and using OpenSSL. Google Test uses the BSD three-clause licence, and
the cache action uses MIT. I retain those upstream references. I'd still like
external review of the complete distribution's notices and licence combinations
before publishing an installer, particularly after choosing the Qt/discovery SDKs.

## What remains open

The runtime assertion checks loaded libcrypto's version. It doesn't identify
every libssl/provider binary or establish their hashes. Packaging needs a runtime
manifest, checked DLL/configuration search paths and a clean-machine exercise.
The historical OpenSSL files remain in the source tree, but the Windows CMake
path no longer selects them and refuses the installer that would package them.
I also retire the batch helpers and disable the old Azure Windows download job.

[OpenSSL releases](https://openssl-library.org/source/),
[3.5 advisories](https://openssl-library.org/news/vulnerabilities-3.5/),
[release policy](https://openssl-library.org/policies/releasestrat/),
[Google Test source](https://github.com/google/googletest/tree/b514bdc898e2951020cbdca1304b75f5950d1f59)
and the [working plan](working-plan.md).


## Native Qt checks, 2.4.26

I select Qt 6.12.0 for the new Windows and macOS jobs. The documented Windows
configuration uses MSVC 2022; macOS needs Xcode 16/macOS 15 SDK or newer and a
14.4+ deployment target. I use macos-15, not the retired macos-14 runner.
Qt 5 remains explicitly selectable for comparison; this isn't a claim that an
unpatched Qt 5 SDK is suitable for release.

I review install-qt-action's manifests and source/compiled entry points, but do
not execute it: its proposed py7zr 1.1.0 extractor is affected by an upstream
arbitrary-write advisory. The native jobs instead use the standard-library
builder in ci/qt-sdk.py, with Qt base commit
025bdad181de241e81bf853c8a2d7bf3d19261a9 and production changes from
these upstream fixes, in order:

- a2cd9d2a70575c37153d43e9c5396a9144af1923, CVE-2026-105924.
- aac1d303c0329241ac59c0c23cb5e4b82251fcfa, CVE-2026-116337 header limits.
- f78a3740281d26af7116517a2b20df36f8deffd7, CVE-2026-116337 status limits.

I read the Qt CMake/configure entry points and all three production fixes against
the maintainer's advisory patches. The builder checks the source revision,
checks patch application, records inputs and retains Qt's licence files. There
is no Python archive installer or resolver in this path. This remains a limited
entry-point review, not an audit of every Qt source file. Native toolchains and
Homebrew package inputs remain hosted build inputs.

Qt Core/Gui/Widgets/Network/Test licensing and deployment notices must accompany
redistribution. Native build success alone doesn't settle downstream licensing,
SDK advisories or a clean-machine installation.


The first 2.4.26 native SDK jobs fail before Qt configuration: fetching a fix at
depth one makes `git show` treat it as a root commit. In 2.4.27 I fetch its parent
and explicitly diff parent to fix. A local regression reproduces the shallow
case and checks that unrelated source stays untouched. I also fetch the actual
three pinned fixes and apply them cleanly to the selected Qt base: only
qjsoncbor.cpp, qhttpheaderparser_p.h and qhttpnetworkreply.cpp change. This is
patch-application evidence, not a successful SDK compilation.

For SSL ownership I recheck the official [OpenSSL threading guidance](https://docs.openssl.org/3.5/man7/openssl-threads/):
shared sessions need application synchronisation. The socket retains one lock
for session access and release; atomic status flags do not replace that lock.


In 2.4.27, macOS run 42755993808 applies the first actual Qt patch, then Git
stops with `shallow file has changed since we read it` during the next fetch.
This is consistent with the upstream [background-maintenance race](https://github.com/actions/checkout/issues/2437).
In 2.4.28 I set maintenance.auto=false inside the disposable SDK repository
and pass the documented [--no-auto-maintenance fetch option](https://git-scm.com/docs/git-fetch).
I keep source pins and patch validation unchanged. This correction doesn't
establish that the native SDK or application compiles successfully.

I also use complete blob IDs for patch headers and disable external diff/text
conversion drivers and colour. Git's automatic object-ID abbreviation changes
as the object database grows; it shouldn't change the recorded patch digest.
The extraction regression sets a short abbreviation and an external diff
command which must not execute, then checks the complete IDs and applied bytes.


For 2.4.29 I check the current [CMake macOS sysroot guidance](https://cmake.org/cmake/help/v4.0/variable/CMAKE_OSX_SYSROOT.html)
and [Qt 6.12 Windows graphics documentation](https://doc.qt.io/qt-6.12/windows-graphics.html).
I remove the inherited hand-built --sysroot compiler argument and explicitly
select macosx in the native job. Windows SDK configuration enables OpenGL using
Qt's default Windows backend; other platforms retain the existing setting.
No dependency revision or additional archive is introduced. I record the exact
configure options in the SDK provenance file. Native compilation remains the
check that determines whether these settings resolve the observed failures.
