# Dependency notes

6 November 2026. This is a review of the build inputs touched by the Windows
TLS work. I haven't audited every library or the complete application.

| Input | Selection | Use and remaining work |
| --- | --- | --- |
| OpenSSL | 3.5.9, commit `45e844fa2a14ec92d146bd8f5778ac130b6625fb` | Windows engine SDK, built from the official release archive. CMake requires 3.5 LTS at 3.5.9 or later. Runtime packaging is still blocked. |
| Google Test / Google Mock | 1.15.2, commit `b514bdc898e2951020cbdca1304b75f5950d1f59` | Windows test builds only. This revision supports the project's C++14 code. Linux uses its packaged test libraries. |
| gulrak filesystem | Submodule `614bbe87b80435d87ab8791564370e0c1d13627d` | Existing filesystem dependency; unchanged here. Parent traversal hardening remains BX-004. |
| Qt and DNS-SD | Existing platform selections | Not upgraded by this change. Supported versions, source licences, advisories and Windows discovery integration need checking before the GUI build moves. |
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
