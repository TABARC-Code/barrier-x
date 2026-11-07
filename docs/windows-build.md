# Windows engine build

I build the x64 engine against external OpenSSL 3.5 LTS, at least 3.5.9. The
old `clean_build.bat` and installer helper are retired. They selected archived
DLLs and SDKs; keeping those copies would undo the dependency change.

The [Windows engine workflow](../.github/workflows/windows-engine.yml) builds
the pinned OpenSSL and Google Test sources, then compiles the client, server,
service and engine tests. The dependency script checks the OpenSSL archive hash
and Google Test commit before building. Exact inputs are in
[dependencies.md](dependencies.md). Build results and limits are in [build.md](build.md).

For a local build, use a Visual C++ x64 environment, CMake 3.20 or newer, the filesystem
submodule and installed SDKs. These example paths match a dependency prefix
of `C:\barrier-deps`:

```powershell
git submodule update --init ext/gulrak-filesystem
cmake -S . -B build -A x64 -DCMAKE_BUILD_TYPE=Release -DCMAKE_CONFIGURATION_TYPES=Release -DBARRIER_BUILD_GUI=OFF -DBARRIER_BUILD_INSTALLER=OFF -DBARRIER_BUILD_TESTS=ON -DBARRIER_USE_EXTERNAL_GTEST=ON -DOPENSSL_ROOT_DIR=C:\barrier-deps\openssl -DCMAKE_PREFIX_PATH=C:\barrier-deps\gtest
cmake --build build --config Release --parallel 2
$env:PATH = "C:\barrier-deps\openssl\bin;$env:PATH"
ctest --test-dir build -C Release --output-on-failure
```

I require both Google Test and Google Mock's CMake targets. The checked source
revision is 1.15.2, built with the shared Visual C++ runtime to match the engine.
The CI dependency helper expects the hosted runner's native Strawberry Perl,
NASM and Visual C++ installation; it's not a general SDK installer.

## Remaining work

The GUI still needs a verified Qt SDK and native Windows build. From 2.4.18,
`-DBARRIER_BUILD_DISCOVERY=OFF` removes the Bonjour SDK requirement; the GUI
no longer downloads or executes a Bonjour installer. This build option has
Linux coverage, not a verified Windows GUI build. Windows installer generation
fails explicitly until it selects the new runtime DLLs, provider/configuration
paths and notices. The retired Azure Windows job is disabled before its old
SDK-download steps. I haven't changed the historical WiX templates into a working
new installer, and manually invoking old templates remains unsupported.

A local checkout needs trusted SDK directories and matching DLLs. The runtime test
checks loaded libcrypto's version; complete libssl/provider provenance and a
private deployment search path remain packaging work. The engine CI doesn't
establish interactive UAC, desktop input, logout or user-switching behaviour.
Those review requests are in the [working plan](working-plan.md).
