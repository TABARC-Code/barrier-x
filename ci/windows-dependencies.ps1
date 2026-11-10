# Copyright (C) 2026 barrier-x contributors; GPL, see LICENSE.
param([Parameter(Mandatory = $true)][string]$Prefix)
$ErrorActionPreference = 'Stop'
$Prefix = [IO.Path]::GetFullPath($Prefix)
$work = Join-Path $env:RUNNER_TEMP 'barrier-dependency-sources'
New-Item -ItemType Directory -Force $work, $Prefix | Out-Null

$vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
$visualStudio = & $vswhere -latest -products '*' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
if ($LASTEXITCODE -ne 0 -or !$visualStudio) { throw 'Visual C++ tools were not found' }
& (Join-Path $visualStudio 'Common7\Tools\Launch-VsDevShell.ps1') -Arch amd64 -HostArch amd64 -SkipAutomaticLocation
if (!(Get-Command nmake.exe -ErrorAction SilentlyContinue)) { throw 'nmake is unavailable' }
# I use the runner's native Perl, rather than accidentally picking Git's MSYS Perl.
$perl = 'C:\Strawberry\perl\bin\perl.exe'
if (!(Test-Path $perl)) { throw 'Native Strawberry Perl is unavailable' }
$env:PATH = "C:\Program Files\NASM;$env:PATH"
if (!(Get-Command nasm.exe -ErrorAction SilentlyContinue)) { throw 'NASM is unavailable' }

# FUTURE(BX-024): I need the published 3.5.10 archive and verified checksum before changing this pin.
$archive = Join-Path $work 'openssl-3.5.9.tar.gz'
Invoke-WebRequest 'https://github.com/openssl/openssl/releases/download/openssl-3.5.9/openssl-3.5.9.tar.gz' -OutFile $archive
$expected = '603f5602e2eef00d77fbd429d34dcd5822bb301757a1bc9cdb24c670f1eb859a'
if ((Get-FileHash $archive -Algorithm SHA256).Hash.ToLowerInvariant() -ne $expected) { throw 'OpenSSL archive checksum mismatch' }
& tar -xzf $archive -C $work
if ($LASTEXITCODE -ne 0) { throw 'OpenSSL archive extraction failed' }
Push-Location (Join-Path $work 'openssl-3.5.9')
try {
    & $perl Configure VC-WIN64A shared no-tests "--prefix=$Prefix\openssl" "--openssldir=$Prefix\openssl\ssl"
    if ($LASTEXITCODE -ne 0) { throw 'OpenSSL configuration failed' }
    & nmake.exe /NOLOGO
    if ($LASTEXITCODE -ne 0) { throw 'OpenSSL compilation failed' }
    & nmake.exe /NOLOGO install_sw
    if ($LASTEXITCODE -ne 0) { throw 'OpenSSL installation failed' }
} finally { Pop-Location }

$gtest = Join-Path $work 'googletest'
& git clone --no-checkout 'https://github.com/google/googletest.git' $gtest
if ($LASTEXITCODE -ne 0) { throw 'Google Test source fetch failed' }
& git -C $gtest checkout --detach b514bdc898e2951020cbdca1304b75f5950d1f59
if ($LASTEXITCODE -ne 0) { throw 'Google Test revision checkout failed' }
$revision = & git -C $gtest rev-parse HEAD
if ($revision -ne 'b514bdc898e2951020cbdca1304b75f5950d1f59') { throw 'Google Test revision mismatch' }
& cmake -S $gtest -B "$work\gtest-build" -A x64 -Dgtest_force_shared_crt=ON -DBUILD_GMOCK=ON -DINSTALL_GTEST=ON "-DCMAKE_INSTALL_PREFIX=$Prefix\gtest"
if ($LASTEXITCODE -ne 0) { throw 'Google Test configuration failed' }
& cmake --build "$work\gtest-build" --config Release --target install --parallel 2
if ($LASTEXITCODE -ne 0) { throw 'Google Test build failed' }
