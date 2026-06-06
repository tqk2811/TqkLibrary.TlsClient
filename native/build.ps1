# Builds the native uTLS TLS-codec shared library (c-shared) for one or more RIDs.
# Uses a portable Go and zig (zig is the cgo C cross-compiler).
# Output: ..\TqkLibrary.TlsClient\runtimes\<rid>\native\tqktls.{dll|so|dylib}
#
# Cross-buildable from Windows: win-x64, linux-x64, linux-arm64.
# osx-x64 / osx-arm64 need Apple's frameworks (CoreFoundation/Security) and so must be built on
# macOS (or with osxcross + the macOS SDK); zig alone cannot link them.
# Example: .\build.ps1 -Rids win-x64,linux-x64,linux-arm64
#requires -Version 5
param(
    [string]$GoRoot = 'D:\tmp\tools\go',
    [string]$Zig    = 'D:/tmp/tools/zig/zig.exe',
    [string[]]$Rids = @('win-x64')
)
$ErrorActionPreference = 'Stop'

$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$go   = Join-Path $GoRoot 'bin\go.exe'

# rid -> GOOS, GOARCH, zig target (empty = native host), output file name
$targets = @{
    'win-x64'     = @{ os = 'windows'; arch = 'amd64'; zig = '';                  out = 'tqktls.dll' }
    'linux-x64'   = @{ os = 'linux';   arch = 'amd64'; zig = 'x86_64-linux-gnu';  out = 'libtqktls.so' }
    'linux-arm64' = @{ os = 'linux';   arch = 'arm64'; zig = 'aarch64-linux-gnu'; out = 'libtqktls.so' }
    'osx-x64'     = @{ os = 'darwin';  arch = 'amd64'; zig = 'x86_64-macos';      out = 'libtqktls.dylib' }
    'osx-arm64'   = @{ os = 'darwin';  arch = 'arm64'; zig = 'aarch64-macos';     out = 'libtqktls.dylib' }
}

$env:GOTOOLCHAIN = 'local'
$env:CGO_ENABLED = '1'

foreach ($rid in $Rids) {
    $t = $targets[$rid]
    if (-not $t) { throw "Unknown RID '$rid'. Known: $($targets.Keys -join ', ')" }

    $outDir = Join-Path $here ("..\TqkLibrary.TlsClient\runtimes\{0}\native" -f $rid)
    New-Item -ItemType Directory -Force -Path $outDir | Out-Null
    $outFile = Join-Path $outDir $t.out

    $env:GOOS = $t.os
    $env:GOARCH = $t.arch
    $ccTarget = if ([string]::IsNullOrEmpty($t.zig)) { '' } else { " -target $($t.zig)" }
    $env:CC = "$Zig cc$ccTarget"
    $env:CXX = "$Zig c++$ccTarget"

    Push-Location $here
    try {
        & $go build -buildmode=c-shared -o $outFile .
        if ($LASTEXITCODE -ne 0) { throw "go build failed for $rid (exit $LASTEXITCODE)" }
    }
    finally { Pop-Location }

    Get-ChildItem $outDir -Filter '*.h' | Remove-Item -Force -ErrorAction SilentlyContinue
    Write-Host ("Built {0} ({1:N0} bytes)" -f $outFile, (Get-Item $outFile).Length)
}

Remove-Item Env:GOOS, Env:GOARCH -ErrorAction SilentlyContinue
