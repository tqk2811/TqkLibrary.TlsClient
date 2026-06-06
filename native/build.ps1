# Builds the native uTLS TLS-codec shared library (c-shared) for a given RID.
# Requires a portable Go and zig (used as the cgo C compiler).
# Output: ..\TqkLibrary.TlsClient\runtimes\<rid>\native\tqktls.dll
#requires -Version 5
param(
    [string]$GoRoot = 'D:\tmp\tools\go',
    [string]$Zig    = 'D:/tmp/tools/zig/zig.exe',
    [string]$Rid    = 'win-x64'
)
$ErrorActionPreference = 'Stop'

$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$go   = Join-Path $GoRoot 'bin\go.exe'
$out  = Join-Path $here ("..\TqkLibrary.TlsClient\runtimes\{0}\native" -f $Rid)
New-Item -ItemType Directory -Force -Path $out | Out-Null
$dll  = Join-Path $out 'tqktls.dll'

$env:GOTOOLCHAIN = 'local'
$env:CGO_ENABLED = '1'
$env:CC = "$Zig cc"

Push-Location $here
try {
    & $go build -buildmode=c-shared -o $dll .
    if ($LASTEXITCODE -ne 0) { throw "go build failed (exit $LASTEXITCODE)" }
}
finally { Pop-Location }

# We don't ship the generated C header.
Remove-Item (Join-Path $out 'tqktls.h') -ErrorAction SilentlyContinue
Write-Host ("Built {0} ({1:N0} bytes)" -f $dll, (Get-Item $dll).Length)
