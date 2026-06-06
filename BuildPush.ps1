# Builds the native uTLS codec and packs the NuGet package (Release).
# GitVersion derives the version from the git tag (tag vMAJOR.MINOR.0 to release).
# Push the resulting .nupkg with your usual tooling (CsharpNugetPush / 'dotnet nuget push').
$ErrorActionPreference = 'Stop'
$repo = $PSScriptRoot
Set-Location $repo

Write-Host "== Building native uTLS codec (Go + zig) =="
# osx-x64/osx-arm64 must be built on a Mac and dropped into runtimes\osx-*\native before packing.
& "$repo\native\build.ps1" -Rids win-x64, linux-x64, linux-arm64

Write-Host "== dotnet pack (Release) =="
dotnet pack "$repo\TqkLibrary.TlsClient\TqkLibrary.TlsClient.csproj" -c Release

Write-Host "Done. The .nupkg is under TqkLibrary.TlsClient\bin\Release."
