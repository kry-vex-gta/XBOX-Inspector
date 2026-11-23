param([string]$Binutils, [string]$TargetDir)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$cargo = Join-Path $env:USERPROFILE '.cargo\bin\cargo.exe'
if (-not (Test-Path -LiteralPath $cargo)) { $cargo = 'cargo' }
$python = Get-Command python -ErrorAction Stop

if (-not $Binutils) {
    $candidate = Join-Path $env:USERPROFILE 'tools\binutils\mingw64\bin'
    if (Test-Path -LiteralPath (Join-Path $candidate 'as.exe') -PathType Leaf) {
        $Binutils = $candidate
    }
}
if ($Binutils) {
    $directory = (Resolve-Path -LiteralPath $Binutils).Path
    if (-not (Test-Path -LiteralPath (Join-Path $directory 'as.exe') -PathType Leaf) -or
        -not (Test-Path -LiteralPath (Join-Path $directory 'dlltool.exe') -PathType Leaf)) {
        throw 'Binutils must contain the GNU assembler and dlltool.'
    }
    $env:PATH = "$directory;$env:PATH"
}

Push-Location -LiteralPath $root
$previousTarget = $env:CARGO_TARGET_DIR
try {
    if ($TargetDir) {
        $env:CARGO_TARGET_DIR = [IO.Path]::GetFullPath($TargetDir, $root)
    }
    & $cargo test --locked --workspace
    if ($LASTEXITCODE -ne 0) { throw 'Tests failed.' }
    & $cargo build --locked --release -p xbs-app
    if ($LASTEXITCODE -ne 0) { throw 'Release build failed.' }
    & $python.Source -X utf8 tools/package_release.py
    if ($LASTEXITCODE -ne 0) { throw 'Packaging failed.' }
} finally {
    $env:CARGO_TARGET_DIR = $previousTarget
    Pop-Location
}
