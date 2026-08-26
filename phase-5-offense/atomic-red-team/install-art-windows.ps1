# Windows-side installer for Atomic Red Team (run on ws-01 by install-art-offline.sh).
# Extracts the pre-staged tarballs into the module path + C:\AtomicRedTeam, then
# imports and verifies. Idempotent: re-running replaces the module/atomics cleanly.
$ErrorActionPreference = 'Stop'
$src = 'C:\Users\localadmin'

function Install-FromTgz($tgz, $dest) {
    if (Test-Path $dest) { Remove-Item $dest -Recurse -Force }
    New-Item -ItemType Directory -Path $dest -Force | Out-Null
    tar.exe -xzf $tgz -C $dest
    if ($LASTEXITCODE -ne 0) { throw "tar extract failed for $tgz ($LASTEXITCODE)" }
    # belt-and-braces: strip any AppleDouble junk that slipped through
    Get-ChildItem $dest -Recurse -Force -File -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -like '._*' -or $_.Name -eq '.DS_Store' } |
        Remove-Item -Force -ErrorAction SilentlyContinue
}

$modRoot = 'C:\Program Files\WindowsPowerShell\Modules'
Write-Output '[*] powershell-yaml (dependency)...'
Install-FromTgz "$src\psyaml.tgz" "$modRoot\powershell-yaml"

Write-Output '[*] Invoke-AtomicRedTeam module...'
Install-FromTgz "$src\art-module.tgz" "$modRoot\Invoke-AtomicRedTeam"

Write-Output '[*] atomics library...'
if (-not (Test-Path 'C:\AtomicRedTeam')) { New-Item -ItemType Directory 'C:\AtomicRedTeam' -Force | Out-Null }
if (Test-Path 'C:\AtomicRedTeam\atomics') { Remove-Item 'C:\AtomicRedTeam\atomics' -Recurse -Force }
tar.exe -xzf "$src\atomics-only.tgz" -C 'C:\AtomicRedTeam'
Get-ChildItem 'C:\AtomicRedTeam\atomics' -Recurse -Force -File -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -like '._*' -or $_.Name -eq '.DS_Store' } |
    Remove-Item -Force -ErrorAction SilentlyContinue

# Defender exclusion for the atomics tree (some atomics drop flagged test artifacts)
Add-MpPreference -ExclusionPath 'C:\AtomicRedTeam' -ErrorAction SilentlyContinue

Write-Output '[*] Import + verify...'
Import-Module 'Invoke-AtomicRedTeam' -Force
$m = Get-Module Invoke-AtomicRedTeam
$tech = (Get-ChildItem 'C:\AtomicRedTeam\atomics' -Directory | Where-Object { $_.Name -like 'T*' }).Count
Write-Output ("    Invoke-AtomicRedTeam = " + $m.Version)
Write-Output ("    powershell-yaml      = " + (Get-Module -ListAvailable powershell-yaml).Version)
Write-Output ("    atomics techniques   = " + $tech)
Write-Output ("    Invoke-AtomicTest    = " + [bool](Get-Command Invoke-AtomicTest -ErrorAction SilentlyContinue))
if (-not (Get-Command Invoke-AtomicTest -ErrorAction SilentlyContinue)) { throw 'Invoke-AtomicTest not available after import' }
Write-Output '[+] Atomic Red Team installed.'
