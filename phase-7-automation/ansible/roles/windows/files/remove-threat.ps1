# Wazuh Windows active-response: terminate the process named in the triggering Sysmon alert.
#
# Two hard-won details:
#  1. Read ONE line from stdin with a timeout -- never [Console]::In.ReadToEnd(). execd sends the AR
#     JSON as a single line and does NOT close the stream, so ReadToEnd() blocks forever and hangs the
#     agent's single-threaded execd (every subsequent AR is then received but never executed).
#  2. Write to active-responses.log with FileShare.ReadWrite -- the agent's logcollector holds that file
#     open, so a plain Add-Content silently fails while the agent is running.
$ErrorActionPreference = 'SilentlyContinue'
$log = Join-Path (Split-Path -Parent $PSScriptRoot) 'active-responses.log'
function Log($m) {
    $line = (Get-Date).ToString('o') + ' remove-threat: ' + $m
    try {
        $fs = [System.IO.File]::Open($log, [System.IO.FileMode]::Append, [System.IO.FileAccess]::Write, [System.IO.FileShare]::ReadWrite)
        $sw = New-Object System.IO.StreamWriter($fs)
        $sw.WriteLine($line); $sw.Flush(); $sw.Close(); $fs.Close()
    } catch {}
}

$raw = $null
try { $t = [Console]::In.ReadLineAsync(); if ($t.Wait(5000)) { $raw = $t.Result } } catch {}
if (-not $raw) { Log 'no stdin line within 5s'; exit 1 }
try { $j = $raw | ConvertFrom-Json } catch { Log 'unparseable stdin JSON'; exit 1 }
if ($j.command -ne 'add') { exit 0 }        # timeout "delete" call (if any): nothing to undo for a kill

$ed = $j.parameters.alert.data.win.eventdata
$rid = $j.parameters.alert.rule.id
$procId = $ed.processId
$image = $ed.image
if (-not $procId) { Log ("rule " + $rid + ": no processId in alert"); exit 0 }
try {
    Stop-Process -Id ([int]$procId) -Force -ErrorAction Stop
    Log ("KILLED pid=" + $procId + " image=" + $image + " (rule " + $rid + ")")
} catch {
    Log ("rule " + $rid + ": could not kill pid=" + $procId + " image=" + $image + " (" + $_.Exception.Message + ")")
}
exit 0
