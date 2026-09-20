# Attack / Detect: Linux sudo/GTFOBins privilege escalation

**Phase 5 — Offense in context.** Every attack-detect writeup so far targets Windows/AD (fs-01 credential
theft, password spray, the DMZ web attack, WMI/WinRM/PsExec lateral movement) despite 3 of this lab's 7 hosts
being Linux. This closes that gap with the lab's first Linux-native offense/detection pair: a deliberately
weak sudo grant on fs-01, exploited via a real-world privilege-escalation technique
([T1548.003](https://attack.mitre.org/techniques/T1548/003/) — Abuse Elevation Control Mechanism: Sudo and
Sudo Caching), detected via **auditd** — a genuinely new telemetry path for this lab.

> [!check] Verified live end-to-end on 2026-09-20.
> `ops-logview` (a local support account on fs-01) escalates to root via the classic GTFOBins `find`
> escape, and Wazuh rule **100540** fires on the real telemetry, level 12, wired into `ad-validate.py`
> and confirmed passing through the actual harness — not just a manual test.

---

## 1. The weakness

fs-01 has a local account, `ops-logview`, with a NOPASSWD sudo grant on `find`:

```
ops-logview ALL=(root) NOPASSWD: /usr/bin/find
```

This mirrors a real, common pattern — someone grants an ops/support account the ability to search logs and
files without full root, and reaches for `find` because it's the obvious tool. What they miss:
[GTFOBins](https://gtfobins.github.io/gtfobins/find/) documents that any `find` grant with the `-exec` (or
`-execdir`/`-ok`/`-okdir`) flag is a straight-line root shell:

```bash
sudo -u ops-logview sudo find /var/log -maxdepth 0 -exec /bin/sh -c 'whoami; id' \;
# root
# uid=0(root) gid=0(root) groups=0(root)
```

The weakness is a permanent fixture of the lab, deployed as code by the `fileserver` Ansible role — the same
idiom as Phase 2's Kerberoastable service accounts (`phase-2-identity/known-weaknesses.md`): left in place
deliberately for Phase 4/5 to attack and detect against, not a throwaway test-only account.

## 2. Why auditd, and why it's new

Detecting this needs process-level telemetry: sudo's own logging only shows the *initial* command
(`sudo find /var/log`), not what `find` does internally afterward — the shell escape happens inside the
process, invisible to sudo's own audit trail. Linux's standard answer is **auditd** syscall auditing.

Every prior auditd use in this lab (the `dc` role) is Wazuh's own **whodata** FIM plumbing — a dedicated
`af_unix` socket feeding file-*watch* events to `wazuh-syscheckd` specifically, nothing to do with general
process execution. This is a different, wider mechanism: `auditd` watches `execve` directly, and Wazuh
ingests the raw `/var/log/audit/audit.log` as text via its stock `<log_format>audit</log_format>`
localfile — general process auditing, which whodata never touches.

The auditd rule (`phase-7-automation/ansible/roles/fileserver/`, `/etc/audit/rules.d/wazuh-root-shell.rules`):

```
-a always,exit -F arch=b64 -S execve -F exe=/usr/bin/find -F euid=0 -F auid!=0 -F auid!=4294967295 -k sudo_find_as_root
```

`auid` — the *audit login uid*, set once at login and immutable across `su`/`sudo`/`setuid` — is the key
field: unlike `euid`, an attacker can't reset it by escalating privilege, so "euid=0 with a real non-root
auid" reliably means "someone escalated and is now running as root."

## 3. Real finding: a naive rule false-positives on routine admin logins

The first cut watched **any** `execve` at `euid=0` with a non-root `auid` — not scoped to `find` at all.
Verified live that it's real signal for a privesc… and also real noise: Ubuntu's `/etc/update-motd.d/*`
scripts run entirely as root on **every single SSH login**, by any admin, and legitimately execve `find`,
`cat`, `sh`, and others with the logging-in user's non-root `auid` the whole way through. A broad rule keyed
purely on "root execve from a non-root login" would fire on routine admin activity constantly, not just an
attack.

`auditd` can't filter argv substrings at the kernel level (no "does this command line contain `-exec`"
condition in `auditctl` syntax), so the auditd rule stays scoped to `exe=/usr/bin/find` (still catches MOTD's
own benign `find -newermt ...` calls) and the actual weaponization signal — `-exec`/`-execdir`/`-ok`/`-okdir`
present in the command line — is matched on the Wazuh side instead, against the decoded event. This mirrors
how published Sigma GTFOBins-detection rules key on the same flag, not an ad hoc choice for this lab.

## 4. Real finding: `wazuh-logtest` doesn't model production auditd ingestion

Wazuh's stock `audit` decoder splits a raw multi-line auditd record (`SYSCALL`, `EXECVE`, `CWD`, `PATH`,
`PROCTITLE` — all sharing one `msg=audit(timestamp:serial)` id) into separate fields, so `audit.key`/
`audit.euid`/`audit.auid` live on the `SYSCALL` line while the actual command arguments
(`audit.execve.a0`…`aN`, including `-exec`) live on a *different* `EXECVE` line.

Feeding both lines to `wazuh-logtest` one at a time reproduces exactly that split — two independent events,
requiring an `if_matched_sid` + `same_field` correlation on `audit.id` to link them (the same idiom this
catalog already uses for Kerberos brute force, #4). That version worked cleanly in `wazuh-logtest` and never
fired on a single live attack.

Reading the actual archived event explained why: **the real `audit` log_format logcollector fuses every line
sharing one `audit.id` into ONE combined event before any rule ever evaluates it** — `audit.key` and
`audit.execve.*` arrive together on the same event. `wazuh-logtest`'s one-line-at-a-time REPL mode doesn't
reproduce that fusion, so it was quietly testing a code path that doesn't exist in production. The fix
collapsed two correlated rules into one rule checking both conditions on the single merged event — simpler,
and actually correct:

```xml
<rule id="100540" level="12">
  <if_sid>80700</if_sid>
  <field name="audit.key">^sudo_find_as_root$</field>
  <match type="pcre2">(?i)-(exec|execdir|ok|okdir)\b</match>
  <description>T1548.003: GTFOBins find privilege escalation — root shell spawned via sudo find -exec/-execdir/-ok/-okdir (auid=$(audit.auid))</description>
  <mitre><id>T1548.003</id></mitre>
</rule>
```

`<if_sid>80700</if_sid>` (not an independent `<decoded_as>auditd</decoded_as>` rule) matters too — the exact
same rule-precedence class of bug the T1047 WMI rule (100527) hit against stock rule 92069: a top-level
sibling rule loses Wazuh's one-rule-per-event resolution to the stock catch-all (`80700`, level 0, matches
every `auditd`-decoded event) every time.

## 5. Verified

```bash
$ sudo -u ops-logview sudo find /var/log -maxdepth 0 -exec /bin/sh -c 'whoami; id' \;
root
uid=0(root) gid=0(root) groups=0(root)
```

- Real alert landed in `alerts.json`: rule **100540**, level 12, MITRE T1548.003, correct `auid`.
- **Negative control**: every `/etc/update-motd.d/*`-triggered `find` call across a full session of repeated
  SSH logins matched the low-noise auditd capture but never the Wazuh rule (no `-exec` present) — zero false
  positives on the deployed rule.
- Wired into `phase-5-offense/purple-team/ad-validate.py` (`"technique": "T1548.003"`) and run through the
  real harness (`before`/`after` alert-count delta, not a manual check): **PASS**, `hits=1`.
- ATT&CK coverage regenerated: **52 techniques, 49 validated** (was 51/48).

## Reproduce

```bash
ssh fs-01 "sudo -u ops-logview sudo find /var/log -maxdepth 0 -exec /bin/sh -c 'whoami; id' \;"
ssh siem-01 "sudo grep -a '\"id\":\"100540\"' /var/ossec/logs/alerts/alerts.json | tail -1"
```

## Related

`phase-7-automation/ansible/roles/fileserver/` · `phase-4-detection/local_rules.xml` (rule 100540) ·
`phase-4-detection/local_decoder.xml` · `phase-4-detection/detection-catalog.md` #46 ·
`phase-5-offense/purple-team/ad-validate.py` · `04-lateral-movement-wmi-winrm-psexec.md` (the T1047 WMI
rule-precedence precedent this bug matches)
