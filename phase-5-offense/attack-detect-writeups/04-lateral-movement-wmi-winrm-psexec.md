# Attack / Detect: Windows lateral movement — WMI, WinRM, PsExec

**Phase 5 — Offense in context.** The lab detected one lateral-movement technique (T1021.002, SMB admin
shares) — thin for an AD-centric lab, since the three most common remote-execution methods an operator
reaches for after landing a credential were uncovered. This adds them, authored as **Sigma** and compiled to
Wazuh by the lab's `sigma-to-wazuh.py` pipeline:

| Technique | Rule(s) | The tell (Sysmon EID1 parent→child) |
|---|---|---|
| **T1047** — WMI | 100515 | `WmiPrvSE.exe` → `cmd.exe`/`powershell.exe` (impacket `wmiexec.py`) |
| **T1021.006** — WinRM | 100516 | any child of `wsmprovhost.exe` (evil-winrm, `Enter-PSSession`) |
| **T1569.002** — Service Execution (PsExec) | 100513, 100514 | `PSEXESVC.exe` runs or spawns a child (Sysinternals/impacket psexec) |

> [!warning] Built 2026-09-06 as detection-as-code — live fire pending.
> Rule **logic is proven offline** by `sigma-selftest.py` (**26/26**, true-positive + precision cases for all
> four rule IDs). They have **not** been fired end-to-end — the lab was powered off, and live validation needs
> a running Windows target (ws-01) plus admin credentials. Exercise commands are in §3; run them from atk-01
> with the lab up to flip this note.

---

## 1. Why parent-process, not command-line

Each of these remote-execution methods runs the attacker's command as a **child of a distinctive host
process** that only exists to service remote execution:

- **WMI** — the provider host `WmiPrvSE.exe` spawns the payload. A `cmd`/`powershell` child of it is remote
  code execution, essentially never local activity.
- **WinRM** — `wsmprovhost.exe` runs *only* to service an inbound WinRM/PS-Remoting session, so **any** child
  is remote execution.
- **PsExec** — uploads a service binary (`PSEXESVC.exe` by default) to `ADMIN$` and starts it as a service to
  run as SYSTEM; the binary running (or spawning a child) is the signature.

Keying on the parent process is far more robust than matching command lines, which operators trivially
obfuscate. It does mean a renamed PsExec service binary evades rule 100513/100514 — a documented limitation;
the network side (SMB service-control traffic) and an EID 7045 service-install rule are the complementary
follow-ups.

## 2. Detection design

Authored as Sigma `process_creation` rules (`phase-4-detection/sigma/rules/`), compiled to Wazuh rules
100513–100516 (`sigma_local_rules.xml`, level 12) anchored on `sysmon_event1` with `win.eventdata.parentImage`
/ `win.eventdata.image` PCRE2 fields. This is the first use of `ParentImage` in the lab's Sigma set — the
compiler already mapped the field, so it dropped in cleanly and extends the detection-as-code showcase from
command-line rules to parent-child lineage rules.

## 3. Exercise (run from atk-01 when the lab is up)

Using a credential from the earlier password spray (`svc-sql:Summer2026`), or any local-admin credential on
ws-01, against the Windows host (`10.10.10.50`):

```bash
# WMI  -> rule 100515 (T1047)
nxc smb 10.10.10.50 -u svc-sql -p 'Summer2026' --exec-method wmiexec -x 'whoami'
#   or: impacket-wmiexec lab.internal/svc-sql:Summer2026@10.10.10.50 'whoami'

# WinRM -> rule 100516 (T1021.006)   (needs WinRM enabled + admin on the target)
nxc winrm 10.10.10.50 -u <admin> -p '<pw>' -x 'whoami'
#   or: evil-winrm -i 10.10.10.50 -u <admin> -p '<pw>'

# PsExec -> rules 100513/100514 (T1569.002)   (needs admin on the target)
nxc smb 10.10.10.50 -u <admin> -p '<pw>' --exec-method psexec -x 'whoami'
#   or: impacket-psexec lab.internal/<admin>:'<pw>'@10.10.10.50 whoami
```

Verify on siem-01:

```bash
ssh siem-01 "sudo grep -E '100513|100514|100515|100516' /var/ossec/logs/alerts/alerts.log | tail"
```

**Note on privileges:** `svc-sql` gets WMI exec if it has the rights; WinRM/PsExec need local-admin on ws-01.
The realistic chain is spray → `svc-sql` → escalate/relay to an admin context → lateral. Wiring these into
`phase-5-offense/purple-team/ad-validate.py` (the AD attack→detect harness) is the natural way to make them
count as **validated** end-to-end once run.

## 4. Coverage

Adds T1047, T1021.006, T1569.002 → coverage map **47 techniques** (`generate-coverage.py`, regenerated).
Lateral Movement goes from 1 covered technique (T1021.002) to **2** (adds WinRM), and Execution gains WMI +
Service Execution. All three score "detection exists (logic-verified)"; they move to "validated" when the §3
exercise is run and wired into the purple-team battery.
