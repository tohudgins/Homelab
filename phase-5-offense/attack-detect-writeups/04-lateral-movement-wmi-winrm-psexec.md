# Attack / Detect: Windows lateral movement — WMI, WinRM, PsExec

**Tools used:** Impacket (`impacket-wmiexec`, `impacket-psexec`), NetExec (`nxc`) — see [`../TOOLS.md`](../TOOLS.md) if either is unfamiliar.

**Phase 5 — Offense in context.** The lab detected one lateral-movement technique (T1021.002, SMB admin
shares) — thin for an AD-centric lab, since the three most common remote-execution methods an operator
reaches for after landing a credential were uncovered. This adds them, authored as **Sigma** and compiled to
Wazuh by the lab's `sigma-to-wazuh.py` pipeline:

| Technique | Rule(s) | The tell (Sysmon EID1 parent→child) |
|---|---|---|
| **T1047** — WMI | 100515 | `WmiPrvSE.exe` → `cmd.exe`/`powershell.exe` (impacket `wmiexec.py`) |
| **T1021.006** — WinRM | 100516 | any child of `wsmprovhost.exe` (evil-winrm, `Enter-PSSession`) |
| **T1569.002** — Service Execution (PsExec) | 100513, 100514 | `PSEXESVC.exe` runs or spawns a child (Sysinternals/impacket psexec) |

> [!check] All three resolved as of 2026-09-12 (live-fire attempted 2026-09-07, WMI fixed 2026-09-12).
> **T1021.006 (WinRM)** verified firing live after standing up a listener and fixing a real Sigma
> parent-process gap (`WinRShost.exe` vs `wsmprovhost.exe`). **T1569.002 (PsExec)** reaches ws-01 and
> drops the service binary, but Defender quarantines it before the service runs — a confirmed
> defense-in-depth block, not a rule gap. **T1047 (WMI)** produced the exact expected telemetry but
> rule 100515 never fired on 2026-09-07 — root-caused 2026-09-12 (stock rule 92069 was silently
> pre-empting it, see `detection-catalog.md` #39) and fixed with a new escalation rule, 100527, verified
> firing live. Rule logic for all four Sigma IDs remains proven offline by `sigma-selftest.py` (26/26).
> Full investigation in §5.

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

## 5. Live-fire attempt (2026-09-07) — one confirmed, two real blockers, one design boundary

Wired all three into `ad-validate.py` and ran them from atk-01 against ws-01, with `ADMIN_USER=localadmin`.
First attempt: all three failed outright — not the rules, the *network path*. ws-01 was completely
unreachable on 445/135 from anywhere, even same-segment (`dc-01`). Root cause, found and fixed live:

1. ws-01's Windows Firewall had the entire **"File and Printer Sharing" and "Windows Management
   Instrumentation (WMI)" rule groups disabled**, for every profile — a side effect of the "debloated" base
   image; nothing had ever tried live inbound lateral movement against this host before tonight.
2. Its network was misclassified `Public` instead of `DomainAuthenticated` (stale NLA detection from boot;
   restarting the NLA service didn't fix it — set the profile to `Private` directly instead).
3. Even with the rules enabled, the SMB-In rule's remote scope was `LocalSubnet` — invisible to REDTEAM
   traffic routed in from a different segment, which is exactly why `dc-01` (same subnet as ws-01) could
   reach it while `atk-01` couldn't. Widened to `Any`.

With the path open, `impacket-psexec` additionally failed to write to `ADMIN$`/`C$` ("share is not
writable") until `LocalAccountTokenFilterPolicy=1` was set — the standard Microsoft fix for UAC's remote
token-filtering of local (non-`Administrator`) accounts; `localadmin` is exactly that. All four fixes were
applied live over SSH that night; **now codified into the `windows` Ansible role** (`roles/windows/tasks/main.yml`)
so a rebuild doesn't silently lose them — idempotent check-then-fix tasks for the firewall rule groups, the
network profile, the SMB-In scope, and the registry value. **Re-converged against a live ws-01 and confirmed
(2026-09-22)**: `ansible-playbook site.yml --limit windows` returns `changed=0` — all four fixes are already
correctly in place and the check-then-fix tasks are genuinely idempotent, not just syntax-checked.

With the path and privilege both fixed:

- **T1569.002 (PsExec) — blocked by Defender, not by tooling.** `nxc`'s `--exec-method` doesn't even offer a
  `psexec` choice in this nxc version (`ad-validate.py`'s original scenario used an invalid argument and had
  never actually attacked anything — fixed to call `impacket-psexec -service-name PSEXESVC` directly, the
  real tool, matching the exact binary name the Sigma rule expects). It writes the service binary and starts
  the service — then Defender detects and quarantines it as **`Trojan:Win32/RemoteExec!pz`** before the
  service can run, confirmed via `Get-MpThreatDetection`/`Get-WinEvent` on the Defender operational log. Same
  class of finding as T1105 certutil and T1003.001 comsvcs: the endpoint control is the outer layer, and this
  rule is the layer that catches the technique wherever that control is weakened, disabled, or bypassed.
  **Follow-up, checked for real (2026-09-23):** does the default (no `-service-name`) randomized-name variant
  actually evade detection entirely, or just this one Sigma rule? Ran `impacket-psexec` against ws-01 without
  the flag — it dropped `hEUJklFD.exe` and created service `aSOd`, and 100513/100514 stayed silent exactly as
  predicted (their match is literally `\PSEXESVC.exe`). But the SIEM didn't miss the technique: **stock rule
  92650** fired at level 12 in the same second, tagged both T1021.002 and T1569.002 — Wazuh's own out-of-the-box
  ruleset already flags any new service whose binary lands directly in `%systemroot%`, independent of the
  name. So the practical coverage gap this note originally flagged doesn't actually exist; it was an
  undocumented stock-rule coverage question, not a real hole, and the answer turned out to be no gap. Interesting
  side effect: Defender did **not** quarantine the randomly-named binary the way it caught the literal
  `PSEXESVC.exe` run above — the AV signature/heuristic that fired on the default name didn't trigger on the
  random one, so this variant is actually *more* evasive against Defender even though it's still caught by
  the SIEM (a real example of the "endpoint control vs. SIEM control" layering being independent in both
  directions).
- **T1047 (WMI) — two separate findings, both now resolved.** `nxc --exec-method wmiexec` reaches ws-01 (a
  fresh `WmiPrvSE.exe` provider host spawns — confirmed via syscollector inventory) but never produces a
  child process, and reports "NETBIOS connection... timed out" — a real, but separate, nxc-vs-lab
  incompatibility, not this rule's problem (`ad-validate.py`'s WMI scenario works around it by calling
  `impacket-wmiexec` — the same underlying tool nxc wraps — directly instead). That path *does* succeed
  cleanly and produces the exact expected telemetry (`WmiPrvSE.exe` → `cmd.exe`), but rule 100515 still
  didn't fire that night — genuinely unresolved after 5 ruled-out causes (Defender, the firewall, a syntax
  error, rule precedence up to Wazuh's max level 16, a stale ruleset). **Root-caused and fixed 2026-09-12**
  (see `detection-catalog.md` #39): stock rule 92069 was silently winning Wazuh's one-rule-per-event
  resolution against 100515, because 100515 sat as an unrelated top-level sibling in the same
  `if_group=sysmon_event1` rather than as a child of 92069 — so it was never even considered once 92069
  matched first. Fixed with a hand-written escalation child of 92069, rule 100527; confirmed live with
  `impacket-wmiexec` and independently re-verified via `ad-validate.py` (`hits=3`).
- **T1021.006 (WinRM) — initially not exercisable as the lab was built.** Port 5985 didn't accept a
  connection at all. Not a bug: Phase 7's `windows` role deliberately manages ws-01 over **SSH, not WinRM**
  (see `group_vars/windows.yml` — avoids standing up a listener + certificate). Standing one up just to
  exercise this technique changes the host's documented management posture, so it was left as Tyler's call
  rather than made unilaterally — and later the same night he made it: a listener went up, and §3/§4 above
  cover the real rule fix (parent process `WinRShost.exe`, not `wsmprovhost.exe`) that made it fire.

**Net (as of 2026-09-12): 3 of 3 now resolved.** PsExec is confirmed Defender-blocked (a real, permanent
finding, not a gap); WinRM is verified firing live; WMI's rule bug is root-caused and fixed (100527, see
`detection-catalog.md` #39). All three rules' *logic* was proven by `sigma-selftest.py` from the start —
what took the rest of this investigation was proving (and, for WMI, fixing) that the logic actually fires
in this live ruleset.
