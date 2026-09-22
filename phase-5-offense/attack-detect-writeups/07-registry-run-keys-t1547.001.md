# Attack / Detect: Registry Run Keys — the persistence technique the stock ruleset half-covers

**Phase 5 — Offense in context.** [T1547.001](https://attack.mitre.org/techniques/T1547/001/) — writing an
autostart entry into `HKLM`/`HKCU\...\CurrentVersion\Run` so a payload survives reboot — is one of the
oldest, most common persistence mechanisms on Windows, and one of the first things both a real attacker and
Sysmon's own stock ruleset were built to expect. This is the writeup where "the stock rule exists" and "the
stock rule actually alerts" turned out to be two different claims.

> [!check] Verified live, original Phase 4 build (2026-08-14/15).
> The identical Run key, written two different ways, produces two different outcomes from the stock
> ruleset — one silent, one not. Custom rule **100070** closes the gap generically.

---

## 1. The same persistence, written two ways

Wrote one Run key twice on ws-01, once with each of the two tools a real attacker plausibly reaches for:

```cmd
:: Method 1 — reg.exe
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v TestPersistence1 /t REG_SZ /d "C:\payload.exe"
```

```powershell
# Method 2 — PowerShell, no external binary at all
New-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' -Name TestPersistence3 -Value 'C:\payload.exe'
```

Both write the exact same registry value through the exact same Sysmon Event ID 13 (RegistryEvent — Value
Set) telemetry path. Only one of them got noticed.

## 2. Real finding: the stock ruleset alerts on the tool, not the behavior

Wazuh's stock Sysmon EID 13 rules (`0860-sysmon_id_13.xml`) classify every Run-key write under a base rule,
**92300** — but that base rule is **level 0**, meaning it matches internally and is used purely to feed more
specific child rules, never surfaced as an alert on its own. The children that *do* alert are narrow:

- **92302** — fires specifically when the writing process is `reg.exe`
- **92301** — fires on a suspicious file extension in the value
- **92303** — fires on a known remote-access-tool signature in the value

The `reg.exe` write correctly triggered 92302. The PowerShell write — arguably the **more** realistic
real-world method, since `reg.exe` usage is comparatively old-school and heavily signatured while
PowerShell-based persistence is extremely common in current tradecraft — **produced zero alerts**, confirmed
by direct side-by-side comparison on the same host, not assumed from reading the rule XML. The stock
ruleset's coverage of this technique was real but accidental: it happened to key on one specific tool
rather than the behavior every tool in this category shares.

## 3. The fix: escalate the behavior, not the tool

```xml
<rule id="100070" level="10">
  <if_sid>92300</if_sid>
  <description>Registry Run key persistence — $(win.eventdata.image) set $(win.eventdata.targetObject)</description>
  <mitre><id>T1547.001</id></mitre>
  <group>persistence,attack,</group>
</rule>
```

A child of the base classification rule (92300) rather than a sibling — the same "hook onto what already
fired" pattern this lab's later Sigma-era rules use for the identical reason (see the WMI lateral-movement
and Linux sudo-privesc writeups: a top-level sibling loses Wazuh's one-rule-per-event resolution to whatever
else matches first; a child of the base rule doesn't have that problem, because it only evaluates once 92300
has already matched). Deliberately one level below the stock rules' specific-pattern escalations (10 vs. 12):
broadening coverage this way means firing on legitimate application installers too, not just attacks, and
that honest tradeoff is reflected in the lower severity rather than hidden behind a level that overstates
confidence.

## 4. Verified

```
Rule: 100070 (level 10) -> 'Registry Run key persistence — C:\WINDOWS\System32\WindowsPowerShell\v1.0\powershell.exe set HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\TestPersistence3'
```

Wired into `purple-team.py`'s battery (`tests.json`, technique `T1547.001`, ART test 3 — "Registry Run key
persistence via PowerShell New-ItemProperty" — expecting rule 100070) and passing.

## 5. Evasion — named honestly, not hidden

This rule closes one specific gap, not the whole technique. Out of scope entirely: `HKCU` (per-user) Run
keys and `RunOnce` variants beyond what rule 92300's own regex already covers, and the dozen-plus *other*
legitimate Windows autostart locations — the Startup folder, services, scheduled tasks, WMI event
subscriptions, `AppInit_DLLs`, and more. T1547 has this many sub-techniques for a reason; this rule (like
the stock ones it extends) only ever covered one of them.

**False-positive risk** is real and non-trivial by design: legitimate installers write Run keys constantly,
and this rule alerts on all of them the same as an attacker's. That's the honest cost of closing a real
detection gap generically rather than chasing a zero-false-positive rule that only ever catches `reg.exe`
again.

## Reproduce

```bash
ssh ws-01 'powershell -c "New-ItemProperty -Path ''HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'' -Name TestPersistence3 -Value ''C:\payload.exe''"'
ssh siem-01 "sudo grep -a '\"id\":\"100070\"' /var/ossec/logs/alerts/alerts.json | tail -1"
```

## Related

`phase-4-detection/detection-catalog.md` #9 (the full original write-up this backfills) ·
`04-lateral-movement-wmi-winrm-psexec.md` and `05-linux-sudo-privesc-t1548.003.md` (the same
child-of-the-matched-rule precedence pattern, hit again later in Sigma-era rules) ·
`phase-5-offense/purple-team/tests.json`
