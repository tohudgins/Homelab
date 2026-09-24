# Attack / Detect: Discovery tactics — where the stock ruleset stops looking

**Phase 4 — Detection engineering.** Three Discovery-tactic techniques, closed in one pass by running a real
[Atomic Red Team](../atomic-red-team/README.md) Discovery battery on ws-01 and diffing what actually fired in
Wazuh against what *should* have mapped: [T1049](https://attack.mitre.org/techniques/T1049/) (System Network
Connections Discovery — `netstat`), [T1518.001](https://attack.mitre.org/techniques/T1518/001/) (Security
Software Discovery — "what's watching me?"), and
[T1069.001](https://attack.mitre.org/techniques/T1069/001/) (Permission Groups Discovery: Local — `net
localgroup`). All three are early, cheap, near-universal recon steps a real intrusion runs before deciding
what to do next — and all three had real, specific gaps in what the stock Sysmon ruleset actually catches.

> [!check] Verified live, 2026-08-27. 21 offline-safe ART tests across seven techniques → 625 alerts, 39
> distinct rules — diffed against `rule.mitre.id`, gaps closed, then re-run to confirm every new rule fires.

---

## 1. What stock coverage actually maps (and doesn't)

- Stock rule **92031** ("Discovery activity executed", tagged T1087) matches **only `net.exe`/`net1.exe`** —
  so `net localgroup` (a T1069.001 command) gets caught, but mis-tagged as the wrong technique entirely.
- **`netstat` (T1049)** has **no stock rule at all** — it decodes fine as Sysmon EID1, but maps to nothing.
- **Security Software Discovery (T1518.001)** — enumerating Sysmon/Defender/EDR via `sc`/`reg`/`tasklist`/
  PowerShell — has **no stock detection** either, despite being one of the strongest pre-attack tells in this
  whole category (an attacker checking what's watching them is a much rarer, more deliberate action than
  ordinary network/host discovery).

## 2. The rules — every technique gets both its native-binary and PowerShell path

Real tradecraft uses both interchangeably, so each technique below is covered by two rules: one for the
native binary via Sysmon EID1, one for the PowerShell cmdlet equivalent via Script Block Logging (EID 4104):

```xml
<rule id="100102" level="4">
  <if_group>sysmon_event1</if_group>
  <field name="win.eventdata.originalFileName" type="pcre2">(?i)netstat\.exe</field>
  <description>Network connections discovery — netstat on $(win.eventdata.parentImage)</description>
  <mitre><id>T1049</id></mitre>
</rule>
<rule id="100103" level="3">
  <if_sid>91802</if_sid>
  <field name="win.eventdata.scriptBlockText" type="pcre2">(?i)Get-NetTCPConnection\b|Get-NetUDPEndpoint\b</field>
  <description>Network connections discovery via PowerShell — $(win.eventdata.scriptBlockText)</description>
  <mitre><id>T1049</id></mitre>
</rule>
```

```xml
<rule id="100104" level="6">
  <if_group>sysmon_event1</if_group>
  <field name="win.eventdata.commandLine" type="pcre2">(?i)(sc|reg|tasklist|net|net1)\b.{0,80}(sysmon|windefend|msmpeng|mssense|securityhealth|mcafee|crowdstrike|carbonblack|cylance|sophos|symantec|windows\s*defender)</field>
  <description>Security software discovery — enumerating AV/EDR/Sysmon: $(win.eventdata.commandLine)</description>
  <mitre><id>T1518.001</id></mitre>
</rule>
<rule id="100105" level="6">
  <if_sid>91802</if_sid>
  <field name="win.eventdata.scriptBlockText" type="pcre2">(?i)Get-Mp(ComputerStatus|Preference|Threat|ThreatDetection)\b|Get-(Service|Process)\b.{0,60}(Sysmon|WinDefend|MsMpEng|Sense)</field>
  <description>Security software discovery via PowerShell — $(win.eventdata.scriptBlockText)</description>
  <mitre><id>T1518.001</id></mitre>
</rule>
```

```xml
<rule id="100106" level="3">
  <if_sid>92031</if_sid>
  <field name="win.eventdata.commandLine" type="pcre2">(?i)\blocalgroup\b</field>
  <description>Local permission-group discovery — $(win.eventdata.commandLine)</description>
  <mitre><id>T1069.001</id></mitre>
</rule>
<rule id="100107" level="3">
  <if_sid>91802</if_sid>
  <field name="win.eventdata.scriptBlockText" type="pcre2">(?i)Get-LocalGroup(Member)?\b</field>
  <description>Local permission-group discovery via PowerShell — $(win.eventdata.scriptBlockText)</description>
  <mitre><id>T1069.001</id></mitre>
</rule>
```

100106 chains as a *child* of 92031 (not a sibling) specifically to correct its mistag — a child only
evaluates once the parent has already matched, so it wins the mapping without needing to out-race 92031 on
severity.

**Severity model, deliberately uneven:** pure host/network discovery (T1049/T1069.001) stays low (3–4) —
these run constantly in legitimate admin and logon activity, so they're tagged-and-queryable for hunting and
for the ATT&CK coverage map, not paged on. Security-software discovery is **level 6**: checking what's
watching you is a far rarer, more deliberate action, and a much stronger signal that something is about to
happen.

## 3. Three findings that only verifying (not writing the rules) surfaced

1. **Wazuh reports one rule per event, so a level *tie* silently shadows.** At level 3, the native
   T1049/T1016 rules never appeared in early testing — the same events also matched stock **92032** (level
   3, generic "Suspicious cmd shell execution", tagged T1087/T1059.003) when spawned via `cmd /c`, and the
   stock rule won the tie, keeping the imprecise tag. Bumping 100102 to **level 4** made the precise mapping
   win outright. The same reasoning is why the level-6 security-software rules always win, and why 100106 —
   a child of 92031 — supersedes its parent rather than competing with it.
2. **Script Block Logging can log a whole multi-command script as one EID 4104 event.** Several of the
   PowerShell rules above matched the *same* event, and only the highest-level match got reported — 100107
   (`Get-LocalGroup`) looked like it wasn't firing until run in isolation. Real, per-command invocations log
   separately in practice; this was a test-harness artifact, not a rule bug, but worth knowing before
   trusting a script-block rule's own "it didn't fire" result.
3. **A false positive from the test tooling itself, not from any of these rules:** ART's own harness trips
   stock rule **92213** (level 15, "Executable dropped in folder commonly used by malware", tagged T1105)
   roughly 26 times per battery as it stages atomic payloads to disk. Not real malware — a tuning artifact
   of running ART at all. A real environment would exclude the atomics staging path, or treat
   92213-from-the-ART-runner as expected noise during a scheduled purple-team exercise.

## 4. Evasion / limits — named honestly

The ideal actionable layer here isn't any single rule above — it's a correlation rule that fires *high* when
many *distinct* discovery commands hit one host in a short window (a real host-enumeration sweep, versus one
benign `netstat`). That needs cross-rule correlation via `<if_matched_group>`, which is non-functional in
this Wazuh build — the same limitation already documented for the T1110 sshd brute-force rules — so it's
deferred rather than shipped broken. These per-technique rules give precise ATT&CK mapping and telemetry
coverage; they are not, on their own, a low-false-positive paging signal.

## Reproduce

```bash
ssh ws-01 'netstat -ano'
ssh ws-01 'sc query WinDefend'
ssh ws-01 'net localgroup Administrators'
ssh siem-01 "sudo grep -aE '\"id\":\"(100102|100104|100106)\"' /var/ossec/logs/alerts/alerts.json | tail -3"
```

## Related

`phase-4-detection/detection-catalog.md`'s "Discovery-tactic additions" section (the full original write-up
this backfills) · `phase-5-offense/purple-team/README.md`'s "First result (Discovery battery)" section (the
same battery, run through the automated harness) · `phase-5-offense/atomic-red-team/README.md`
