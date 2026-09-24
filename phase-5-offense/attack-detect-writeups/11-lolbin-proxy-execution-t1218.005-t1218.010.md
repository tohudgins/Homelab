# Attack / Detect: LOLBin Proxy Execution — regsvr32 and mshta, mapped to the technique they actually are

**Phase 4 — Detection engineering.** [T1218.010](https://attack.mitre.org/techniques/T1218/010/)
(`regsvr32.exe`, the "Squiblydoo" scriptlet technique) and [T1218.005](https://attack.mitre.org/techniques/T1218/005/)
(`mshta.exe`, script-moniker execution) are two of the most cited living-off-the-land binaries in real-world
intrusions: both are signed Microsoft binaries present on every Windows box, both can execute arbitrary
script content with no separate payload file ever touching disk, and both bypass application-allowlisting
policies that block "unknown" executables but trust `regsvr32.exe`/`mshta.exe` by name. Detected via an ART
LOLBin battery on ws-01, diffed against what the stock ruleset actually maps.

> [!check] Verified live, 2026-08-27. Both LOLBins detected and correctly mapped; the third T1218 sub-technique
> in the same battery (`rundll32`, T1218.011) is covered separately by rule 100115 — see
> `phase-5-offense/purple-team/README.md`.

---

## 1. The gap: detected, but mapped to the wrong technique entirely

Both LOLBins were already being caught by the generic stock cmd rule **92032** ("Suspicious cmd shell
execution") — but that rule is mis-tagged **T1087** (Account Discovery), because it's a broad catch-all for
"a shell process ran something that looked odd," not a technique-specific rule. Nothing in the stock ruleset
mapped either binary to **T1218 System Binary Proxy Execution** at all. The telemetry existed; the ATT&CK
mapping didn't.

## 2. The rules — high-signal patterns only, not the bare binary

Deliberately narrow: both LOLBins run constantly for entirely legitimate reasons (`regsvr32` registers real
COM components as part of normal software installs; `mshta` opens legitimate `.hta` help files). Matching
the bare binary name would page on routine background noise. Instead, each rule keys on the specific
argument patterns that make an invocation a proxy-execution technique rather than ordinary use:

```xml
<rule id="100114" level="4">
  <if_group>sysmon_event1</if_group>
  <field name="win.eventdata.originalFileName" type="pcre2">(?i)regsvr32\.exe</field>
  <field name="win.eventdata.commandLine" type="pcre2">(?i)(scrobj\.dll|/i:)</field>
  <description>Regsvr32 proxy execution (scriptlet/Squiblydoo) — $(win.eventdata.commandLine)</description>
  <mitre><id>T1218.010</id></mitre>
  <group>defense_evasion,lolbin,attack,</group>
</rule>
```

`scrobj.dll` is the Windows Script Component scripting engine `regsvr32` loads to run a remote or local
`.sct` scriptlet — its presence on a `regsvr32` command line is the actual "Squiblydoo" signature, not just
`regsvr32` running at all.

```xml
<rule id="100116" level="4">
  <if_group>sysmon_event1</if_group>
  <field name="win.eventdata.originalFileName" type="pcre2">(?i)mshta\.exe</field>
  <field name="win.eventdata.commandLine" type="pcre2">(?i)(vbscript:|javascript:|https?:|\.hta\b)</field>
  <description>Mshta proxy execution (script moniker / HTA) — $(win.eventdata.commandLine)</description>
  <mitre><id>T1218.005</id></mitre>
  <group>defense_evasion,lolbin,attack,</group>
</rule>
```

The `vbscript:`/`javascript:` moniker prefixes are the actual proxy-execution signature — `mshta.exe` running
a locally-installed, legitimate `.hta` help file (no script moniker, no remote URL) never matches.

Both are **level 4**, matching the pattern established in the Discovery batch above: just high enough to win
the one-rule-per-event tie against the generic stock cmd rule (level 3) that would otherwise keep the
T1087 mistag.

## 3. Verified

Both fired correctly against the real ART battery, mapped to their real techniques rather than the stock
catch-all's T1087 mistag:

```
Rule: 100114 (level 4) -> 'Regsvr32 proxy execution (scriptlet/Squiblydoo) — regsvr32.exe /s /n /u /i:scrobj.dll'
Rule: 100116 (level 4) -> 'Mshta proxy execution (script moniker / HTA) — mshta.exe vbscript:close(...)'
```

## 4. Evasion / limits — named honestly

**Deliberately narrow, on purpose.** Neither rule matches the bare binary — `regsvr32.exe somefile.dll` with
no scriptlet argument, or `mshta.exe legitimate.hta` with no moniker, produce zero alerts, by design, since
matching either binary unconditionally would page constantly on normal software installs and help-file
usage. That's an accepted evasion tradeoff: an attacker who can smuggle a scriptlet reference through some
argument form these regexes don't anticipate slips past both rules. The gap these rules close is "this
technique has no ATT&CK mapping at all," not "this technique is now unevadable."

**No remote-fetch verification.** Both scenarios were exercised with a local/self-contained payload
reference (matching this lab's offline-only Atomic Red Team constraint — see
`phase-5-offense/atomic-red-team/README.md`). The remote-URL variant of either technique (`regsvr32
/i:http://.../file.sct scrobj.dll`, `mshta http://.../payload.hta`) is covered by the same regex (both
patterns match `http(s):` and `scrobj.dll` regardless of whether the source is local or remote) but was
never independently fired against a live remote host to confirm network-layer telemetry lines up the same
way.

## Reproduce

```bash
ssh ws-01 'regsvr32.exe /s /n /u /i:scrobj.dll'
ssh ws-01 'mshta.exe vbscript:close(Execute("Msgbox 1"))'
ssh siem-01 "sudo grep -aE '\"id\":\"(100114|100116)\"' /var/ossec/logs/alerts/alerts.json | tail -2"
```

## Related

`phase-4-detection/detection-catalog.md`'s "T1218 — System Binary Proxy Execution (LOLBins)" section (the
full original write-up this backfills) · `phase-5-offense/purple-team/README.md` (rundll32/T1218.011, the
third sibling technique in the same battery, plus the direct-invocation workaround needed when ART's own
harness crashed on this exact technique family) · `10-discovery-tactics-t1049-t1069.001-t1518.001.md` (the
same one-rule-per-event level-tie lesson, hit again here)
