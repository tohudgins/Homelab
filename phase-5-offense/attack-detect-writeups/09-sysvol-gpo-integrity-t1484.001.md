# Attack / Detect: SYSVOL/GPO Integrity — the one path with a blast radius unlike anything else in the lab

**Phase 4 — Detection engineering.** [T1484.001](https://attack.mitre.org/techniques/T1484/001/) — Group
Policy Modification — targets `SYSVOL`, the share every domain controller replicates to every other DC and
that every domain-joined host reads GPOs and logon scripts from on its next policy refresh or logon. A
single unauthorized write there doesn't compromise one host, it plants a payload that will eventually touch
every machine in the domain. No other monitored path in this lab has that reach, which is exactly why it
gets its own escalated rule instead of riding on default file-integrity severity.

> [!check] Verified live, original Phase 4 build (2026-08-14), all three FIM event types (add/modify/delete)
> against a real planted logon script.

---

## 1. The gap: default FIM doesn't even look at SYSVOL

Wazuh's default agent config on dc-01 only checked `/etc,/usr/bin,/usr/sbin,/bin,/sbin,/boot`, and only on a
12-hour polling cycle (`<frequency>43200</frequency>`, no realtime) — SYSVOL wasn't monitored at all. Added a
scoped real-time directory:

```xml
<directories realtime="yes" report_changes="yes">/var/lib/samba/sysvol</directories>
```

`report_changes="yes"` makes Wazuh keep pre/post hashes and a real diff, not just "something changed."

## 2. Attack simulation

Simulated an attacker (or a compromised service account) with filesystem access to dc-01 planting a
malicious logon script — `scripts/logon.bat` containing a payload comment — then modifying it, then deleting
it, covering all three FIM event types a real tamper-and-cover-tracks sequence would produce.

## 3. Raw telemetry: the default rules already fire, they just don't stand out

Wazuh's stock FIM rules fired immediately on the planted file, no custom decoder needed — `554` (added,
level 5), `550` (modified, level 7), `553` (deleted, level 7), each carrying a full `syscheck` block (path,
size, permissions, owner, mtime, MD5/SHA1/SHA256 before/after). The problem: these are identical regardless
of *where* under the monitored tree a change happened. A change to `/etc/hostname` and a change to a GPO
logon script land at the exact same severity by default — nothing about SYSVOL's actual blast radius is
reflected anywhere.

## 4. The fix: an escalator scoped to the one path that matters most

```xml
<rule id="100020" level="12">
  <if_sid>550,553,554</if_sid>
  <field name="file" type="pcre2">^/var/lib/samba/sysvol</field>
  <description>SYSVOL integrity change (GPO/logon script) — $(file)</description>
  <mitre><id>T1484.001</id></mitre>
  <group>gpo_tampering,attack,</group>
</rule>
```

Chains off all three base FIM rules (`550,553,554`) rather than replacing them — the base records still
carry the full evidence, this just adds a second, much higher-severity alert specifically for this one path,
so a SYSVOL write can't get lost in routine `/etc` noise the way it would at the base rules' own level.

## 5. Verified

```
Rule: 100020 (level 12) -> 'SYSVOL integrity change (GPO/logon script) — .../scripts/logon.bat'
File '.../scripts/logon.bat' added|modified|deleted    Mode: realtime
```

Confirmed for all three event types against the real file — the `modified` case carried the full diff
evidence (size 69→78 bytes, MD5/SHA1/SHA256 before and after).

## 6. Evasion / real limitations — named honestly

**No active response is wired on purpose.** Auto-reverting a file is a much riskier default action than
blocking an IP — it could clobber a legitimate GPO edit made seconds earlier — so this stays alert-only
pending an actual response playbook. That means detection here is not prevention: the write completes
before any alert is read, so the real "evasion" is simply outrunning analyst response time, not a technical
rule gap.

**A genuine untested gap:** everything here was simulated via a local root shell on dc-01, standing in for
an already-compromised DC or a service account with filesystem access. The more realistic T1484.001 path is
a *remote* SMB write from a domain member using a stolen account with an over-permissioned SYSVOL ACL. The
underlying filesystem write is identical either way (`inotify` doesn't care about the client), but that path
is untested here — it needs a second domain-joined host driving it.

**False-positive risk:** a legitimate GPO edit from the Group Policy Management side fires this rule
identically to an attacker's write, by design — the point is "alert on any SYSVOL write, then let a human
judge intent," not "distinguish good writes from bad ones." A real deployment would correlate this against a
change-ticket system or a known-admin allowlist before treating every alert as an incident.

## Reproduce

```bash
ssh dc-01 'sudo tee /var/lib/samba/sysvol/lab.internal/scripts/logon.bat <<< "REM payload"'
ssh siem-01 "sudo grep -a '\"id\":\"100020\"' /var/ossec/logs/alerts/alerts.json | tail -1"
ssh dc-01 'sudo rm /var/lib/samba/sysvol/lab.internal/scripts/logon.bat'
```

## Related

`phase-4-detection/detection-catalog.md` #2 (the full original write-up this backfills) ·
`07-registry-run-keys-t1547.001.md` (the same "escalate a scoped path on top of stock/base rules" idiom)
