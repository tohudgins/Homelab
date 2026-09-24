# Attack / Detect: AD Group Membership Manipulation — a real dead end that wasn't actually dead

**Phase 4 — Detection engineering.** [T1098.007](https://attack.mitre.org/techniques/T1098/007/) —
adding an account to a privileged group like Domain Admins — is Windows Event ID 4728 in the real world,
one of the most consistently monitored events in production AD security, and the natural next step after a
real attacker has cracked or stolen a credential with enough privilege to do it. This is the writeup where
"the platform genuinely can't do this" and "we were using the wrong log level" turned out to be the same
investigation, four weeks apart.

> [!check] The section below through "Not pursued further tonight" is the **original 2026-08-15
> investigation, left exactly as written** — it genuinely looked like a platform limitation at the time. It
> wasn't. See the resolution after it, closed 2026-09-12.

---

## 1. What was tried first

Samba's `auth_json_audit` facility (already proven — the Kerberoasting and Kerberos-brute-force detections
in this catalog are built on it) only covers *authentication* events. Directory-object *modification* has
its own separate logging facility family in Samba's source (`dsdb_audit`), so every plausible variant got
enabled:

```
log level = 1 auth_audit:3 auth_json_audit:3 dsdb_audit:3 dsdb_json_audit:3 dsdb_group_audit:3 dsdb_group_json_audit:3 dsdb_password_audit:3 dsdb_password_json_audit:3
```

**Test methodology, built to rule out "the change didn't actually happen":** created a dedicated `adm-test`
account, added it to Domain Admins locally as a one-time bootstrap, then authenticated as `adm-test`
**over the network LDAP protocol** — `samba-tool group addmembers "Domain Admins" jdoe -H
ldap://dc-01.lab.internal -k yes` — the same path a real remote attacker would use, not a local-database
shortcut. Confirmed the modification genuinely succeeded (`samba-tool group listmembers "Domain Admins"`
showed `jdoe` added), and confirmed the *authentication* half of that same operation *was* captured
correctly (a real `KDC Authorization` TGS-REQ event for the `ldap/dc-01.lab.internal` SPN) — proving the
audit pipeline itself works, and isolating the gap to directory-modification logging specifically.

**Result:** zero output from any `dsdb_*` facility, across all four variants, for a change independently
verified to have genuinely happened via the exact real-world attack path. This looked like a real capability
gap in this Samba AD DC build (4.23.6) versus a real Windows Server DC — a concrete, honest cost of the
Samba pivot this lab made in Phase 2. Cleaned up before moving on (removed `jdoe` from Domain Admins,
deleted `adm-test`) rather than leaving an undocumented extra Domain Admin lying around to quietly corrupt
later Phase 5 BloodHound work.

The remaining untried option — registering a real LDB audit-log module in the schema, rather than a log-level
flag — was judged a materially bigger, more invasive change than anything else in this catalog, risking the
live DC for a payoff that wasn't guaranteed. Left as a dedicated pass for later, not squeezed in.

## 2. The resolution: it wasn't a platform limit, it was the wrong log level

Four weeks later, went back to actually check Samba's register of debug classes rather than re-deriving them
from memory. `dsdb_group_audit`/`dsdb_group_json_audit` **is** the officially documented Samba facility for
exactly this event — group *membership* changes, logged with a schema matching Windows Event ID 4728 — and
the Samba Wiki's own configuration example uses **level 5**, not the level 3 every class was set to in the
original attempt. That's the entire gap: not a missing capability, a log level too low to make this one
specific class emit anything at all.

**Confirmed by re-running the identical test methodology, unchanged:** `dsdb_group_audit:5
dsdb_group_json_audit:5`, then the same bootstrap-account-over-LDAP path, authenticated as a throwaway admin
account, not a local shortcut. This time it produced a full JSON `groupChange` event in
`/var/log/samba/log.samba` — the same file the Kerberoasting telemetry already uses, so no new Wazuh
localfile or decoder was needed:

```json
{"timestamp":"2026-09-12T17:15:44+0000","type":"groupChange","groupChange":{
  "eventId":4728,"status":"Success","action":"Added",
  "remoteAddress":"ipv4:10.10.10.10:40790",
  "group":"CN=Domain Admins,CN=Users,DC=lab,DC=internal",
  "user":"CN=John Doe,CN=Users,DC=lab,DC=internal", ...}}
```

`remoteAddress` confirms this came over the wire, from the real attack path — the same rigor the original
investigation insisted on, still holding four weeks later.

**Why this doesn't risk the "Too many fields" JSON-decoder overflow that got a different, generic audit
class removed elsewhere in this lab:** that earlier removal was about `dsdb_json_audit`, which logs *every*
routine LDB attribute change (`lastLogon`, `badPwdCount`, ...) — real, constant churn on a live DC.
`dsdb_group_audit`/`dsdb_group_json_audit` is narrower by design: it only fires on group *membership*
changes specifically, a fixed ~10-field schema, and a genuinely rare event category rather than routine
noise. No overflow observed in testing.

## 3. The rules

```xml
<rule id="100014" level="3">
  <!-- base classifier: tags any groupChange event -->
  <mitre><id>T1098</id></mitre>
</rule>
<rule id="100015" level="13">
  <if_sid>100014</if_sid>
  <!-- action=Added + group matches a curated privileged-group list -->
  <mitre><id>T1098.007</id></mitre>
</rule>
```

`100014` is a base classifier (level 3, tags any `groupChange` event — added *or* removed, any group).
`100015` escalates specifically to `action=Added` where the group matches a curated list of privileged
groups (Domain Admins, Enterprise Admins, Schema Admins, Administrators, Backup Operators, Account
Operators) — level 13, correct MITRE tagging for both `T1098.007` and the broader `T1098`.

## 4. Verified — and re-verified against the fully converged state

Re-ran the exact test against the fully `ansible-playbook dc.yml`/`siem.yml`-converged state, not just the
live hand-edit that first proved the fix, and confirmed `100015` fires clean with correct MITRE tagging.
Now wired into `ad-validate.py`'s automated battery — the harness gained generic `setup`/`teardown` fields
specifically for this scenario: bootstrap `adm-test` and grant it Domain Admins (local/root, fine for setup
since bootstrapping isn't the thing being measured), run the *measured* attack step over real network LDAP,
then remove `jdoe` from Domain Admins and delete `adm-test`. Same scenario, same rigor, no longer "verified
manually" as a standing exception to this repo's own discipline.

## 5. A follow-up finding while wiring up the harness, worth recording on its own

Re-tested whether the *bootstrap* step itself (a local, non-LDAP `samba-tool group addmembers` run as root)
also reaches `log.samba` — because if it did, the harness's own setup step would trip rule 100015 before the
"real" measured attack even ran. **It doesn't.** Confirmed by watching the file's line count across a local
call (unchanged, 3330→3330 lines) versus the identical operation via `-H ldap://10.10.10.10` (+6 lines, with
a real `remoteAddress`). `samba-tool` prints its own "Group Change [Added]..." audit text to the terminal on
*every* invocation, local or remote — identical-looking output either way — but only the network-LDAP path's
event is actually written to the log file Wazuh monitors.

This means the original investigation's insistence on "the real remote-LDAP path, not a local shortcut"
wasn't just extra realism for its own sake, as first assumed — it's a hard requirement. A local CLI call's
audit line never reaches `dsdb_group_audit` at *any* log level, because it never goes through the code path
that audit facility hooks into. Worth knowing before assuming any `samba-tool`-driven Ansible task quietly
produces group-membership telemetry — it doesn't, by design of the local-vs-LDAP access-path split.

## 6. Evasion / limits — named honestly

Detection is keyed entirely on the curated privileged-group list inside rule 100015 — a group not on that
list (a custom, over-privileged group an attacker creates specifically to avoid the well-known names) is
tagged only by the base classifier 100014 at level 3, not escalated. Real coverage depends on that list
staying current with whatever groups actually carry real privilege in a given domain, which is an ongoing
maintenance cost, not a one-time fix.

## Reproduce

```bash
ssh dc-01 'sudo samba-tool user create adm-test AdmTest2026 && sudo samba-tool group addmembers "Domain Admins" adm-test'
ssh dc-01 'kinit adm-test && samba-tool group addmembers "Domain Admins" jdoe -H ldap://dc-01.lab.internal -k yes'
ssh siem-01 "sudo grep -a '\"id\":\"100015\"' /var/ossec/logs/alerts/alerts.json | tail -1"
ssh dc-01 'sudo samba-tool group removemembers "Domain Admins" jdoe adm-test && sudo samba-tool user delete adm-test'
```

## Related

`phase-4-detection/detection-catalog.md`'s "T1098.007 (Account Manipulation — privileged group membership)"
section (the full original write-up this backfills, including the dead-end investigation preserved as
written) · `phase-5-offense/purple-team/README.md`'s "Closing the 23→48 gap" section (where this scenario
was wired into `ad-validate.py`) · `01-fs01-credential-theft-to-dcsync.md` (the same Samba-audit-logging
pipeline, applied to a different facility)
