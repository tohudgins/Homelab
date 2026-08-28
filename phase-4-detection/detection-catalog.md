# Phase 4 — Detection Catalog

For each technique: run/simulate the attack → observe raw telemetry in Wazuh → write a custom rule in
`local_rules.xml` → verify it fires on a true positive → attempt evasion → document false-positive risk.

Rules live on siem-01 at `/var/ossec/etc/rules/local_rules.xml` (mirrored in this folder). Rule IDs in the
`100xxx` range are reserved for custom/local rules by Wazuh convention (the shipped ruleset uses IDs below
100000), so every rule below lives there to guarantee no collision with an upstream update.

## Status

**Verified across 2026-08-14/15, all against real telemetry, not just syntax checks:**

| # | ATT&CK Technique | Rule ID(s) | Source Host | Status |
|---|---|---|---|---|
| 1 | [T1110 – Brute Force](https://attack.mitre.org/techniques/T1110/) | 100010, 100011 | dc-01 (sshd) | ✅ verified TP, active response confirmed |
| 2 | [T1484.001 – Group Policy Modification](https://attack.mitre.org/techniques/T1484/001/) | 100020 | dc-01 (SYSVOL FIM) | ✅ verified TP (add/modify/delete) |
| 3 | [T1558.003 – Kerberoasting](https://attack.mitre.org/techniques/T1558/003/) | 100030, 100031 | dc-01 (Samba KDC audit) | ✅ verified TP + evasion confirmed; **100031 off-by-one fixed 2026-08-24** (`frequency` 3→2 — fired on the 4th TGS-REQ, but a roast sends 3; found during Phase 5 re-verify, see `phase-5-offense/`) |
| 4 | [T1110.001 – Password Guessing (Kerberos)](https://attack.mitre.org/techniques/T1110/001/) | 100040, 100041 | dc-01 (Samba KDC audit) | ✅ verified TP, custom active response confirmed |
| 5 | [T1053.003 – Scheduled Task/Job: Cron](https://attack.mitre.org/techniques/T1053/003/) | 100050 | dc-01 (cron FIM) | ✅ verified TP |
| 6 | [T1136.001 – Create Account: Local Account](https://attack.mitre.org/techniques/T1136/001/) (+ T1098) | 100051 | dc-01 (passwd/shadow/sudoers FIM) | ✅ verified TP (passwd + shadow) |
| 7 | [T1562.001 – Impair Defenses: Disable or Modify Tools](https://attack.mitre.org/techniques/T1562/001/) | 100060 | dc-01 (sudo/journald) | ✅ verified TP |
| 8 | [T1059.001 – PowerShell](https://attack.mitre.org/techniques/T1059/001/) | 92057 (stock) | ws-01 (Sysmon) | ✅ verified TP (encoded command) |
| 9 | [T1547.001 – Registry Run Keys](https://attack.mitre.org/techniques/T1547/001/) | 92302 (stock) + 100070 (custom) | ws-01 (Sysmon) | ✅ verified TP, real stock gap found + closed |
| 10 | [T1053.005 – Scheduled Task](https://attack.mitre.org/techniques/T1053/005/) | 92154 (stock) | ws-01 (Sysmon) | ✅ verified TP |
| 11 | [T1070 / T1070.004 – Indicator Removal: Clear Logs](https://attack.mitre.org/techniques/T1070/004/) | 63104, 63103 (stock) | ws-01 (Windows Eventlog) | ✅ verified TP (Application + Security) |
| 12 | [T1003.001 – LSASS Memory](https://attack.mitre.org/techniques/T1003/001/) | 92900 (stock) | ws-01 (Sysmon) | ⚠️ confirmed correct by inspection; live-fire blocked by LSASS PPL (see below) |
| 13 | [T1016 – System Network Configuration Discovery](https://attack.mitre.org/techniques/T1016/) | 100100, 100101 | ws-01 (Sysmon EID1 + PS 4104) | ✅ verified TP (native + PowerShell) — **no stock rule existed** (added 2026-08-27) |
| 14 | [T1049 – System Network Connections Discovery](https://attack.mitre.org/techniques/T1049/) | 100102, 100103 | ws-01 (Sysmon EID1 + PS 4104) | ✅ verified TP (native + PowerShell) — **no stock rule existed** (added 2026-08-27) |
| 15 | [T1518.001 – Security Software Discovery](https://attack.mitre.org/techniques/T1518/001/) | 100104, 100105 | ws-01 (Sysmon EID1 + PS 4104) | ✅ verified TP, **level 6** (AV/EDR/Sysmon enum = pre-attack tell); no stock rule existed (2026-08-27) |
| 16 | [T1069.001 – Permission Groups Discovery: Local](https://attack.mitre.org/techniques/T1069/001/) | 100106, 100107 | ws-01 (Sysmon EID1 + PS 4104) | ✅ verified TP — refines stock 92031's T1087 mistag (2026-08-27) |
| 17 | [T1087.002 – Domain Account Discovery](https://attack.mitre.org/techniques/T1087/002/) | 100108, 100112 | ws-01 → dc-01 (net /domain, ADSI) | ✅ verified TP (2026-08-27) |
| 18 | [T1069.002 – Permission Groups Discovery: Domain](https://attack.mitre.org/techniques/T1069/002/) | 100109 | ws-01 → dc-01 (net group) | ✅ verified TP — fixes local/domain conflation in 100106 (2026-08-27) |
| 19 | [T1018 – Remote System Discovery](https://attack.mitre.org/techniques/T1018/) | 100110 | ws-01 → dc-01 (nltest /dclist) | ✅ verified TP (2026-08-27) |
| 20 | [T1482 – Domain Trust Discovery](https://attack.mitre.org/techniques/T1482/) | 100111 | ws-01 → dc-01 (nltest /domain_trusts) | ✅ verified TP — was mistagged T1087 by stock (2026-08-27) |
| 21 | [T1201 – Password Policy Discovery](https://attack.mitre.org/techniques/T1201/) | 100113 | ws-01 → dc-01 (net accounts) | ✅ verified TP (2026-08-27) |
| 22 | [T1218.010 – System Binary Proxy Execution: Regsvr32](https://attack.mitre.org/techniques/T1218/010/) | 100114 | ws-01 (Sysmon) | ✅ verified TP (Squiblydoo scriptlet) — was mistagged T1087 by stock (2026-08-27) |
| 23 | [T1218.011 – System Binary Proxy Execution: Rundll32](https://attack.mitre.org/techniques/T1218/011/) | 100115 | ws-01 (Sysmon) | ✅ verified TP (script moniker) — no stock T1218 mapping (2026-08-27) |
| 24 | [T1218.005 – System Binary Proxy Execution: Mshta](https://attack.mitre.org/techniques/T1218/005/) | 100116 | ws-01 (Sysmon) | ✅ verified TP (script moniker) — no stock T1218 mapping (2026-08-27) |
| 25 | [T1548.002 – Abuse Elevation Control: Bypass UAC](https://attack.mitre.org/techniques/T1548/002/) | 100117, 100118 | ws-01 (Sysmon EID13) | ✅ verified TP — closes the mscfile/Event-Viewer gap in stock 92304, + maps disable-UAC-via-reg (2026-08-27) |
| 26 | [T1021.002 – Remote Services: SMB/Windows Admin Shares](https://attack.mitre.org/techniques/T1021/002/) | 100119, 100120 | ws-01 → dc-01 (net use / New-SmbMapping) | ✅ verified TP (C$/ADMIN$ access; IPC$ excluded as noise) — stock only mistagged T1059.003 (2026-08-27) |

(#6 is tagged with both IDs deliberately: the rule can't distinguish creating a new local account from
modifying an existing one's credentials — same file, same rule, same broad-not-narrow tradeoff as the
rest of this FIM family — but the actual test below specifically exercised account *creation*
(`useradd`), which is T1136.001, not T1098. There's a separate, more precise T1098.007-flavored angle —
*AD Domain Admins* group membership specifically — that was investigated and honestly not achieved; see
[below](#investigated-not-achieved-t1098007-account-manipulation--privileged-group-membership) for why.)

**12 of the build plan's target 8-12 techniques**, spanning Credential Access, Persistence, Defense
Evasion, and Execution, across both the Linux/AD side (dc-01/rtr-01, techniques 1-7, almost entirely
custom rules written from scratch since Samba's default logging is sparse) and the Windows side (ws-01,
techniques 8-12, mostly *verifying* Wazuh's mature stock Sysmon ruleset rather than writing new rules —
a genuinely different, equally real kind of detection-engineering work; see the Windows section below for
why that contrast matters and is worth stating explicitly in a portfolio).

Plus a real SCA before/after remediation pass on dc-01 (48% → 55%, see below — a different Wazuh
capability, compliance benchmarking rather than attack-simulation rule-writing, so it isn't in the table
above), and one AD-specific investigation honestly documented as not achieved (T1098.007, see below).

**Vulnerability-detection module — independently verified (2026-08-24).** Enabled with
`<index-status>yes</index-status>`; results live only in the OpenSearch indexer in this Wazuh version (no
local CLI path the way SCA had). Retrieved the indexer admin password from `wazuh-install-files.tar` and
queried the `wazuh-states-vulnerabilities-*` index directly — **9,888 CVE findings** across the agents,
proving the module is doing real package-CVE matching, not just "running":

| Agent | Findings | Critical | High |
|---|---|---|---|
| dc-01 | 3,731 | 359 | 1,688 |
| rtr-01 | 2,416 | 80 | 368 |
| dmz-01 | 1,870 | 175 | 851 |
| fs-01 | 1,870 | 175 | 851 |
| ws-01 | 1 | 0 | 0 (agent was offline; stale inventory) |

Concrete example (dc-01, sorted by CVSS): `CVE-2026-74475` / `CVE-2026-74309` / `CVE-2026-72408` … all
**CVSS 10.0**, all against `linux-image-7.0.0-28-generic 7.0.0-28.28` — the running kernel. High counts are
expected: these are lab boxes tracking `-generic`/rolling packages, and the module matches *every* known CVE
for *every* installed version. The full active-vs-passive comparison against Greenbone's scan of the same
hosts is in [`vulnerability-management-active-vs-passive.md`](vulnerability-management-active-vs-passive.md).
Query recipe: `curl -sk -u admin:<pw> https://127.0.0.1:9200/wazuh-states-vulnerabilities*/_search`.

**Deliberately deferred, not forgotten:**
- **NSM / Suricata rule-writing** — wired Suricata's `eve.json` into Wazuh (real ingestion, verified
  flowing) as prep, but building actual detections on top of it is explicitly **Phase 6** scope in the
  build plan (ET Open tuning, Suricata+Zeek correlation). Started drifting into that scope mid-session and
  pulled back deliberately rather than half-finish Phase 6 under the Phase 4 banner.
- **12 techniques is the top of the build plan's target range, not a hard stop.** Real candidates for a
  future pass: T1055 (process injection, stock rule 92910 already covers explorer.exe access — untested),
  T1218 (LOLBin abuse — stock coverage exists, untested), T1087 (account/group discovery), and revisiting
  T1003.001 with a proper PPL-bypass methodology if that's ever genuinely warranted (it wasn't here — see
  below for why that line wasn't crossed).

---

## 1. T1110 — Brute Force (SSH password guessing)

**Objective:** Detect repeated SSH authentication failures against dc-01 from a single source within a
short window, distinct from an isolated failed login (typo) or a single legitimate retry — and
auto-contain the source.

**Attack simulation:** No atk-01 yet (that's Phase 5) — simulated from rtr-01 as an interim attacker
vantage point, proxying through it via `ssh -J` from the Mac. A loop of `sshpass`-driven SSH attempts
against `dc-01` (`10.10.10.10`), password auth forced (`PubkeyAuthentication=no`), mixing wrong passwords
for a real user (`tohudgins`) and a non-existent user (`svc-backup`). From dc-01's perspective the source
is `10.10.10.1` (rtr-01's CORP address), same as any real pivot through a compromised jump box would look.

**Raw telemetry observed:** Ubuntu 26.04 logs sshd via `sshd-session[PID]` to journald (not a separate
`sshd` binary name) — decoded fine by the stock `sshd` decoder (`program_name: ^sshd` matches the
`sshd-session` prefix). Six real attempts produced pairs of lines per attempt: `pam_unix(sshd:auth):
authentication failure...` → `Failed password for tohudgins from 10.10.10.1 port NNNNN ssh2` (existing
user) or `Invalid user svc-backup from 10.10.10.1 port NNNNN` → `Failed password for invalid user
svc-backup from ...` (non-existent user). One real gotcha: `/var/log/auth.log` on dc-01 contains some
binary content mixed into an otherwise-text file (unrelated cause, not investigated), so plain `grep`
silently reports "binary file matches" with zero output — needs `grep -a` to force text mode.

**Custom rules — two iterations, one real dead end:**

*First attempt* — a single correlator using `if_matched_group="authentication_failed"` to aggregate
across both failure types (wrong-password and non-existent-user) with a threshold of 4 failures/60s from
one source, tighter than the stock per-type correlators (5712/5719/5763, each independently
frequency=8/timeframe=120). Syntax validated clean via `wazuh-logtest-legacy`, but it never actually
fired — not on the live attack (6 real events, well over threshold, zero alert), and not in `wazuh-logtest`
against synthetic input either.

To isolate whether the bug was in my rule specifically or in `if_matched_group` generally, I copied the
*stock* ruleset's own `if_matched_group` rule (`40111` in `0280-attack_rules.xml`, same
`authentication_failed` group + `same_source_ip` + frequency/timeframe pattern Wazuh itself ships) as a
throwaway test rule, changing only the frequency to something reachable in a short test. It didn't fire
either, while the stock `if_matched_sid`-based correlator (`5763`, same file family) fired exactly on
schedule at its 8th matching event in the same test session. That isolated the issue to `if_matched_group`
specifically, not my rule's syntax — confirmed via `wazuh-logtest` (v4.14.7), not just a syntax linter.
Rather than chase what looks like a version-specific bug in a mechanism the shipped ruleset itself barely
uses, pivoted to the mechanism proven to work.

*Working version* — two explicit `if_matched_sid` correlators, one per failure-decoder rule, each
frequency=4/timeframe=60/same_source_ip, `ignore=120` to avoid re-alerting on an already-contained source:

```xml
<rule id="100010" level="12" frequency="4" timeframe="60" ignore="120">
  <if_matched_sid>5760</if_matched_sid>  <!-- sshd: authentication failed (wrong password) -->
  <same_source_ip />
  <description>sshd: brute force — $(srcip) had 4+ wrong-password failures in 60s.</description>
  <mitre><id>T1110</id><id>T1110.001</id></mitre>
  <group>authentication_failures,attack,</group>
</rule>

<rule id="100011" level="12" frequency="4" timeframe="60" ignore="120">
  <if_matched_sid>5710</if_matched_sid>  <!-- sshd: non-existent user -->
  <same_source_ip />
  <description>sshd: brute force — $(srcip) had 4+ non-existent-user failures in 60s.</description>
  <mitre><id>T1110</id><id>T1110.001</id></mitre>
  <group>authentication_failures,attack,</group>
</rule>
```

**Verification (true positive):** Confirmed twice. First via `wazuh-logtest` with 4 synthetic
`Failed password` lines — rule `100010` fired on the 4th, correct level (12), correct description with
`$(srcip)` resolved to `10.10.10.1`, correct MITRE tags. Then live: 5 real wrong-password attempts against
`tohudgins@dc-01` from rtr-01 produced a real alert in `/var/ossec/logs/alerts/alerts.log`:

```
Rule: 100010 (level 12) -> 'sshd: brute force — 10.10.10.1 had 4+ wrong-password failures in 60s.'
Src IP: 10.10.10.1
Aug 15 02:38:31 dc-01 sshd-session[4623]: Failed password for tohudgins from 10.10.10.1 port 39982 ssh2
```

**Active response — confirmed, with a real side effect:** wired in `/var/ossec/etc/ossec.conf`:

```xml
<active-response>
  <command>firewall-drop</command>
  <location>local</location>
  <rules_id>100010,100011</rules_id>
  <timeout>600</timeout>
</active-response>
```

`location=local` runs the response on whichever agent generated the alert (dc-01, here) rather than the
manager or a fixed target — `timeout=600` self-reverses the block after 10 minutes. It fired for real: within seconds of the alert, SSH from the Mac to dc-01 (proxied through rtr-01 via `ssh -J`) started
hanging with no response — consistent with an inbound DROP rule for `10.10.10.1` at dc-01's firewall, not
a reset. This is the honest catch: **the attack was simulated from rtr-01, which is also the only jump
host into CORP, so blocking the attacker's source IP also blocked my own legitimate admin access** for the
10-minute AR timeout. In a real deployment the attacker's box and the admin's jump host are different
hosts; in this lab, until atk-01 exists (Phase 5), they're the same box by necessity. Documented here
rather than hidden — this is exactly the kind of active-response collateral-damage risk a real SOC has to
reason about (see False-positive risk below).

**Evasion attempts — two, both succeeded (honest gap, not patched here):**
1. *Rate limiting:* staying under 4 failures/60s from one source evades both rules by design — a
   real attacker throttling below the threshold is a known, standard SSH-brute-force evasion technique.
2. *Type-mixing:* the very first live test (6 events: 3 wrong-password + 3 non-existent-user, interleaved)
   evaded detection entirely — each type stayed at 3, under either rule's individual threshold of 4, even
   though 6 total failing attempts hit the host in ~24 seconds. This is the direct, empirically-discovered
   cost of abandoning the group-level `if_matched_group` correlator: the working two-rule design only
   watches one failure type per rule, so an attacker who mixes guess types can split traffic across both
   thresholds without tripping either. A genuine fix would need a proven-working cross-type correlator —
   worth another pass once the `if_matched_group` question is better understood (a case for opening a real
   issue/discussion upstream) or once there's a second CORP host to source a distributed test from.

**False-positive risk:** A legitimate user mistyping their password 3-4 times in a row; more seriously in
this specific topology — **any legitimate traffic proxied through the same jump host as an attacker gets
auto-blocked along with them**, since active response keys on source IP, not on identity or intent. Worth
weighing against the containment value before enabling in anything less contained than a homelab.

---

## 2. T1484.001 — Group Policy Modification (SYSVOL integrity)

**Objective:** Real-time detection of any write under dc-01's SYSVOL share (`/var/lib/samba/sysvol`),
which holds GPOs and logon scripts pushed to every domain-joined host on the next policy refresh/logon —
one unauthorized write there has a blast radius no other monitored path in this lab has.

**Enabling FIM:** default agent config only checked `/etc,/usr/bin,/usr/sbin,/bin,/sbin,/boot` on a
12-hour polling cycle (`<frequency>43200</frequency>`, no realtime). Added a scoped real-time directory in
dc-01's agent `ossec.conf`:

```xml
<directories realtime="yes" report_changes="yes">/var/lib/samba/sysvol</directories>
```

`report_changes="yes"` makes Wazuh keep pre/post hashes and diffs, not just "something changed."

**Attack simulation:** simulated an attacker (or compromised service account) with filesystem access to
dc-01 planting a malicious logon script — `scripts/logon.bat` containing a payload comment — then
modifying and finally deleting it, covering all three FIM event types.

**Raw telemetry observed:** default FIM rules already exist and fired immediately, no custom decoder
needed — `554` (added, level 5), `550` (modified, level 7), `553` (deleted, level 7), each carrying a full
`syscheck` block (path, size, permissions, owner, mtime, MD5/SHA1/SHA256 before/after). These are
identical regardless of *where* under the monitored tree the change happened — a change to
`/etc/hostname` and a change to a GPO logon script both land at the same severity by default.

**Custom rule:** one escalator sitting on top of the three base FIM rules, scoped to SYSVOL specifically
via the `file` dynamic field syscheck decodes into (`syscheck.path` in the JSON, `file` in rule XML):

```xml
<rule id="100020" level="12">
  <if_sid>550,553,554</if_sid>
  <field name="file" type="pcre2">^/var/lib/samba/sysvol</field>
  <description>SYSVOL integrity change (GPO/logon script) — $(file)</description>
  <mitre><id>T1484.001</id></mitre>
  <group>gpo_tampering,attack,</group>
</rule>
```

This doesn't replace the base rules — they still fire and still carry the full record — it adds a second,
much higher-severity alert specifically for this one path, so it can't get lost in routine `/etc` noise.

**Verification (true positive):** confirmed live for all three event types against the real file:

```
Rule: 100020 (level 12) -> 'SYSVOL integrity change (GPO/logon script) — .../scripts/logon.bat'
File '.../scripts/logon.bat' added|modified|deleted    Mode: realtime
```

The `modified` case carried the full diff evidence: size 69→78 bytes, MD5/SHA1/SHA256 before and after.

**Evasion / real limitation (honest, not patched):** no active response is wired to this rule on purpose
— auto-reverting a file is a much riskier default action than blocking an IP (it could clobber a
legitimate GPO edit made seconds earlier), so this stays alert-only pending an actual response playbook.
That means detection here is not prevention: the write completes before any alert is read, so the real
"evasion" is simply outrunning analyst response time, not a technical rule gap. A genuine untested gap:
everything here was simulated via local root shell on dc-01 (standing in for an already-compromised DC or
a service account with filesystem access) — the more realistic T1484.001 path is a *remote* SMB write
from a domain member using a stolen account with an over-permissioned SYSVOL ACL. The underlying
filesystem write is identical either way (inotify doesn't care about the client), but that path is
untested here since it needs a second domain-joined host driving it — worth confirming once ws-01 (or
fs-01, Phase 5) is available to test as the attacker's vantage point instead of dc-01 itself.

**False-positive risk:** legitimate GPO edits (from the Group Policy Management side, or any admin editing
a logon script) fire this rule identically to an attacker — by design, since the point is "alert on any
SYSVOL write, then let a human judge intent," not "distinguish good writes from bad ones." A real
deployment would want this correlated against a change-ticket system or a known-admin allowlist before
treating every alert as an incident.

---

## 3. T1558.003 — Kerberoasting

**Objective:** Detect an attacker with any valid (even low-privilege) domain credentials requesting
Kerberos service tickets (TGS) for service accounts, in order to crack the tickets offline and recover
the service account's plaintext password — the classic AD lateral-movement/privilege-escalation
technique, and one Phase 2's own build plan named as an intended misconfig that never actually got built.

**Setting up the intentional misconfig (retroactively completing Phase 2):** created three Kerberoastable
service accounts on dc-01 — the kind of legacy accounts a real AD environment accumulates over years —
each with an SPN registered (making it a valid Kerberoasting target) and a weak, dictionary-guessable
password (the actual point of the exercise: a Kerberoastable *account* is only a real risk if its
*password* is also weak enough to crack once you have the ticket):

| Account | SPN | Password | Realistic role |
|---|---|---|---|
| `svc-sql` | `MSSQLSvc/dc-01.lab.internal:1433` | `Summer2026` | seasonal-pattern password, SQL service |
| `svc-backup` | `HOST/backup-svc.lab.internal` | `Backup2026` | backup agent |
| `svc-web` | `HTTP/webapp.lab.internal` | `WebApp2026` | IIS/web app pool identity |

Also created `jdoe`, an ordinary domain user with no special privileges, to play the attacker — any valid
domain account can request a TGS for any SPN in the domain; Kerberoasting needs no special access beyond
"has a domain logon," which is what makes it dangerous. Full rationale in
[`phase-2-identity/known-weaknesses.md`](../phase-2-identity/known-weaknesses.md).

**Enabling telemetry — Samba doesn't log this by default:** at the default log level (0), Samba's AD DC
logs nothing about individual Kerberos ticket requests. Enabled structured audit logging in
`/etc/samba/smb.conf`:

```ini
[global]
	log level = 1 auth_audit:3 auth_json_audit:3
```

This makes Samba emit real per-request JSON to `/var/log/samba/log.samba`, alternating with its normal
human-readable lines. Wired as a `log_format=json` Wazuh localfile — the JSON parser silently skips lines
that don't parse as JSON, so the human-readable half is dropped for free without a separate decoder.

**Attack simulation:** authenticated as `jdoe` (`kinit`), then requested service tickets for all three
Kerberoastable SPNs in immediate succession via `kvno` — functionally identical to what
`impacket-GetUserSPNs.py` or Rubeus do (request a TGS per known SPN, extract the encrypted portion for
offline cracking; `kvno` doesn't extract the crackable hash itself, but it performs the exact same TGS-REQ
that a real Kerberoasting tool's request does, and that request is what this detects).

**Raw telemetry observed:** a `"type": "KDC Authorization"` JSON event per ticket, with
`"authType": "TGS-REQ with Ticket-Granting Ticket"`, the requesting account, and the target SPN —
Samba's equivalent of Windows Event ID 4769 (*A Kerberos service ticket was requested*), the exact event
ID real-world Kerberoasting detections are built on:

```json
{"timestamp":"2026-08-15T16:21:01.019867+0000","type":"KDC Authorization","KDC Authorization":
 {"status":"NT_STATUS_OK","serviceDescription":"MSSQLSvc/dc-01.lab.internal:1433@LAB.INTERNAL",
  "authType":"TGS-REQ with Ticket-Granting Ticket","domain":"LAB","account":"jdoe", ...}}
```

**Custom rules:**

```xml
<rule id="100030" level="3">
  <decoded_as>json</decoded_as>
  <field name="type">^KDC Authorization$</field>
  <options>no_full_log</options>
  <description>Samba KDC: TGS-REQ for a service ticket.</description>
  <group>kerberos_tgs,</group>
</rule>

<rule id="100031" level="12" frequency="3" timeframe="60" ignore="120">
  <if_matched_sid>100030</if_matched_sid>
  <same_field>KDC Authorization.account</same_field>
  <description>Kerberoasting suspected — $(KDC Authorization.account) requested 3+ service tickets in 60s.</description>
  <mitre><id>T1558.003</id></mitre>
  <group>attack,</group>
</rule>
```

`<same_field>` — not used in either technique above — correlates on an *arbitrary* dynamic field value
(here, the nested `KDC Authorization.account` JSON key) rather than just source IP; confirmed it works
correctly even with a field name containing a literal space, which Samba's own JSON schema uses (the
top-level key really is `"KDC Authorization"`, space and all).

**Verification (true positive):** confirmed live — 3 real TGS-REQs against the 3 planted SPNs from `jdoe`
in under a second produced:

```
Rule: 100031 (level 12) -> 'Kerberoasting suspected — jdoe requested 3+ service tickets in 60s.'
```

**Evasion attempt — confirmed it works:** re-authenticated as `jdoe` and requested a single additional
ticket (targeting just the one juiciest-looking SPN, as a patient real attacker who's already done
recon would). Confirmed via the alert count before/after: **zero new alerts** — a single targeted request
is indistinguishable from a legitimate client requesting its one normal ticket, and `same_field`
correlation counts *occurrences*, not *distinct SPNs*, so there's no volume signal to catch here at all.
This is an honest, real limitation, not patched: a genuinely un-detectable-by-volume targeted Kerberoast
would need baselining normal per-account SPN request patterns (which SPNs does `jdoe` request in the
course of legitimate work, and does this one fall outside that set) — meaningfully harder than a
threshold rule, and out of scope for what this lab can verify against real telemetry tonight.

**False-positive risk:** a legitimate service or user that genuinely needs 3+ different service tickets
within a minute — a user opening several different mapped drives/services in quick succession at login,
or a monitoring/backup tool that touches multiple services on a schedule — would trip this identically.
Real deployments tune the threshold and/or exclude known service accounts with legitimately bursty
ticket-request patterns from this rule.

---

## 4. T1110.001 — Password Guessing (Kerberos pre-authentication)

**Objective:** Detect an attacker guessing AD account passwords via Kerberos directly (`kinit`, or any
AD-aware tool) — a genuinely different detection surface from the sshd-based T1110 rules (100010/100011)
above, which are completely blind to this vector since it never touches SSH at all. Same ATT&CK ID,
different protocol, same reasoning as before for why real detection catalogs carry more than one rule per
technique: coverage means covering every path an attacker could actually take, not just the first one.

**Attack simulation:** created a throwaway domain account, then attempted `kinit` against it with 4 wrong
passwords in immediate succession — reusing the same `auth_json_audit` telemetry wired up for
Kerberoasting above.

**Raw telemetry observed:** Samba emits `eventId: 4625` (matches real Windows Event ID 4625, *An account
failed to log on*) for each failed pre-auth attempt, with the account name and failure reason:

```json
{"type":"Authentication","Authentication":{"eventId":4625,"status":"NT_STATUS_WRONG_PASSWORD",
 "serviceDescription":"Kerberos KDC","authDescription":"ENC-TS Pre-authentication",
 "clientAccount":"test-lockout@LAB.INTERNAL","becameAccount":"test-lockout", ...}}
```

**Custom rules:**

```xml
<rule id="100040" level="5">
  <decoded_as>json</decoded_as>
  <field name="type">^Authentication$</field>
  <field name="Authentication.eventId">^4625$</field>
  <field name="Authentication.serviceDescription">^Kerberos KDC$</field>
  <options>no_full_log</options>
  <description>Samba KDC: Kerberos pre-authentication failed for $(Authentication.clientAccount).</description>
  <mitre><id>T1110.001</id></mitre>
  <group>authentication_failed,</group>
</rule>

<rule id="100041" level="12" frequency="4" timeframe="60" ignore="120">
  <if_matched_sid>100040</if_matched_sid>
  <same_field>Authentication.clientAccount</same_field>
  <description>Kerberos brute force — $(Authentication.clientAccount) had 4+ pre-auth failures in 60s.</description>
  <mitre><id>T1110</id><id>T1110.001</id></mitre>
  <group>authentication_failures,attack,</group>
</rule>
```

**Verification (true positive):** confirmed live —

```
Rule: 100041 (level 12) -> 'Kerberos brute force — test-lockout@LAB.INTERNAL had 4+ pre-auth failures in 60s.'
```

**Active response — a genuinely custom script, and why:** IP-blocking (the sshd rules' approach) doesn't
fit here — a Kerberos brute force can come from *any* domain member, so blocking one source IP does
nothing once the attacker tries from another host. The right containment is disabling the targeted
*account*, but Wazuh's stock `disable-account` active response only understands local system accounts
(`usermod -L`) — it has no concept of a Samba AD domain account. Wrote a real custom active-response
script instead ([`disable-ad-account.py`](disable-ad-account.py), mirrored here, deployed to
`/var/ossec/active-response/bin/disable-ad-account` on dc-01):

- Parses the JSON payload Wazuh feeds active-response scripts on stdin, pulls the target account out of
  `parameters.alert.data.Authentication.becameAccount`
- On `"command":"add"`, runs `samba-tool user disable <account>`; on `"command":"delete"` (fired
  automatically when the active-response `<timeout>` expires), runs `samba-tool user enable <account>`
- **Hard-excludes `administrator`, `krbtgt`, and `guest`** from automated action — flagged as a real risk
  in the rule's own comment before ever testing it: an attacker who knows this rule exists could otherwise
  weaponize it into a denial-of-service by deliberately failing Kerberos auth *as* a real admin account to
  get it locked out. A response that can be turned into an attack is worse than no response.

**Verified end-to-end, not just "script looks right":**
1. Alert fired → `active-responses.log` on dc-01 recorded `disable test-lockout2: rc=0`
2. `samba-tool user show test-lockout2` — `userAccountControl` flipped from `512` (normal, enabled) to
   `514` (`512 | ACCOUNTDISABLE`) — a real AD-level change, not just a log line
3. Attempted `kinit` against the disabled account **with the correct password** —
   `kinit: Client's credentials have been revoked` — genuine lockout confirmed, not cosmetic
4. Automatic reversal at the 600s timeout — **and a real, unplanned second finding here.** Restarted the
   manager to deploy the next rules (100050/100051 below) while the reversal was still pending, and it
   never fired. `ossec.log` showed exactly why: `wazuh-execd: Shutdown received. Deleting responses.` —
   **restarting `wazuh-execd` (which a full manager restart does) discards every pending scheduled
   active-response reversal**, silently, with no warning and no error. The account stayed disabled
   indefinitely until manually re-enabled (`samba-tool user enable`). This is a genuine operational risk
   worth knowing before relying on AR timeouts in anything resembling production: a routine config
   deploy/restart during an active incident can permanently strand a block or a lockout — the fix is
   either avoiding manager restarts while responses are in flight, or building monitoring that catches
   "should have expired by now, didn't" rather than trusting the timeout blindly. See [[Wazuh]] in the
   vault for the reusable version of this gotcha.

**Evasion:** same core gap as the sshd rules — rate-limiting under 4 failures/60s evades detection
entirely, and this protocol has no equivalent of trying multiple failure "types" to split across rules
(the base account discovery is what's happening here; there's just one failure mode: wrong password).

**False-positive risk — real and worth taking seriously given the active response attached:** a user who
mistypes their password 4 times in a row gets their own account disabled for 10 minutes by the system
that was supposed to be helping them. This is the honest cost of pairing account-lockout active response
with a threshold this tight; a production deployment would want this threshold noticeably looser than the
lab's own AD password lockout policy (if one is even configured — it isn't, here) to avoid the detection
system locking out users before the directory's own native lockout policy would.

---

## 5 & 6. T1053.003 (Cron Persistence) and T1136.001 (Local Account Creation)

Both reuse the real-time FIM machinery proven in T1484.001 — same escalation pattern (default FIM rules
550/553/554 scoped to a specific path set via the `file` field), extended to two more path groups that are
classic Linux persistence/credential targets, distinct from the AD-level techniques above. Adding these
cost almost nothing beyond the SYSVOL work already done, which is exactly the point of building FIM this
way — the pattern is designed to extend.

**Setup:** extended dc-01's real-time FIM directories:

```xml
<directories realtime="yes" report_changes="yes">/etc/cron.d,/etc/cron.daily,/etc/cron.hourly,/etc/cron.weekly,/etc/cron.monthly</directories>
<directories realtime="yes" report_changes="yes">/etc/passwd,/etc/shadow,/etc/sudoers,/etc/crontab</directories>
```

**Attack simulation:**
- **T1053.003:** planted a cron job mimicking a disguised beacon (`/etc/cron.d/system-update-check`, a
  name chosen to blend in with legitimate scheduled maintenance) that would periodically pull and execute
  a remote script — the actual mechanics of cron-based persistence.
- **T1136.001:** ran `useradd -m backdoor-test` — the direct local-account equivalent of what Kerberoasting/
  Kerberos-brute-force above are ultimately after: once an attacker has root on the DC itself (through
  *any* path), planting a local backdoor account is a much simpler, protocol-independent persistence
  mechanism than anything AD-specific.

**Custom rules:**

```xml
<rule id="100050" level="12">
  <if_sid>550,553,554</if_sid>
  <field name="file" type="pcre2">^/etc/cron\.(d|daily|hourly|weekly|monthly)/|^/etc/crontab$</field>
  <description>Cron persistence — $(file) added/modified/deleted.</description>
  <mitre><id>T1053.003</id></mitre>
  <group>persistence,attack,</group>
</rule>

<rule id="100051" level="12">
  <if_sid>550,553,554</if_sid>
  <field name="file" type="pcre2">^/etc/(passwd|shadow|sudoers)$</field>
  <description>Local account/credential file changed — $(file).</description>
  <mitre><id>T1136.001</id><id>T1098</id></mitre>
  <group>persistence,attack,</group>
</rule>
```

Tagged with both MITRE IDs deliberately: the rule can't distinguish creating a new account (`useradd`
writes both `passwd`+`shadow`, T1136.001) from modifying an existing one's password/shell (T1098) — same
file, same rule, same broad-not-narrow tradeoff as the rest of this FIM family.

**Verification (true positive):** both confirmed live —

```
Rule: 100050 (level 12) -> 'Cron persistence — /etc/cron.d/system-update-check added/modified/deleted.'
Rule: 100051 (level 12) -> 'Local account/credential file changed — /etc/passwd.'
Rule: 100051 (level 12) -> 'Local account/credential file changed — /etc/shadow.'
```

`useradd -m` correctly triggered *two* separate alerts (`/etc/passwd` and `/etc/shadow` both get written),
confirming the rule catches the real filesystem-level footprint of account creation, not a synthetic test.

**Evasion:** neither rule requires any specific *content* pattern — any write to these paths fires,
regardless of what changed. That's the honest trade-off already established for SYSVOL: broad and
reliable rather than narrow and gameable, but it means a legitimate `useradd`/`crontab -e` looks
identical to an attacker's, and there's no distinction between "added a line" and "added a malicious
line" — a human (or a future correlation rule cross-referencing *who* ran the change against an expected
maintenance window) has to make that call.

**False-positive risk:** any legitimate system administration touching these paths — routine user
provisioning, a real cron job being added by an admin or a package's postinst script — fires identically.
High-noise by design in a lab with no separate change-management signal to cross-reference against; a real
deployment would pair this with a ticketing/CMDB lookup before treating every alert as an incident, same
caveat as the SYSVOL rule.

---

## 7. T1562.001 — Impair Defenses: Disable or Modify Tools

Arguably the single highest-value rule in this whole catalog: an attacker who successfully disables the
monitoring itself makes every other rule above moot. Every technique before this one assumes the SIEM is
still watching — this is the one that questions that assumption directly.

**Objective:** detect an attempt to stop, disable, or mask the security tooling running on dc-01 itself
(the Wazuh agent, `auditd` if present, or the `samba-ad-dc` service whose logs feed most of this catalog).

**No new telemetry needed — pure escalation on what's already flowing:** chains directly off the stock
sudo rule (`5402`, any successful sudo-to-root, already firing constantly throughout this session) rather
than requiring a new logging facility, decoder, or FIM path. The whole rule is a regex over the `command`
field the stock `sudo` decoder already extracts.

**Attack simulation — a genuinely self-defeating test, handled honestly:** the obvious test
(`systemctl stop wazuh-agent`) has an irony baked in — an agent that's just been killed can't report that
it was killed, so the test would risk failing for a reason that has nothing to do with whether the rule
works. Used `systemctl disable wazuh-agent` instead: it matches the exact same detection pattern (and is
a real, meaningfully dangerous action — it prevents the agent from surviving the *next* reboot, a
realistic low-and-slow persistence-denial move) while leaving the agent running long enough to actually
report the alert it just triggered.

**Custom rule:**

```xml
<rule id="100060" level="13">
  <if_sid>5402</if_sid>
  <field name="command" type="pcre2">systemctl\s+(stop|disable|mask)\s+\S*(wazuh-agent|auditd|samba-ad-dc)|service\s+(wazuh-agent|auditd|samba-ad-dc)\s+stop</field>
  <description>Security tooling disruption attempt — $(command)</description>
  <mitre><id>T1562.001</id></mitre>
  <group>defense_evasion,attack,</group>
</rule>
```

**Verification (true positive):** confirmed live —

```
Rule: 100060 (level 13) -> 'Security tooling disruption attempt — /usr/bin/systemctl disable wazuh-agent'
```

Level 13 — one level above everything else in this catalog — deliberately: this alert type should never
get lost in a busy queue behind routine credential-access noise.

**Evasion — real, and worth being upfront about:** only catches the *obvious* path (systemctl/service
managing the named unit by name). A more careful attacker sends `SIGSTOP`/`SIGKILL` directly to the
`wazuh-agent` process, blocks `1514/tcp` outbound at the host firewall, or corrupts the agent's own config
— none of which touch this rule, since none of them are a sudo command matching this text pattern at all.
A production deployment would pair this with **manager-side "agent went silent unexpectedly" monitoring**
(Wazuh's own agent-disconnection alerting) as the real backstop — that path doesn't depend on the
compromised agent reporting anything, which is the whole point once an attacker is sophisticated enough
to avoid the obvious command-line path this rule watches.

**False-positive risk:** low in a small lab (legitimate reasons to stop the Wazuh agent — patching,
planned maintenance — are rare and usually scheduled), but real in any environment with routine agent
upgrades/restarts as part of normal ops; those would need an allowlist window rather than firing this as
an incident every time.

---

# Windows / Sysmon Techniques (ws-01)

**A genuinely different kind of detection-engineering work than techniques 1-7, worth stating explicitly.**
The Linux/AD side above needed heavy custom rule authorship because Samba's default logging is sparse —
Kerberos ticket requests, brute-force attempts, none of it existed until `auth_json_audit` was explicitly
enabled and rules written from scratch against it. The Windows side is the opposite: Sysmon plus a mature
community config (Olaf Hartong's modular ruleset) plus Wazuh's own bundled Sysmon rules already produce
rich, correctly ATT&CK-tagged detections for a large fraction of common techniques, out of the box, with
zero custom rule-writing. The real engineering work here was different in kind, not lesser: selecting a
good config, wiring the log pipeline correctly (event channels, PowerShell Script Block Logging, which
is off by default), and — the part that actually matters — *verifying* the stock coverage against real
attacks rather than assuming a config file downloaded from GitHub does what it claims. That verification
work found one real gap (T1547.001, below) that a less rigorous pass would have missed entirely.

**Setup:** installed Sysmon (native ARM64 build, `Sysmon64a.exe`, matching this lab's ARM64-only theme)
with Olaf Hartong's config; wired `Microsoft-Windows-Sysmon/Operational` and
`Microsoft-Windows-PowerShell/Operational` into Wazuh as `eventchannel` localfiles; enabled PowerShell
Script Block Logging via registry (`HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging`,
off by default — without it the PowerShell channel carries almost nothing useful). All of this reused a
`localadmin` SSH session bootstrapped the same key-based way as the Linux hosts, once Windows OpenSSH
Server was manually enabled and given an inbound firewall rule (neither is automatic from installing the
optional feature alone — a real, if mundane, gotcha in its own right, in [[Windows OpenSSH Server]] in the
vault).

## 8. T1059.001 — PowerShell (encoded command)

**Objective:** detect obfuscated/encoded PowerShell execution — the base64 `-EncodedCommand` pattern is
one of the most consistently-cited real-world indicators of malicious PowerShell use, precisely because
it's how an attacker avoids having their actual command appear in plaintext in the process command line.

**Attack simulation:** a parent PowerShell process base64-encoded a benign reconnaissance command
(`whoami; hostname; Get-Process ...`) and spawned a child `powershell.exe -EncodedCommand <base64>` to
execute it — the exact mechanical pattern real encoded-PowerShell attacks use, with harmless payload
content.

**Coverage:** stock rule `92057` (`0800-sysmon_id_1.xml`) — `if_group=sysmon_event1` +
`parentImage` matches `powershell.exe` + `commandLine` matches an encoded-command flag
(`-encodedcommand`/`-e`/`-ec`/etc., case-insensitive, several aliases covered).

**Verification (true positive):** confirmed live —

```
Rule: 92057 (level 12) -> 'Powershell.exe spawned a powershell process which executed a base64 encoded command'
```

**Evasion:** the regex covers the standard flag spellings but PowerShell accepts *any unambiguous prefix*
of `-EncodedCommand` (`-e`, `-en`, `-enc`, ... all the way to the full name) — the rule's own alternation
list already anticipates this, which is a sign of a well-written rule, not a gap. A real evasion:
splitting the encoded payload across an environment variable or a here-string built at runtime rather
than passing it directly on the command line at all — the classic cat-and-mouse of command-line-based
detection versus in-memory/staged execution.

**False-positive risk:** legitimate remote-management tooling (some RMM/deployment tools, some
CI/CD-style automation) does use `-EncodedCommand` for legitimate reasons (safely passing complex
multi-line scripts through layers of shell quoting) — this is a real source of noise in any environment
using such tooling, worth an allowlist for known-legitimate callers rather than blanket suppression.

## 9. T1547.001 — Registry Run Keys (real gap found and closed)

**Objective:** detect persistence via the classic `HKLM/HKCU\...\CurrentVersion\Run` autostart mechanism.

**What was tried and found:** wrote the identical Run key twice, once via `reg.exe` and once via
PowerShell's `New-ItemProperty` cmdlet. Wazuh's stock Sysmon EID 13 rules (`0860-sysmon_id_13.xml`) only
escalate to a visible alert for narrow sub-patterns — `reg.exe` usage specifically (rule `92302`), a
suspicious file extension in the value (`92301`), or a known remote-access-tool signature (`92303`). The
base classification rule (`92300`, any write to a Run/RunOnce key) is level 0 — matched internally,
**never alerted**. The `reg.exe` write correctly triggered `92302`; the PowerShell write — arguably the
*more* realistic real-world method, since `reg.exe` usage is comparatively old-school and heavily
signatured while PowerShell-based persistence is extremely common in current tooling — **produced zero
alerts**, confirmed by direct comparison, not assumption.

**Custom rule (closes the gap):**

```xml
<rule id="100070" level="10">
  <if_sid>92300</if_sid>
  <description>Registry Run key persistence — $(win.eventdata.image) set $(win.eventdata.targetObject)</description>
  <mitre><id>T1547.001</id></mitre>
  <group>persistence,attack,</group>
</rule>
```

Escalates the base rule generically regardless of which tool performed the write — deliberately one level
below the stock rules' specific-pattern escalations (10 vs. 12), since broadening coverage this way
means firing on legitimate app installers too, not just attacks; that tradeoff is named honestly rather
than hidden behind a high severity that overstates confidence.

**Verification (true positive):** confirmed live, closing exactly the gap identified above —

```
Rule: 100070 (level 10) -> 'Registry Run key persistence — C:\WINDOWS\System32\WindowsPowerShell\v1.0\powershell.exe set HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\TestPersistence3'
```

**Evasion:** `HKCU` (per-user) Run keys, `RunOnce` variants beyond what `92300`'s regex covers, and the
dozen-plus *other* legitimate Windows autostart locations (Startup folder, services, scheduled tasks,
WMI event subscriptions, AppInit_DLLs, etc.) are outside this specific rule's scope entirely — T1547 has
over a dozen sub-techniques for a reason, and this rule (like the stock ones it extends) only covers one.

**False-positive risk:** real and non-trivial by design (see above) — this is the honest cost of closing
a real detection gap rather than a free win.

## 10. T1053.005 — Scheduled Task

**Objective:** detect Windows Task Scheduler used for persistence — the Windows equivalent of the cron
technique already covered on dc-01 (#5), same tactic, completely different mechanism and telemetry.

**Attack simulation:** created a scheduled task set to run at every logon as SYSTEM
(`schtasks /create /tn "WindowsUpdateCheck" /tr ... /sc onlogon /ru SYSTEM`) — a deliberately
innocuous-sounding task name, matching how a real persistence attempt would try to blend in with
legitimate Windows Update-adjacent naming.

**Coverage:** Sysmon's own config tags the process creation with `technique_id=T1053.005` directly (Olaf
Hartong's config embeds ATT&CK metadata in the Sysmon `RuleName` field itself); Wazuh's stock rule `92154`
alerts specifically on the `taskschd.dll` module load that `schtasks.exe` triggers.

**Verification (true positive):** confirmed live —

```
Rule: 92154 (level 4) -> 'Process loaded taskschd.dll module. May be used to create delayed malware execution'
```

Real, working coverage — level 4 is modest, appropriately so for a signal this common in legitimate
administration (task creation itself isn't inherently suspicious; the *content and context* of the task
is), and not treated here as a gap needing a custom escalation the way the Registry Run Key case was.

**False-positive risk:** high without additional context — routine software installers, backup tools, and
IT automation all legitimately create scheduled tasks constantly. This rule is a starting point for
investigation, not an incident on its own.

## 11. T1070 / T1070.004 — Indicator Removal: Clear Windows Event Logs

**Objective:** detect anti-forensic log clearing — arguably as important as detecting the *original*
attack, since a sophisticated attacker's last move is often erasing the evidence of everything before it.

**Attack simulation — two variants, deliberately:** cleared the `Application` log
(`Clear-EventLog -LogName Application`, a lower-stakes test) and separately the `Security` log
(`wevtutil cl Security`, the actual high-value target for anti-forensics, since that's where authentication
and privilege-use evidence lives).

**Coverage:** stock rules matching Windows Eventlog service events — Event ID 104 (*"The X log file was
cleared"*, generic, any channel) and Event ID 1102 (*"The audit log was cleared"*, Security-log-specific,
the more critical signal).

**Verification (true positive):** both confirmed live —

```
Rule: 63104 (level 5) -> 'A Windows log file was cleared'   [Application log]
Rule: 63103 (level 5) -> 'The audit log was cleared'         [Security log]
```

Both alerts carry real forensic detail beyond just "a log was cleared" — the exact account, domain, and
client process ID that performed the clear are captured in the structured `logFileCleared` fields, which
is exactly the information needed to actually act on this alert rather than just acknowledge it happened.

**Evasion:** neither rule requires elevated logging levels to fire — this coverage is solid as long as
the *Eventlog service itself* is still running and able to log its own clear-events. A sufficiently
privileged attacker stopping the Eventlog service first, or tampering with the log files directly at the
filesystem level while the service is down, would evade this specific detection (a variant of the same
"disable the monitoring first" problem T1562.001 addresses on the Linux side).

**False-positive risk:** low — clearing the Security log in particular has essentially no legitimate
routine use case in most environments; this is one of the highest-confidence alerts in the whole catalog.

## 12. T1003.001 — LSASS Memory (OS Credential Dumping)

**Objective:** detect an attempt to dump LSASS process memory to extract cached credentials — one of the
most consequential AD-adjacent techniques there is, and the natural escalation path from "has a foothold
on a workstation" to "has domain credentials."

**Coverage confirmed by inspection:** stock rule `92900` (`0945-sysmon_id_10.xml`) —
`targetImage` matches `lsass.exe`, `grantedAccess` matches `0x1010` or `0x40` (the access masks that
correspond to read access sufficient for a memory dump), with an explicit negation excluding common
legitimate callers (`C:\Program Files\...`, `wmiprvse.exe`). This is correctly-written, real detection
logic — verified by reading it, the same standard applied to every rule in this catalog, not just the
custom ones.

**Attack simulation — thorough, and a real multi-layer finding, not a shortcut:**
1. **`comsvcs.dll` MiniDump technique** (`rundll32.exe comsvcs.dll, MiniDump <lsass_pid> ... full`), the
   standard textbook LSASS-dump method — **blocked in real time by Windows Defender** (confirmed via
   `Get-MpThreatDetection`: `ThreatStatusID: 4`, remediated) before Sysmon could observe a qualifying
   `ProcessAccess` event at all.
2. Attempted to test the Sysmon/Wazuh layer independently of Defender (standard, legitimate
   detection-engineering practice — testing each defensive layer in isolation) by disabling Defender's
   real-time protection — `Set-MpPreference -DisableRealtimeMonitoring $true` **silently had no effect**,
   because **Windows 11's Tamper Protection blocks this specific change via script/registry with no
   error message at all**, by design, specifically to stop this exact bypass (including by real malware).
   Tamper Protection can only be toggled through the Windows Security GUI — deliberately not scriptable.
3. With Tamper Protection and real-time protection both genuinely off (confirmed via
   `Get-MpComputerStatus`), retried the `comsvcs.dll` technique — still failed, `ACCESS_DENIED`
   (`0x80070005`), even from an elevated Administrator session.
4. Investigated further rather than assuming: `SeDebugPrivilege` is *present* in an elevated token but
   not *enabled* by default, and doesn't propagate to a child process spawned via `Start-Process` — a real
   Windows token-privilege nuance. Enabling it in-process (`[System.Diagnostics.Process]::EnterDebugMode()`)
   and attempting an in-process `MiniDumpWriteDump` via P/Invoke still failed.
5. **Root cause confirmed via registry:** `HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\RunAsPPL = 2` —
   **LSASS is running as Protected Process Light at the strongest enforcement tier.** This is Microsoft's
   real, modern mitigation for this entire technique class, correctly enabled on this Windows 11 build,
   and it structurally prevents *any* userland process — regardless of privilege level — from opening a
   memory-read handle to LSASS. Zero Sysmon telemetry was ever generated across all attempts, because the
   OS rejects the access before it reaches a point Sysmon's hooks would observe.

**The line deliberately not crossed:** defeating LSASS PPL for real requires loading a vulnerable signed
kernel driver to strip the protection — a genuine, real-world technique used by actual credential-theft
tooling. Building that is exploit development, not detection engineering, and was not attempted here,
even in this authorized, isolated lab — that's a different category of work with a different risk profile,
not a box to check for catalog completeness.

**Verification method used instead — testing what could honestly be tested:** since `wazuh-logtest`
worked for the Samba/JSON sources earlier in this catalog, tried it here too, with a synthetic Sysmon
Event ID 10 payload carrying exactly the field values rule 92900 requires
(`targetImage=lsass.exe`, `grantedAccess=0x1010`). **It didn't fire — a distinct, deeper limitation than
the one already documented for Suricata/Samba sources.** Tracing the rule's full `if_sid` chain
(`92900 → 61612 → 61600 → 60004 → 60000`) found the actual base condition:
`<rule id="60000"><decoded_as>windows_eventchannel</decoded_as>...`. `wazuh-logtest` decodes a raw pasted
JSON blob via the generic `json` decoder, never the `windows_eventchannel` decoder real Windows-agent
traffic is tagged with at ingestion — no amount of payload accuracy can substitute for that, since it's a
property of the ingestion path, not the content. This confirms `wazuh-logtest` cannot verify *any*
eventchannel-sourced rule via manual paste, a stronger and more precise version of the earlier finding
(see [[Wazuh]] in the vault, updated with both).

**Status: coverage confirmed correct by code inspection; live-fire blocked by a working OS mitigation
(LSASS PPL); rule-logic verification blocked by a `wazuh-logtest` architectural limitation.** Genuinely
the most technically involved investigation in this whole catalog, and arguably a *better* portfolio
entry than a clean true-positive would have been — it demonstrates defense-in-depth working correctly at
three independent layers (AV, Tamper Protection, PPL) and the judgment to recognize where legitimate
detection-engineering verification ends and exploit development begins.

**False-positive risk (of the rule itself, as written):** the negation for `Program Files`/`wmiprvse.exe`
already excludes the most common legitimate callers (AV/EDR products, WMI-based monitoring); residual
noise would mostly come from legitimate credential-management/SSO tooling that genuinely needs
LSASS read access, which any real deployment running this rule would need to allowlist by path.

---

## Investigated, not achieved: T1098.007 (Account Manipulation — privileged group membership)

Worth documenting the dead end itself, not just the successes — this is a real, tested platform
limitation, not a skipped step.

**Goal:** detect an attacker adding an account to Domain Admins (or any privileged group) — one of the
most consistently-monitored events in real-world AD security (Windows Event ID 4728/4732, *A member was
added to a security-enabled group*), and a natural next step after Kerberoasting or brute-forcing your way
to a privileged credential.

**What was tried:** Samba's `auth_json_audit` (proven, working — everything above is built on it) only
covers *authentication* events. Directory-object *modification* has its own logging facility family in
Samba's source (`dsdb_audit`), so enabled every plausible variant in `smb.conf`:

```
log level = 1 auth_audit:3 auth_json_audit:3 dsdb_audit:3 dsdb_json_audit:3 dsdb_group_audit:3 dsdb_group_json_audit:3 dsdb_password_audit:3 dsdb_password_json_audit:3
```

**Test methodology (to rule out "the change didn't actually happen" as the explanation):** created a
dedicated `adm-test` account, added it to Domain Admins locally (as a one-time bootstrap, not part of the
test itself), then authenticated as `adm-test` **over the network LDAP protocol**
(`samba-tool group addmembers "Domain Admins" jdoe -H ldap://dc-01.lab.internal -k yes`) — the same path a
real remote attacker would use, not a local-database shortcut. Confirmed the modification genuinely
succeeded (`samba-tool group listmembers "Domain Admins"` showed `jdoe` added) and confirmed the
*authentication* half of that same operation *was* captured correctly (a real `KDC Authorization` TGS-REQ
event for the `ldap/dc-01.lab.internal` SPN, exactly like the Kerberoasting telemetry above) — proving the
audit pipeline itself works and the gap is specifically in directory-modification logging, not the whole
mechanism.

**Result:** zero output from any `dsdb_*` facility, across all four variants tried, for a change verified
to have genuinely happened via the exact real-world attack path. This is a genuine capability gap in this
Samba AD DC build (4.23.6) versus a real Windows Server DC, which supports this natively — and a concrete,
honest cost of the Samba pivot documented in `docs/design-decisions.md`: the protocol behavior an attacker
exercises is identical either way, but the *defender's* visibility into it is not automatically identical,
and this is the first place in the whole catalog where that gap actually bit.

**Cleaned up before moving on:** removed `jdoe` from Domain Admins and deleted `adm-test` entirely — both
were test artifacts, not intentional misconfigurations, and leaving an undocumented extra Domain Admin
account in place would have quietly corrupted the AD state for Phase 5's BloodHound work later.

**Not pursued further tonight:** the remaining option — registering a real LDB audit-log module in the
schema rather than a log-level flag — is a materially bigger, more invasive change than anything else in
this catalog, and risks the live DC for a payoff that isn't guaranteed. Worth a dedicated pass later, not
squeezed in as a footnote to something else.

---

## SCA — CIS Benchmark, before/after remediation (dc-01)

Different Wazuh capability than the rule-writing above — compliance/configuration benchmarking against a
recognized standard (CIS), not attack-simulation-driven. Still real detection-engineering-adjacent work:
knowing your actual hardening posture is what tells you which techniques above are even worth writing
rules for.

**Gotcha before any score exists at all:** the only SCA policy Wazuh ships (`cis_ubuntu22-04.yml`) gates
itself on `/etc/os-release` matching literally `Ubuntu 22.04` — dc-01 runs 26.04, so the scan module
loaded the policy, then immediately logged `Skipping policy ... 'Check Ubuntu version.'` and reported a
scan with **zero checks run**, no error, no obviously-broken output. Easy to miss entirely if you only
glance at "scan finished" in the log rather than actually checking whether it evaluated anything.

Fixed by relaxing that one version-gate regex directly in the vendor policy file
(`/var/ossec/ruleset/sca/cis_ubuntu22-04.yml`), leaving all ~400 actual CIS controls untouched — most
Linux hardening checks (SSH config, password policy, filesystem permissions, auditd rules) aren't actually
version-specific, so re-gating rather than rewriting was the honest fix. Real tradeoff, documented rather
than hidden: this is a local edit to a package-managed file, so a future `apt upgrade` of the Wazuh agent
package will silently revert it — worth re-checking after any agent upgrade. A separate attempt to keep
an unmodified vendor copy alongside an adapted one in `etc/shared/` failed outright: Wazuh validates check
IDs *globally* across every loaded policy, and a literal copy reuses every ID, so the second file got
rejected wholesale as a duplicate (`Found duplicated check ID: 28500`) rather than coexisting. In-place
edit was the only approach that actually worked, not just the simplest one.

A second, subtler gotcha in the same fix attempt: the first regex patch (`r:Ubuntu 22.04|r:Ubuntu 26.04`)
looked reasonable but was wrong — the SCA rule DSL's `r:` prefix applies once to everything after `->`,
so writing it twice makes the second `r:` literal text the regex has to match, not a second marker. The
policy still silently skipped after that "fix," for a subtly different reason than the original problem.
Caught only by checking `/etc/os-release`'s actual content against the pattern by hand.

**Baseline (before):**

```
SCA summary: CIS Ubuntu Linux 22.04 LTS Benchmark v2.0.0: Score less than 50% (48)
passed: 96   failed: 100   invalid: 11   total_checks: 207
```

**Remediated** (safe, verified-non-breaking items only — nothing touching partitioning, the firewall, or
anything that risked Kerberos/DNS/Samba on a live DC):
- `sshd_config`: `PermitRootLogin no`, `MaxAuthTries 4` (deliberately pairs with the T1110 rules above —
  defense in depth, not redundant: MaxAuthTries caps attempts *per connection*, the Wazuh rules catch
  attempts *across* connections/time), `Banner /etc/issue.net`; inserted before the `Include` line since
  OpenSSH takes the first occurrence of a directive, matching CIS's own remediation note
- `chmod u-x,og-rwx /etc/ssh/sshd_config` (was world-readable)
- Ownership/permissions on `/etc/crontab`, `/etc/cron.{hourly,daily,weekly,monthly,d}`
- `/etc/issue` and `/etc/issue.net` login banners
- Disabled and masked `apport` (automatic error reporting)

Verified the reload didn't break admin access before treating any of this as done — `sshd -t` for syntax,
`systemctl reload ssh` (not `restart`, to avoid dropping the active session), then a fresh connection from
the Mac through the ProxyJump path to confirm key auth still worked end to end.

**After:**

```
SCA summary: CIS Ubuntu Linux 22.04 LTS Benchmark v2.0.0: Score less than 80% (55)
passed: 108   failed: 88   invalid: 11   total_checks: 207
```

**48% → 55%**, +12 checks passed, zero downtime, verified by re-running the scan rather than assuming the
config changes mapped cleanly to the checks intended.

**What was deliberately left failing:** partition-layout checks (`noexec`/`nodev` on `/tmp`, `/var`, etc.)
— this lab's disks were never split into separate partitions, and redoing partitioning on a live domain
controller to satisfy a benchmark isn't a real remediation, it's a rebuild; auditd rule installation —
real value, but overlaps enough with what Wazuh's own FIM/log collection already covers here that it felt
like padding the score rather than closing a real gap; firewall checks (`ufw`/`iptables`/`nftables` base
policy) — dc-01 isn't the segmentation boundary (rtr-01 is, see Phase 1), and a default-deny host firewall
on the DC risks breaking AD DS/DNS/Kerberos ports for the sake of a checkbox. **The score is a prioritization
signal, not a target to max out** — every unfixed item above has a specific, stated reason, which is the
actual point of running this rather than just chasing the percentage up.

---

*(Additional techniques added as Phase 4 progresses — target is 8–12 total per the build plan, covering
both dc-01/rtr-01 Linux telemetry and ws-01 Windows/Sysmon telemetry once ws-01 is back online.)*

---

## Phase 5 additions (offense-in-context)

Two custom detections written to close gaps found while executing a BloodHound-mapped attack path from the
Kali attacker box. Full attacker/defender walkthrough: [`../phase-5-offense/attack-detect-writeups/`](../phase-5-offense/attack-detect-writeups/).

### T1003.006 — DCSync (rule 100080, level 12)

An attacker with replication rights (here svc-backup, deliberately granted `DS-Replication-Get-Changes[-All]`)
asks the DC to replicate account secrets via MS-DRSR `DsGetNCChanges`. In this **single-DC** domain there
is no legitimate DC-to-DC replication, so any `DsGetNCChanges` is an attack. The rule matches Samba's
replication-handler log line (`dcesrv_drsuapi_DsGetNCChanges`) forwarded via journald.
- **Gotcha:** a rule `<location>` filter silently blocks a `<match>` rule on agent-forwarded logs — it fails
  in `wazuh-logtest` *and* production. Dropping it and relying on the unique `<match>` string fixed it.
- **Samba note:** impacket's DCSync doesn't complete against Samba (`Failed to decode remote prefixMap`),
  but the request still reaches the DC — detection doesn't depend on the exploit succeeding. Raise
  `log level drsuapi:5` to also catch a *successful* replication from a non-buggy client.

### T1552.001 — Unsecured Credentials in Files, share read (rule 100090, level 12)

FIM catches file *changes*, never *reads*, so reading the planted credential on the fs-01 weak share
produced no alert. Samba `full_audit` on `[public]` logs every `openat` to `smbd_audit` (journald); a
custom decoder (`samba-full-audit`, **child of the stock `smbd` decoder** — a plain sibling gets shadowed
since first match wins) parses the pipe-delimited line into `smb_user`/`srcip`/`smb_path`. The rule fires
on a read of `map-backup-share.ps1`, reporting the user and source IP.

## Discovery-tactic additions (ATT&CK-mapping gaps, 2026-08-27)

Driven by running an **Atomic Red Team** Discovery battery on ws-01 (now that ART is installed —
`phase-5-offense/atomic-red-team/`) and diffing what fired in Wazuh against what *should* map. 21 built-in,
offline-safe tests across seven techniques (T1087.001 / T1082 / T1016 / T1057 / T1049 / T1518.001 /
T1069.001) → 625 alerts, 39 distinct rules. Method: exercise → observe (query the indexer by rule.id +
`rule.mitre.id`) → write rules for the gaps → **re-run and confirm each new rule fires**.

**Gap analysis (what stock coverage actually maps):**
- Stock rule **92031** ("Discovery activity executed", T1087) matches **only `net.exe`/`net1.exe`** — so
  `net localgroup` (Permission Groups Discovery) is caught but **mis-tagged T1087** instead of T1069.001.
- **ipconfig / netsh / arp / route / nbtstat / nslookup (T1016)** and **netstat (T1049)** have **no stock
  rule** — they decode fine as Sysmon EID1 but map to no technique.
- **Security Software Discovery (T1518.001)** — enumerating Sysmon/Defender/EDR — has **no stock
  detection** either.

Eight rules added (100100–100107), each covering both telemetry paths — native binaries via **Sysmon EID1**
(`<if_group>sysmon_event1</if_group>`, match `originalFileName`/`commandLine`) and PowerShell cmdlet
equivalents via **Script Block Logging EID 4104** (`<if_sid>91802</if_sid>`, match `scriptBlockText`):

| Rule | Technique | Telemetry | Level | Verified |
|---|---|---|---|---|
| 100100 | T1016 | Sysmon EID1 (ipconfig/netsh/arp/route/nbtstat/nslookup) | 4 | ✅ fires |
| 100101 | T1016 | PS 4104 (Get-Net*/Get-DnsClientServerAddress) | 3 | ✅ fires |
| 100102 | T1049 | Sysmon EID1 (netstat) | 4 | ✅ fires |
| 100103 | T1049 | PS 4104 (Get-NetTCPConnection/Get-NetUDPEndpoint) | 3 | ✅ fires |
| 100104 | T1518.001 | Sysmon EID1 (sc/reg/tasklist/net querying AV/EDR/Sysmon) | 6 | ✅ fires |
| 100105 | T1518.001 | PS 4104 (Get-MpComputerStatus/Get-MpPreference/…) | 6 | ✅ fires |
| 100106 | T1069.001 | Sysmon EID1 (net localgroup — refines 92031) | 3 | ✅ fires |
| 100107 | T1069.001 | PS 4104 (Get-LocalGroup/Get-LocalGroupMember) | 3 | ✅ fires |

**Severity model:** pure host/network discovery (T1016/T1049/T1069.001) stays low (3–4) — these run
constantly in legitimate admin/logon activity, so they're tagged-and-queryable for hunting and for the
ATT&CK Navigator coverage layer, not paged on. Security-software discovery is level 6: "what's watching
me?" is a much stronger pre-attack tell and far rarer in normal activity.

**Three findings surfaced only by verifying (not by writing the rules):**
1. **Wazuh reports one rule per event, so a level *tie* silently shadows.** At level 3, the native
   T1016/T1049 rules never appeared — the same events also match stock **92032** (L3, generic
   "Suspicious cmd shell execution", tagged T1087/T1059.003) when spawned via `cmd /c`, and the stock rule
   won the tie, keeping the imprecise tag. Bumping 100100/100102 to **level 4** makes the precise mapping
   win. (This is also why the L6 security-software rules always win, and why 100106 — a *child* of 92031 —
   supersedes its parent.)
2. **Script Block Logging can log a whole multi-command script as one 4104 event**, so several of these PS
   rules matched the *same* event and only the highest-level one was reported — `Get-LocalGroup` (100107)
   looked like it wasn't firing until run in isolation. Real per-command invocations log separately, so
   this is a test artifact, not a rule bug — but worth knowing when verifying script-block rules.
3. **False positive to note:** ART's own harness trips stock rule **92213** (L15, "Executable dropped in
   folder commonly used by malware", T1105) ~26× per battery as it stages atomic payloads to disk. Not
   real malware — a tuning artifact of running ART itself; a real environment would exclude the atomics
   path or treat 92213-from-the-ART-runner as expected.

**Also found while doing this (fixed, see `phase-7-automation`):** ws-01's clock was ~3h fast — its
timezone was Pacific while the host/domain are US Eastern, and Windows reading the VM RTC as local time
pushed its computed UTC 3h ahead, silently mis-timestamping all Sysmon telemetry relative to the SIEM.
(The verification query missed the first battery entirely until re-run by manager-receipt time.) Fixed by
correcting the zone and disciplining `w32time` to rtr-01's chrony (10.10.10.1, the lab's internal NTP);
codified in the `windows` role, converges at `changed=0`.

**Evasion / limits (honest):** the ideal actionable layer is a correlation rule that fires *high* when many
*distinct* discovery commands hit one host in a short window (a host-enumeration sweep, vs. a single benign
ipconfig). That needs cross-rule correlation via `<if_matched_group>`, which is non-functional in this
Wazuh build — the same limitation already documented for the T1110 sshd rules — so it's deferred rather
than shipped broken. These per-technique rules are precise ATT&CK mapping + telemetry coverage, not a
low-FP paging signal on their own.

## Discovery-tactic additions, batch 2 — domain-scoped (2026-08-27)

Extends the local-discovery batch to the AD-facing commands, run against dc-01 and mapped by diffing.
Six rules (100108–100113), all **level 4–5** to win the one-rule-per-event tie over the generic stock
discovery rules (the level-tie lesson from batch 1). Techniques 17–21.

| Rule | Technique | Command | Fix / gap it closes |
|---|---|---|---|
| 100108 | T1087.002 Domain Account | `net user /domain` | stock only tagged generic T1087 |
| 100109 | T1069.002 Domain Groups | `net group [/domain]` | **corrects a bug in 100106**, which had conflated `net group` (domain) with `net localgroup` (local) and tagged both T1069.001 |
| 100110 | T1018 Remote System | `nltest /dclist` | no stock rule |
| 100111 | T1482 Domain Trust | `nltest /domain_trusts` | stock mistagged it T1087 |
| 100112 | T1087.002 (PowerShell) | `[adsisearcher]`, `Get-AD*` | no stock rule; ADSI needs no RSAT (LotL domain enum) |
| 100113 | T1201 Password Policy | `net accounts` | no stock rule |

**The `net group` vs `net localgroup` bug (worth calling out):** `net group` queries the DC for global
groups = T1069.**002**; `net localgroup` is the local machine = T1069.**001**. The batch-1 rule 100106
matched `\b(localgroup|group)\b` and tagged everything .001. Tightened 100106 to `localgroup` only and
gave 100109 the domain case (`\bgroup\b` — the word boundary excludes "localgroup"). A reminder that a
sub-technique split can hinge on one word in the command line.

**Two nltest quirks, found only by reading the raw Sysmon events:**
1. **nltest's PE `OriginalFileName` is `nltestrk.exe`** (Resource Kit heritage), not `nltest.exe` — so a
   rule keyed on `originalFileName` silently misses it (net.exe-style matching does *not* transfer). Key
   on the distinctive `/dclist`/`/domain_trusts` switch in the command line instead.
2. **The direct `nltest.exe /dclist` process event is logged inconsistently here**, while the
   `cmd /c "nltest /dclist…"` wrapper event reliably carries the switch. So 100110 matches the command
   line on any process and is **level 5** to beat the stock cmd rule 92004 (L4) that also matches the
   wrapper — catching the invocation whichever event survives.

## T1218 — System Binary Proxy Execution (LOLBins), batch 3 (2026-08-27)

Ran an ART T1218 battery (mshta / regsvr32 / rundll32). Techniques 22–24; three rules (100114–100116),
all level 4 to win the one-rule-per-event tie over the generic stock cmd rule.

| Rule | Technique | LOLBin | Pattern matched |
|---|---|---|---|
| 100114 | T1218.010 | regsvr32 | `scrobj.dll` / `/i:` scriptlet (Squiblydoo) |
| 100115 | T1218.011 | rundll32 | `javascript:` / `vbscript:` / `RunHTMLApplication` / `LaunchINFSection` moniker |
| 100116 | T1218.005 | mshta | `vbscript:` / `javascript:` / `http(s):` / `.hta` |

**The gap:** the LOLBins that execute (regsvr32 Squiblydoo, rundll32) were detected only by the generic
stock cmd rule 92032 and **mis-tagged T1087** — nothing mapped them to T1218 System Binary Proxy
Execution. These rules add the correct mapping. Deliberately high-signal patterns only (script monikers /
scriptlets / INF-exec / HTA), not the bare binaries — rundll32 in particular runs constantly for
legitimate reasons, so plain `Control_RunDLL` is intentionally not matched (accepted evasion tradeoff).

**A wrong hypothesis, corrected by checking (worth recording):** the ART mshta-vbscript and
rundll32-vbscript tests both errored at the harness `.Start()` with *Access is denied*, which looked like
VBScript deprecation (Microsoft is retiring it). **It wasn't** — verified on the host that the `VBSCRIPT`
Windows capability is *Installed*, `cscript` runs a `.vbs`, and `mshta vbscript:close` exits 0. Attack
Surface Reduction is also not configured (empty rule set). The most likely cause is Defender real-time
protection killing the specific malicious *child-spawn* chain the ART payloads build (mshta → WScript.Shell
→ spawn) — a live defense, not a missing engine. Either way the LOLBin **process still launches with its
telltale command line**, so detection is verified by invoking the binary directly with a representative
moniker (the same "confirmed by exercising the observable, not the payload" approach as the LSASS-PPL
case). Lesson: check the assumption on the host before writing the finding — a plausible story (VBScript
is dead) was simply false here.

## T1548.002 — Bypass UAC (Privilege Escalation), batch 4 (2026-08-27)

Ran the classic registry-hijack UAC bypasses (fodhelper / eventvwr / sdclt / disable-via-reg). Technique
25 — the first **Privilege Escalation** technique in the catalog. Two rules (100117/100118).

**Coverage diff:** stock rule 92304 (L6) catches `Classes\(Folder|ms-settings)\shell\open\command`
hijacks and 92306 escalates to L12 — but only when the writing process is cmd/powershell.

| Rule | Gap closed |
|---|---|
| 100117 (L12) | **Event Viewer bypass had zero coverage.** 92304's regex is literally `(FOLDER\|MS-SETTINGS)` — the `mscfile\shell\open\command` hijack the eventvwr bypass uses isn't in it. Confirmed: the mscfile write produced *no* alert. This is the mirror image of the T1547.001 Run-key gap (#9) — a stock rule enumerating specific subkeys and missing one. |
| 100118 (L10) | **Disabling UAC via the policy registry** (`EnableLUA` / `ConsentPromptBehaviorAdmin`) was detected only as T1027/T1112 (reg.exe obfuscation via rule 92041), never mapped to T1548.002. Now mapped. |

**Verified** by re-running the eventvwr (mscfile) and disable-UAC (EnableLUA) atomics with `-Cleanup`; both
new rules fired and UAC was confirmed restored (`EnableLUA=1`) afterward. The `sdclt` DelegateExecute
variant was already well-covered by stock 92306 (it writes via PowerShell), so no rule was added for it —
worth stating, since "the stock rule already handles this one" is a legitimate catalog outcome.

**Aside worth noting:** the fodhelper (`ms-settings`) and rundll32/mshta ART tests error at the harness
`.Start()` with *Access is denied* even from an elevated session — most likely Defender real-time
protection killing the auto-elevated child. The registry-hijack half still executes and is what these
rules key on, so detection is verified regardless of whether the elevation itself completes.

## T1021.002 — SMB / Windows Admin Shares (Lateral Movement), batch 5 (2026-08-27)

Ran admin-share access from ws-01 to dc-01 (`net use` / `New-SmbMapping` to C$/ADMIN$/IPC$). Technique 26
— the first **Lateral Movement** technique in the catalog. Two rules (100119/100120).

**The gap:** accessing a remote host's ADMIN$ or drive-letter$ share is a classic lateral-movement /
remote-exec precursor, but stock only fired the generic net.exe rule 92036 (mistagged
T1059.003/T1574.001). 100119 (L5) maps the `net use`/`copy`/`dir \\host\C$` command-line pattern to
T1021.002; 100120 (L4) maps the PowerShell `New-SmbMapping`/`New-PSDrive` variant.

**Deliberate exclusion:** `IPC$` is *not* matched — every normal SMB session opens IPC$, so it's pure
noise. The regex `\\HOST\(ADMIN|<single-drive-letter>)$` matches C$/D$/ADMIN$ but not the 3-letter IPC$;
verified live that `net use \\dc-01\IPC$` and the benign `\\dc-01\SYSVOL` still fall through to the generic
rule while C$/ADMIN$ fire 100119. A good example of a rule where what you *exclude* is as important as
what you match.

**Topology note:** this lab is all-Linux except ws-01, so Windows→Windows PsExec (T1021.002-3) and WinRM
(T1021.006) have no target — SMB admin-share access to the Samba DC is the topology-appropriate
lateral-movement surface. The intended end-to-end path (ws-01 → the writable `\\fs-01\public` bait share →
read the planted credential) is already covered by rule 100090 (T1552.001) when fs-01 is up.

## Active Response — process-kill on the Windows endpoint (2026-08-28)

The Linux side already auto-responds (firewall-drop on the sshd brute-force rules 100010/100011; the
custom disable-ad-account script on the Kerberos rule 100041). This adds **detect-and-respond on ws-01**:
when a high-confidence LOLBin execution fires (100114 regsvr32 / 100115 rundll32 / 100116 mshta), the
manager pushes an active-response to the agent, which **kills the offending process** and logs it —
turning the SIEM from detect-only into detect-and-respond on the Windows endpoint.

**Components**
- `remove-threat.ps1` + `remove-threat.cmd` — deployed to the agent's `active-response\bin\` **as code**
  by the `windows` role (`roles/windows/files/`, converges `changed=0`). The `.ps1` reads the AR alert
  JSON from stdin and `Stop-Process` on the `data.win.eventdata.processId` it names.
- Manager `ossec.conf` (applied the same manual way as the existing ARs):
  ```xml
  <command>
    <name>win-remove-threat</name>
    <executable>remove-threat.cmd</executable>
    <timeout_allowed>yes</timeout_allowed>
  </command>
  <active-response>
    <command>win-remove-threat</command>
    <location>local</location>
    <rules_id>100114,100115,100116</rules_id>
    <timeout>60</timeout>
  </active-response>
  ```

**Verified end-to-end (2026-08-28):** manager remoted logs `Active response sent` to agent 003; the agent
runs the script live (~1.5s); it reads the alert, extracts the PID, kills it, and logs
`KILLED pid=<n> image=<img> (rule <id>)` to `active-responses.log` (which the agent forwards back to the
SIEM — the *response* becomes its own alert). Confirmed on a live long-lived victim process.

**Two findings that made this real detection-engineering work, not a config paste:**
1. **`[Console]::In.ReadToEnd()` hangs the agent's single-threaded execd.** execd passes the AR JSON on
   stdin but never closes the stream, so `ReadToEnd()` blocks *forever*. The agent's execd is
   single-threaded, so after the first AR it stayed blocked — every later AR was *received but never
   executed*, and the queued scripts only completed (logging "could not kill, process gone") at the next
   agent restart when stdin finally closed. Diagnosed by finding a `cmd.exe`→`powershell.exe` pair
   (children of `wazuh-agent`) stuck for 20+ minutes, plus agent debug showing `receive_msg '#!-execd'`
   with **no** matching `ExecdRun`. Fix: read one line with a timeout (`ReadLineAsync().Wait(5000)`).
2. **`active-responses.log` needs `FileShare.ReadWrite` to write.** The agent's logcollector holds that
   file open, so a plain `Add-Content` silently fails while the agent runs (the log lines only appeared
   at restart). Fix: open with `[System.IO.File]::Open(..., 'Append', 'Write', 'ReadWrite')`.

**On the test vectors (honest note):** demonstrating the *kill* took effort because the LOLBins the rules
match are intrinsically short-lived here — `mshta` self-exits within a second or two over the headless
session-0, and a Squiblydoo `regsvr32` gets terminated by Defender — both often faster than the ~1.5–6s
detect→respond latency, so a transient test process is frequently already gone when the AR lands (logged
as "could not kill, process not found"). That's a property of the *test target*, not the response: a real
process that runs more than a few seconds is killed, as verified against a controlled long-lived victim.
