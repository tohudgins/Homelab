# Phase 4 — Detection Catalog

For each technique: run/simulate the attack → observe raw telemetry in Wazuh → write a custom rule in
`local_rules.xml` → verify it fires on a true positive → attempt evasion → document false-positive risk.

Rules live on siem-01 at `/var/ossec/etc/rules/local_rules.xml` (mirrored in this folder). Rule IDs in the
`100xxx` range are reserved for custom/local rules by Wazuh convention (the shipped ruleset uses IDs below
100000), so every rule below lives there to guarantee no collision with an upstream update.

## Status

**Verified tonight (2026-08-14/15), all against real telemetry, not just syntax checks:**

| # | ATT&CK Technique | Rule ID(s) | Source Host | Status |
|---|---|---|---|---|
| 1 | [T1110 – Brute Force](https://attack.mitre.org/techniques/T1110/) | 100010, 100011 | dc-01 (sshd) | ✅ verified TP, active response confirmed |
| 2 | [T1484.001 – Group Policy Modification](https://attack.mitre.org/techniques/T1484/001/) | 100020 | dc-01 (SYSVOL FIM) | ✅ verified TP (add/modify/delete) |
| 3 | [T1558.003 – Kerberoasting](https://attack.mitre.org/techniques/T1558/003/) | 100030, 100031 | dc-01 (Samba KDC audit) | ✅ verified TP + evasion confirmed |

Plus a real SCA before/after remediation pass on dc-01 (48% → 55%, see below) — a different Wazuh
capability (compliance benchmarking, not attack-simulation rule-writing), so it isn't in the technique
table above.

**Deliberately deferred, not forgotten:**
- **Windows/Sysmon coverage (ws-01)** — ws-01 is a suspended 8GB VM; this MacBook's 24GB is already fully
  committed across rtr-01+dc-01+siem-01 with real swap pressure observed tonight. Resuming it needs either
  more free RAM (close other VMs) or accepting real thrash risk — not a decision to make silently mid-session.
  Next session's natural starting point.
- **NSM / Suricata rule-writing** — wired Suricata's `eve.json` into Wazuh tonight (real ingestion,
  verified flowing) as prep, but building actual detections on top of it is explicitly **Phase 6** scope
  in the build plan (ET Open tuning, Suricata+Zeek correlation). Started drifting into that scope
  mid-session and pulled back deliberately rather than half-finish Phase 6 under the Phase 4 banner.
- **Target is 8-12 techniques total** per the build plan; 2 custom-rule techniques + SCA is a real,
  verified subset, not the finish line. Continuing this catalog is the first thing to pick back up.

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
