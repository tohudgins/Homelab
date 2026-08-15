# Phase 4 — Detection Catalog

For each technique: run/simulate the attack → observe raw telemetry in Wazuh → write a custom rule in
`local_rules.xml` → verify it fires on a true positive → attempt evasion → document false-positive risk.

Rules live on siem-01 at `/var/ossec/etc/rules/local_rules.xml` (mirrored in this folder). Rule IDs in the
`100xxx` range are reserved for custom/local rules by Wazuh convention (the shipped ruleset uses IDs below
100000), so every rule below lives there to guarantee no collision with an upstream update.

| # | ATT&CK Technique | Rule ID(s) | Source Host | Status |
|---|---|---|---|---|
| 1 | [T1110 – Brute Force](https://attack.mitre.org/techniques/T1110/) | 100010, 100011 | dc-01 (sshd) | ✅ verified TP, active response confirmed |

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

*(Additional techniques added as Phase 4 progresses — target is 8–12 total per the build plan, covering
both dc-01/rtr-01 Linux telemetry and ws-01 Windows/Sysmon telemetry once ws-01 is back online.)*
