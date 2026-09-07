# Purple-team validation — "run the attack, prove the detection fired"

Writing a detection rule and *assuming* it works is how SOCs end up with silent blind spots. This is the
discipline that prevents that: an automated harness that **executes real ATT&CK techniques and verifies the
intended detection actually fired** — a repeatable coverage report, not a one-time manual check. It's the
operational proof behind the Phase 4 detection catalog.

Attacker/target: `ws-01` (Windows, Atomic Red Team + Sysmon + the custom rules) · SIEM: `siem-01` (Wazuh).

```
for each technique in tests.json:
    baseline = count matching alerts in the Wazuh log            # before
    run the Atomic Red Team test on ws-01
    wait for propagation
    delta = count matching alerts - baseline                     # after
    PASS if delta > 0 (the technique executed AND was detected), else FAIL
```

## Run it
```bash
./purple-team.py              # uses tests.json; needs SSH to ws-01 + siem-01 (the ~/.ssh/config aliases)
```
Exit code is non-zero if any technique is undetected (usable as a CI gate on the detection ruleset).

**Current: 18/18 (100%), last run 2026-09-07** — the battery has grown well past the original Discovery set
(now includes the Sigma-compiled rules and all 4 exercisable T1490 sub-rules); see `tests.json` for the live
list. The "9/9" result immediately below is kept as-is — it's the *first* run, and the findings under "What
building this exposed" are still exactly how they happened.

## First result (Discovery battery, 2026-08-27) — 9/9
```
[PASS] T1016      rules 100100,100101   Network Configuration Discovery
[PASS] T1049      rules 100102,100103   Network Connections Discovery
[PASS] T1518.001  rules 100104,100105   Security Software Discovery
[PASS] T1069.001  rules 100106,100107   Permission Groups: Local
[PASS] T1087.002  rules 100108,100112   Account Discovery: Domain
[PASS] T1069.002  rules 100109          Permission Groups: Domain
[PASS] T1018      rules 100110          Remote System Discovery (nltest /dclist)
[PASS] T1482      rules 100111          Domain Trust Discovery (nltest /domain_trusts)
[PASS] T1201      rules 100113          Password Policy Discovery (net accounts)
== 9/9 techniques detected (100% coverage) ==
```
Every custom Discovery-tactic rule (100100–100113) is confirmed firing against the ATT&CK test it was written
for. Domain-discovery tests (T1087.002/T1069.002/T1018/T1482) detect **even with dc-01 powered off** — the
rules key on the *command line* (`net user /domain`, `nltest /domain_trusts`), so they catch the attacker's
attempt regardless of whether the query reaches a DC.

## What building this exposed (the value is in the FAILs)
Getting to 9/9 took three iterations, and each failure was a real finding a detection engineer acts on:

1. **Verification bug (the harness itself).** v1 counted detections via an indexer `_count` query and reported
   0/9 — while the alerts plainly existed. Rewrote it to diff the manager's **alert log** (the source of
   truth) before/after each atomic. Lesson: validate the validator, and prefer the authoritative log over a
   secondary index. ([[Silent Fallbacks]] again — a green harness that measures nothing.)
2. **A hung atomic stalled the run.** T1018's `net view` atomic hung 774s waiting on the powered-off DC. Added
   a hard per-atomic timeout so one hang can't wedge the battery.
3. **Test-selection + a genuine coverage gap.** Two mappings used atomic *test 1*, which for T1069.001 and
   T1201 is a **Linux** test ("0 applicable to windows") — wrong target. And T1482's test 1 uses **`dsquery`**,
   but rule 100111 only matches **`nltest`** — a real gap. The rules are deliberately command-specific, so
   these atomic variants of the same techniques would **evade** them:

   | Technique | Covered (detected) | Uncovered variant (evasion) — future rule work |
   |---|---|---|
   | T1482 Domain Trust Discovery | `nltest`, **`dsquery`, `adfind`** (100111 — broadened, see below) | PowerView `Get-DomainTrust` (PowerShell) |
   | T1018 Remote System Discovery | `nltest /dclist` (100110) | `net view`, ping-sweep, `nslookup`, `adfind` |
   | T1069.001 Local Groups | `net localgroup` (100106) | `wmic group`, `Get-LocalGroup`, SharpHound |

   These aren't failures of the pipeline — they're the pipeline doing its job: mapping exactly which *variants*
   of each technique the current ruleset sees, and which an attacker could use to slip past.

   **Closing one (the loop end-to-end):** the run flagged that rule 100111 caught only `nltest` domain-trust
   discovery. Broadened its regex from `(domain_trusts|trusted_domains)` to add `trustedDomain` — now covering
   the `dsquery`/`adfind` variants (which enumerate trusts via an LDAP `objectClass=trustedDomain` filter),
   verified to match those commands while still not matching benign `net user`. (The dsquery *atomic* can't be
   exercised on ws-01 — RSAT/`dsquery` isn't installed on a workstation — so this closure is verified at the
   detection level; its rule structure is identical to the harness-confirmed `nltest` path.) Broadening the
   `net view` / `wmic group` / PowerView variants the same way is the ongoing increment.

## Attack validation from atk-01 — `ad-validate.py`
`purple-team.py` validates *endpoint* detections by running Atomic Red Team locally on ws-01. `ad-validate.py`
applies the identical "attack → prove the detection fired" discipline to attacks that must be launched **from
another host** — originally just domain attacks against the Samba AD DC, extended (2026-09-06) to every
technique whose detection keys on being the *target* of an inbound connection, which no local ART atomic can
fake: WMI/WinRM/PsExec lateral movement into ws-01, and a web attack against dmz-01. Same before/after
alert-log diff, same PASS/FAIL/exit-code contract, same repeatable practice range and CI gate.

**Live result, 2026-09-07 (`ADMIN_USER=localadmin ADMIN_PW=... ./ad-validate.py`): 7/8 (PsExec deliberately
excluded — see below).**
```
[PASS] Password Spray         rules 100401       one password x many accounts (T1110.003)
[PASS] Kerberoasting          rules 100031       request 3+ service tickets in 60s (T1558.003)
[PASS] DCSync                 rules 100080       DsGetNCChanges from a non-DC (T1003.006)
[PASS] Credential Theft       rules 100090       read planted cred on the weak share (T1552.001)
[FAIL] WMI Lateral Movement   rules 100515       WmiPrvSE spawns a shell on ws-01 (T1047)
[PASS] WinRM Lateral Movement rules 100516       wsmprovhost/winrshost spawns a shell on ws-01 (T1021.006)
[PASS] DMZ Web Attack         rules 100440       SQLi against Juice Shop (T1190)
[PASS] Archive Collection     rules 100519       Compress-Archive stages a fileless archive on ws-01 (T1560.001)
```
Getting here needed real infrastructure fixes, not just credentials — ws-01's Windows Firewall had SMB/WMI
inbound rule groups entirely disabled, its network was misclassified `Public`, and even fixed, the SMB-In
rule was scoped `LocalSubnet` (invisible to routed REDTEAM traffic). See `detection-catalog.md`'s note below
row #41 for the full fix, and rows #39-41 for the per-technique findings (WMI is a genuinely open question;
PsExec is confirmed Defender-blocked, same class as T1105/T1003.001-comsvcs, and deliberately not in this
battery for that reason — a permanently-red test is worse than none, same reasoning as `tests.json`'s
wmic/comsvcs exclusions).

These attacks **complete on Samba** — SMB/NTLM password spraying returns a real credential, and the
TGS-REQ / DsGetNCChanges reach the DC (which logs them) even where impacket's later parse fails against Samba;
see `../attack-detect-writeups/` for per-attack detail and the documented interop boundaries (Kerberoast crack,
DCSync dump, and AS-REP roasting all hit Samba-vs-Windows walls — the *telemetry*, hence the *detection*,
fires regardless). A scenario gated on a host that's down (cred-theft needs fs-01) **SKIPs** cleanly instead of
failing. Scenarios that declare a `technique` are read by `generate-coverage.py`, so a passing AD attack
promotes that technique to **validated (dark green)** on the ATT&CK coverage map (now 12 validated total).

Run: `./ad-validate.py` (needs SSH to atk-01 + siem-01; weak lab creds are baked in — already public in
`phase-2-identity/known-weaknesses.md`).

## Extending
Two paths, depending on where the telemetry is actually produced:
- **A local ART atomic exists on ws-01** → add a `{technique, test, desc, expect_rules}` object to `tests.json`.
  Point it at any ATT&CK technique with an offline-viable Atomic Red Team test (no internet-fetched payload —
  see `phase-5-offense/atomic-red-team/README.md`) and the Wazuh rule(s) that should catch it.
- **The detection only fires when the host is the *target* of an inbound attack** (lateral movement, a web
  attack against a service) → add a `{name, host, cmd, rules, technique, desc}` scenario to `ad-validate.py`'s
  `SCENARIOS`, with `requires`/`requires_env` for any host or credential the attack needs. `purple-team.py`
  can only run *local* ART atomics on ws-01, so it structurally can't express these.

Either way this scales the detection catalog into a **continuously-verifiable** coverage map — with one sharp
edge to know about: `generate-coverage.py` promotes a technique to "validated" the moment it's *declared* in
either file (a `"technique"` key present), not the moment it's actually confirmed passing. That's normally
fine because the existing convention is to add the entry only after a real PASS — but it means **adding an
entry and regenerating the coverage map are two separate steps**, never done in the same breath: run the
harness first, confirm PASS, *then* regenerate. Declaring first and regenerating before ever running it would
report a technique as validated that has never actually fired — the exact "hand-typed number describing the
data, not the data" trap this repo's `attack-coverage/README.md` had to fix once already.
