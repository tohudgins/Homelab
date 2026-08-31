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

## Latest result — 9/9 (100% coverage of the battery)
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

   | Technique | Covered (detected) | **Uncovered variant (evasion) — future rule work** |
   |---|---|---|
   | T1482 Domain Trust Discovery | `nltest /domain_trusts` (100111) | `dsquery`, PowerView `Get-DomainTrust`, `adfind` |
   | T1018 Remote System Discovery | `nltest /dclist` (100110) | `net view`, ping-sweep, `nslookup`, `adfind` |
   | T1069.001 Local Groups | `net localgroup` (100106) | `wmic group`, `Get-LocalGroup`, SharpHound |

   These aren't failures of the pipeline — they're the pipeline doing its job: mapping exactly which *variants*
   of each technique the current ruleset sees, and which an attacker could use to slip past. Broadening the
   rules to cover them (and re-running to confirm) is the next detection-engineering increment.

## Extending
Add a `{technique, test, desc, expect_rules}` object to `tests.json`. Point it at any ATT&CK technique with an
Atomic Red Team test and the Wazuh rule(s) that should catch it; the harness handles the rest. This scales the
detection catalog into a **continuously-verifiable** coverage map.
