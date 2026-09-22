# Attack / Detect: Inhibit System Recovery — the ransomware pre-encryption step

**Phase 5 — Offense in context.** Every prior writeup covers a technique that gets an attacker *in* or moves
them *around*. This one covers the step a ransomware operator takes right before the part that actually
hurts: deleting Volume Shadow Copies and disabling Windows recovery, so a victim can't just restore from a
backup once the encryption runs. [T1490 — Inhibit System Recovery](https://attack.mitre.org/techniques/T1490/)
pairs with the fs-01 [ransomware canary](../../phase-4-detection/deception/README.md) (rules 100430/100431,
the lab's other Impact-tactic detection) to cover Impact from both angles: the canary catches the
file-encryption behavior itself, this catches the setup that makes encryption survivable-proof for the
attacker beforehand.

> [!check] Verified live, 2026-09-07 — 4 of 5 rules fire clean via `purple-team.py` (18/18, 100%).
> The fifth (`wmic`) is correct logic that simply can't be exercised on this Windows 11 build — see the
> finding below, not a gap.

---

## 1. Four tools, one Sigma rule

Real-world ransomware doesn't pick one shadow-copy-killing command — different families reach for whichever
of a handful of built-in Windows tools happens to work in that environment. `proc_creation_win_inhibit_system_recovery.yml`
covers all of them as five selections under one `1 of selection_*` condition, compiling to five independent
Wazuh rules (`sigma-to-wazuh.py`'s one-rule-per-selection pattern):

| Rule | Tool + command pattern | What it does |
|---|---|---|
| 100520 | `vssadmin.exe` ... `delete` ... `shadows` | Deletes existing Volume Shadow Copies outright |
| 100521 | `vssadmin.exe` ... `resize` ... `shadowstorage` | Shrinks the shadow-copy storage allocation to zero, achieving the same result without the word "delete" |
| 100522 | `wmic.exe` ... `shadowcopy` ... `delete` | The WMI-CLI equivalent of 100520 |
| 100523 | `wbadmin.exe` ... `delete catalog` / `delete systemstatebackup` / `delete backup` | Deletes Windows Server Backup's own catalog/history, a second, independent backup mechanism from shadow copies |
| 100524 | `bcdedit.exe` ... `recoveryenabled no` / `bootstatuspolicy ignoreallfailures` | Disables the Windows Recovery Environment (WinRE) boot-time repair options entirely |

All five compile to Wazuh level 12 (Sigma `level: high`) and carry the `T1490` MITRE tag. Two are worth
reading closely: 100521 exists specifically because *shrinking* shadow storage to nothing is functionally
identical to deleting it, but doesn't contain the word "delete" at all — a rule keyed only on `vssadmin
delete shadows` would miss it entirely. And 100523/100524 exist because deleting shadow copies alone doesn't
stop a victim who still has WinRE or a separate Windows Server Backup history to fall back on — a ransomware
operator serious about denying recovery goes after all three independent recovery mechanisms, not just the
best-known one.

## 2. Real finding: the offline ART bundle's test numbers don't match public documentation

Mapping each rule to an Atomic Red Team test on ws-01, rule 100521 (`vssadmin resize`) was first pointed at
what a fetched summary of T1490's public test list called "test 9." Wrong: running
`Invoke-AtomicTest T1490 -ShowDetailsBrief` directly on ws-01 showed test 9 is actually **"Disable System
Restore Through Registry"** on this offline bundle — a different technique variant entirely — with the real
vssadmin-resize test sitting at **test 10**. The rule itself had been correct the whole time (confirmed by
running the actual command by hand and watching it fire); the bug was purely in which ART test number
`tests.json` pointed at. Fixed by listing the tests on the real host instead of trusting a remembered or
fetched number — the same "verify by exercising" discipline this lab applies to its detection logic, just
turned on the test harness's own inputs for once.

## 3. Real finding: the `wmic` rule is correct but permanently unexercisable here

Rule 100522 maps to the right ART test (test 2) and its logic is sound — but `wmic.exe` doesn't exist on
this ws-01 image at all. Windows 11 25H2 dropped it: `Test-Path` on both `System32\wmic.exe` and
`System32\wbem\WMIC.exe` returns `False`, and `Get-Command wmic` finds nothing. The rule wasn't removed from
the ruleset — it's still the correct detection for any host old enough to actually have `wmic` — but it was
pulled from `tests.json`'s active battery (`_comment_not_in_battery`) since a test that can never pass on
this build is worse than no test at all: a permanently red result trains you to ignore failures instead of
investigating them. Same class of finding as certutil and PsExec being pulled for a confirmed Defender
block elsewhere in this lab — a rule can be correct and simultaneously not belong in the automated gate.

## 4. Verified

```
purple-team.py, 2026-09-07: 18/18 (100%)
  [PASS] 100520  vssadmin delete shadows           (T1490)
  [PASS] 100521  vssadmin resize shadowstorage      (T1490, ART test 10 — corrected from a wrong "test 9")
  [PASS] 100523  wbadmin delete catalog             (T1490)
  [PASS] 100524  bcdedit recoveryenabled no         (T1490)
  100522 wmic shadowcopy delete — logic correct, unexercisable on this Windows 11 build, excluded from battery
```

ATT&CK coverage: 4 of 5 rules validated end-to-end by the real harness; the fifth is detection-only by
confirmed environmental necessity, not an open gap — see `technique-index.md` for how that distinction is
tracked lab-wide.

## Reproduce

```bash
ssh ws-01 'powershell -c "Invoke-AtomicTest T1490 -TestNumbers 1"'   # vssadmin delete shadows -> rule 100520
ssh ws-01 'powershell -c "Invoke-AtomicTest T1490 -TestNumbers 10"'  # vssadmin resize shadowstorage -> rule 100521
ssh siem-01 "sudo grep -a '\"id\":\"100520\"' /var/ossec/logs/alerts/alerts.json | tail -1"
```

## Related

`phase-4-detection/sigma/rules/proc_creation_win_inhibit_system_recovery.yml` ·
`phase-4-detection/sigma/README.md` (the "Rules shipped" table + the ART-test-numbering and wmic findings in
full) · `phase-4-detection/deception/README.md` (the ransomware canary — the companion Impact-tactic
detection) · `phase-5-offense/purple-team/tests.json` · [`../TOOLS.md`](../TOOLS.md)
