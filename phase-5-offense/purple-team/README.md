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

**`purple-team.py` never calls `-Cleanup`** — it only proves detection, so any atomic with a persistent
side effect (a registry Run key, UAC disabled via policy, shadow copies deleted) stays changed on `ws-01`
after the run ends. Harmless for the discovery/Sigma techniques (read-only), but real for the newer
persistence/UAC additions (2026-09-13): running the full battery leaves `T1547.001`'s `RunOnce` key and
`T1548.002`'s UAC weakening in place until manually reverted (`Invoke-AtomicTest <T> -TestNumbers <n>
-Cleanup`, same technique/test number as the `tests.json` entry) — found the hard way, re-running the whole
battery to confirm the new entries left `ws-01`'s UAC disabled and a live `RunOnce` persistence key behind.
Clean up after any run that includes a state-changing test, the same discipline `ad-validate.py`'s
`teardown` field exists to automate for its own scenarios.

**Current: 22/23 (96%), last run 2026-09-13** — the battery has grown well past the original Discovery set
(now includes the Sigma-compiled rules, all 4 exercisable T1490 sub-rules, and the 4 LOLBin/persistence/UAC
techniques added closing the 23→48 coverage gap — see below); see `tests.json` for the live list. The one
FAIL (T1003.001, LSASS comsvcs MiniDump, rule 100525) is a real environment-drift finding, not a rule
regression: it fired reliably as recently as 2026-09-07, but a fresh check found Defender now blocks the
process at launch (`Access is denied` even via a direct `rundll32.exe comsvcs.dll` invocation, bypassing
the ART harness entirely) rather than only denying the memory read afterward — Defender's own real-time
heuristics evidently tightened in the interim, outside this repo's control; see `tests.json`'s comment for
the full history. The "9/9" result immediately below is kept as-is — it's the *first* run, and the findings
under "What building this exposed" are still exactly how they happened.

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
   secondary index. (A green harness that measures nothing is worse than no harness at all — the same
   silent-fallback trap as everything else in this catalog that checks "did anything log," not "did the
   specific thing I expected log.")
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
[FAIL] WMI Lateral Movement   rules 100515       WmiPrvSE spawns a shell on ws-01 (T1047) — fixed 2026-09-12, see below
[PASS] WinRM Lateral Movement rules 100516       wsmprovhost/winrshost spawns a shell on ws-01 (T1021.006)
[PASS] DMZ Web Attack         rules 100440       SQLi against Juice Shop (T1190)
[PASS] Archive Collection     rules 100519       Compress-Archive stages a fileless archive on ws-01 (T1560.001)
```
Getting here needed real infrastructure fixes, not just credentials — ws-01's Windows Firewall had SMB/WMI
inbound rule groups entirely disabled, its network was misclassified `Public`, and even fixed, the SMB-In
rule was scoped `LocalSubnet` (invisible to routed REDTEAM traffic). See `detection-catalog.md`'s note below
row #41 for the full fix, and rows #39-41 for the per-technique findings (WMI's rule bug is fixed as of
2026-09-12, see below; PsExec is confirmed Defender-blocked, same class as T1105/T1003.001-comsvcs, and
deliberately not in this battery for that reason — a permanently-red test is worse than none, same reasoning
as `tests.json`'s wmic/comsvcs exclusions).

These attacks **complete on Samba** — SMB/NTLM password spraying returns a real credential, and the
TGS-REQ / DsGetNCChanges reach the DC (which logs them) even where impacket's later parse fails against Samba;
see `../attack-detect-writeups/` for per-attack detail and the documented interop boundaries (Kerberoast crack,
DCSync dump, and AS-REP roasting all hit Samba-vs-Windows walls — the *telemetry*, hence the *detection*,
fires regardless). A scenario gated on a host that's down (cred-theft needs fs-01) **SKIPs** cleanly instead of
failing. Scenarios that declare a `technique` are read by `generate-coverage.py`, so a passing AD attack
promotes that technique to **validated (dark green)** on the ATT&CK coverage map (now 12 validated total).

**WMI fixed and re-verified, 2026-09-12** — root cause: stock rule 92069 was silently winning Wazuh's
one-rule-per-event resolution against 100515 (both anchored on the same top-level `if_group=sysmon_event1`
as unrelated siblings, so 92069 — matched first, at level 0 — was the only one ever considered; see
`detection-catalog.md` #39). Fixed with a hand-written escalation child of 92069, rule 100527. Re-ran
`ad-validate.py` against the live lab (dc-01/fs-01/dmz-01 intentionally suspended/not booted this session
to stay under the host's RAM ceiling — their FAILs/SKIP below are that, not new regressions):
```
[FAIL] Password Spray         rules 100401       dc-01 suspended this session — not a regression
[FAIL] Kerberoasting          rules 100031       dc-01 suspended this session — not a regression
[FAIL] DCSync                 rules 100080       dc-01 suspended this session — not a regression
[SKIP] Credential Theft       needs fs-01 (unreachable)
[PASS] WMI Lateral Movement   rules 100515,100527   hits=3   WmiPrvSE spawns a shell on ws-01 (T1047)
[PASS] WinRM Lateral Movement rules 100516       hits=1   wsmprovhost/winrshost spawns a shell on ws-01
[FAIL] DMZ Web Attack         rules 100440       dmz-01 not booted this session — not a regression
[PASS] Archive Collection     rules 100519       hits=1   Compress-Archive stages a fileless archive on ws-01
```
WMI now passes on both the original Sigma rule (100515, still doesn't fire — kept as the documented,
Sigma-verified logic) and the real fix (100527, `hits=3`) via the `["100515", "100527"]` rule list in
`ad-validate.py`'s scenario definition — the harness counts a hit on *either*.

Run: `./ad-validate.py` (needs SSH to atk-01 + siem-01; weak lab creds are baked in — already public in
`phase-2-identity/known-weaknesses.md`).

## Extending
Two paths, depending on where the telemetry is actually produced:
- **A local ART atomic exists on ws-01, and actually runs cleanly** → add a `{technique, test, desc,
  expect_rules}` object to `tests.json`. Point it at any ATT&CK technique with an offline-viable Atomic Red
  Team test (no internet-fetched payload — see `phase-5-offense/atomic-red-team/README.md`) and the Wazuh
  rule(s) that should catch it. "Runs cleanly" is doing real work in that sentence: ART's own harness
  (`Invoke-AtomicTest`) is itself sometimes the thing that breaks — see below.
- **Anything else** → add a scenario to `ad-validate.py`'s `SCENARIOS`. What started as "attacks launched from
  atk-01" (2026-09-06) generalized further (2026-09-12/13) to *any* technique `purple-team.py`'s
  ART-atomic-only model can't express — three real reasons that keeps happening:
  1. **The detection only fires when the host is the *target* of an inbound attack** (lateral movement, a web
     attack against a service) — no local atomic can fake being on the receiving end of a connection.
  2. **The technique is a Linux/AD-infra action with no ART coverage at all** (Samba group-membership changes,
     SYSVOL/cron/passwd FIM, disabling the Wazuh agent, a real DNS tunnel) — these just run a real command on
     `dc-01`/`fs-01`/`atk-01` directly, no `test` number involved.
  3. **An ART atomic for a Windows technique exists, but its own harness breaks on this host** — found live
     2026-09-12 rebuilding the LOLBin battery: `Invoke-AtomicTest T1218.011 -TestNumbers 2` didn't just error,
     it **crashed the SSH/WinRM session outright**. The commit-message-worthy lesson: a `-ShowDetailsBrief`
     listing tells you a test *exists*, never that its harness will behave — the only way to know is running
     it and watching what happens to the connection, same "verify by exercising" discipline as everything
     else here. When this happens, invoke the LOLBin directly with a minimal representative command line
     instead (`mshta.exe vbscript:close`, `rundll32.exe vbscript:close` — both exit cleanly, confirmed) wrapped
     in `Start-Process -PassThru` + `Wait-Process -Timeout` as a hard backstop against a future hang, same
     "verified by the observable, not the payload" idiom `detection-catalog.md` already uses for the
     Defender-blocked cases.

  Every `ad-validate.py` scenario needs `{name, host, cmd, rules, technique, desc}`, plus whichever of these
  fit: `requires`/`requires_env` for a prerequisite host or credential; `settle` to override the default
  25s propagation wait (the fs-01 `susp-exec-path` collector polls every 30s, so that scenario needs longer);
  and `setup`/`teardown` (each a `{host, cmd}` dict, or a list of them) for anything that needs a throwaway
  account bootstrapped-then-deleted or a background daemon started-then-stopped — bootstrap/teardown steps
  aren't counted toward the before/after delta, only the measured `cmd` is.

Either way this scales the detection catalog into a **continuously-verifiable** coverage map — with one sharp
edge to know about: `generate-coverage.py` promotes a technique to "validated" the moment it's *declared* in
either file (a `"technique"` key present), not the moment it's actually confirmed passing. That's normally
fine because the existing convention is to add the entry only after a real PASS — but it means **adding an
entry and regenerating the coverage map are two separate steps**, never done in the same breath: run the
harness first, confirm PASS, *then* regenerate. Declaring first and regenerating before ever running it would
report a technique as validated that has never actually fired — the exact "hand-typed number describing the
data, not the data" trap this repo's `attack-coverage/README.md` had to fix once already.

**A real instance of exactly that, caught in this audit (2026-09-12):** T1047's `ad-validate.py` scenario
already declared `"technique": "T1047"` back on 2026-09-06/07, before the WMI detection actually worked, so
the coverage map had been showing T1047 dark green ("validated") the whole time it was genuinely failing.
Harmless in hindsight only because the rule got fixed later and the map's claim became true retroactively —
it would have stayed silently wrong indefinitely otherwise. No process change from this (the convention above
is still the right one), just a concrete example that the failure mode is real, not theoretical.

## Closing the 23→48 gap (2026-09-12/13)

Every technique with a custom detection now has a runnable, repeatable, automated simulation, not just the
ones that happened to be easy — the explicit goal going in was **zero gaps left on the table**, not "add a
few more." 13 new `ad-validate.py` scenarios and 4 new `tests.json` entries later:

```
== 18/23 AD detections validated (all 6 VMs up) ==
```
Chasing every one of the 5 non-dmz-01 FAILs in that raw run down to a root cause (rather than accepting
"mostly works" for a battery meant to prove *zero* gaps) is itself the story of this pass:

- **2 were never regressions** — `DMZ Web Attack` and `Automated Scanner Detection` both need `dmz-01`,
  intentionally down mid-battery to keep the host under its RAM ceiling (running all 7 lab VMs at once
  earlier in this session OOM-killed 5 of them — a real reminder the "never run everything" rule in
  `scripts/lab.sh` exists for a reason, not just a suggestion). Both scenarios independently confirmed PASS
  earlier in this same session with `dmz-01` up.
- **2 were a real timing margin, not a rule defect** — `Kerberoasting` and `Kerberos Brute Force` both
  reported `hits=0`, but the expected alert had genuinely fired, just a handful of seconds *after* the 25s
  settle check — confirmed by finding both in `alerts.json` moments later on a manual re-run. `impacket`
  against Samba and Wazuh's `frequency`/`timeframe` correlation windows both have some jitter; `settle`
  bumped 25→35 for both scenarios.
- **1 was a real, previously-unknown Wazuh FIM gap** — `Local Account Creation` (rule 100051) — see below.
- **1 was a real infrastructure bug in the new automation itself** — `DNS Tunneling` — see below.

Coverage map: **48 of 51 techniques now validated end-to-end** (was 23) — the 3 that aren't are T1027/T1105
(certutil) and T1569.002 (PsExec), deliberately excluded because Defender blocks all three before any
telemetry is produced (see `attack-coverage/README.md`).

**Two real infrastructure bugs the automation itself surfaced** — the same "the harness accumulates real
bugs worth fixing" pattern as the capstone script's own history:

1. **`systemd-run --unit ... iodine(d)` silently died a fraction of a second after starting.** iodine(d)
   self-daemonizes by default (forks, prints "Detaching from terminal...", and the *original* process
   exits) — a transient systemd service's default `KillMode=control-group` reads "tracked main PID exited"
   as "service stopped" and kills the whole cgroup, taking the just-detached daemon child down with it.
   The DNS Tunneling scenario passed by hand (built with `--scope`, which doesn't have this problem the same
   way) but FAILed every time under the real `--unit`-based automation — confirmed via
   `journalctl -u pt-iodined`: "Detaching from terminal..." then "Deactivated successfully." in the same
   tick. Fixed by adding `-f` (foreground, don't daemonize) to both `iodined` and `iodine`, which keeps
   systemd's tracked PID as the actual running server for as long as the unit needs to exist.
2. **Rule 100051 (`/etc/passwd`/`/etc/shadow` FIM) fires exactly once per `wazuh-agent` restart, then goes
   silently blind** — a real detection gap, not a test bug, root-caused rather than shrugged off as
   "flaky": `useradd`/`userdel` replace those files via write-tempfile-then-`rename()` (standard shadow-utils
   practice), which orphans the `inotify`-based `realtime` FIM watch (it's tracking the now-unlinked old
   inode). `100020` (SYSVOL) and `100050` (cron) don't have this problem because their scenarios only
   `touch`/`tee`/`rm` the same inode in place. Full evidence and the honest non-fix in
   `detection-catalog.md`'s T1136.001 section — this is exactly the kind of finding building the automation
   was *for*, and it would never have surfaced from a single hand-run verification.

**New scenarios by host/mechanism, for anyone extending this further:**

| Where | Techniques closed | Mechanism |
|---|---|---|
| `dc-01`, direct command (no `atk-01` needed) | T1484.001, T1053.003, T1136.001, T1562.001 | root-shell FIM/systemd tests — same pattern as the existing SYSVOL rule, just extended to cron/passwd/agent-tooling |
| `dc-01` + `setup`/`teardown` | T1098.007, T1110.001 | throwaway account bootstrapped, real attack (network LDAP / 4 failed `kinit`s), account torn down — the "bigger design decision" flagged as not-yet-done back in the T1098.007 section of `detection-catalog.md` |
| `ws-01`, direct invocation (ART harness unusable) | T1218.005, T1218.011 | `Start-Process -PassThru` + `Wait-Process -Timeout`, see the LOLBin note above |
| `ws-01`, standard ART harness | T1547.001, T1218.010, T1548.002 (×2 rules) | added straight to `tests.json` — these ones just worked |
| `ws-01`, direct command | T1021.002 | `net use` against a UNC admin share; fires on the attempt, not success |
| `atk-01` | T1595.002, T1078 | scanner User-Agent against the DMZ app; authenticate as the `svc-sqladmin` honeytoken |
| `fs-01` | T1486 | tamper-then-restore a ransomware-canary decoy file |
| `fs-01` + `atk-01` | T1204.002/T1059.004/T1071.001 (one rule, one test — see `generate-coverage.py`'s cross-referencing), T1071, T1048.003/T1071.004 | a copy of `dash` run from `/tmp`; 15 rapid connections to REDTEAM:443 (no real C2 binary needed — the Suricata rule keys on connection *pattern*, not payload); a real `iodine` tunnel |

**A genuine one-line fix along the way:** the pre-existing "Credential Theft" scenario had never declared a
`"technique"` key at all — a real, silent gap in the coverage cross-referencing that had nothing to do with
this batch, caught only because building `generate-coverage.py`'s rule-tag cross-referencing (below) meant
reading every scenario closely for the first time in a while.

## First full re-run since the T1098.007/whodata fixes landed (2026-09-15)

The battery hadn't been run end-to-end since the T1098.007 logging fix (rule 100015) and the passwd/shadow
`whodata` fix both landed in separate later sessions — this was the first chance to actually prove, not
assume, that both still work together and that nothing regressed. It didn't just confirm; it found three
more real bugs, the same "trust the harness, not the memory of the last run" discipline as the 23→48 pass
above:

```
== 18/21 AD detections validated (2 skipped) ==   # first raw run
```

- **`T1098.007` (`AD Group Membership Manipulation`, rule 100015) genuinely PASSED live** — resolving a
  stale claim in `detection-catalog.md`'s own history: the commit that built rule 100015 said the scenario
  "wasn't wired into `ad-validate.py`'s automated battery," but the scenario had actually been written
  *before* that rule existed (referencing rule ID 100015 as a forward declaration) and never re-checked
  once the rule went live. It was already there; it just needed running.
- **A real, reproducible regression, not a flake: `whodata` was silently back to plain `realtime`.** A
  routine `ansible-playbook site.yml` converge restarted `auditd`, and the `audisp-af_unix` plugin that
  feeds Wazuh's whodata engine couldn't rebind its own socket (a stale-socket-from-shutdown race — full
  root cause and the systemd-drop-in fix are in `detection-catalog.md`'s T1136.001 section). This silently
  undid the whole point of the earlier passwd/shadow FIM fix; **any future `auditd` restart would have hit
  it again** had it not been fixed at the systemd level, not just live-patched.
- **A second real, reproducible finding: zero-gap create-then-delete on the same path can miss `/etc/cron.d`
  FIM (rule 100050).** The original scenario chained create+delete with no gap and failed 3 of 4 manual
  reproductions; a ~1-2s gap fired reliably every time. Agent-side inotify coalescing/dropping one half of
  a same-instant create+delete pair, not a settle-timing issue — full writeup in the same catalog section.
- **A real correlation-engine finding, and the opposite of the usual brute-force blind spot: firing *fast*
  evades `Kerberos Brute Force` (rule 100041), firing at human/throttled pace doesn't.** All 4 wrong-password
  `kinit` attempts landing at the manager within a few ms of each other reliably failed to correlate, even
  though every individual attempt matched the base rule; spacing them ~1s apart fired every time. Full
  repro table (three paces tested) in `detection-catalog.md`'s T1110.001 section.
- **Two scenarios (`DMZ Web Attack`, `Automated Scanner Detection`) used to report a bare FAIL whenever
  `dmz-01` was down**, indistinguishable from a real regression. Both now declare `"requires": "dmz-01"`
  and SKIP cleanly, same discipline as the existing `fs-01`-gated scenarios.

All three real gaps got a real fix (an Ansible-codified systemd drop-in for the auditd race; `sleep 1`
added to the two burst-sensitive scenarios) rather than a relaxed assertion. Clean re-run after every fix:

```
== 19/19 AD detections validated (4 skipped) ==
[exited with code 0]
```

The 4 skips are the pre-existing `ADMIN_USER`/`ADMIN_PW`-gated WMI/WinRM scenarios (no credential set this
session) and the two now-cleanly-skipping `dmz-01` scenarios (VM intentionally left out of this session's
6-VM `attack` profile to stay under the RAM ceiling — see the OOM note above).

## `generate-coverage.py`'s cross-referencing (2026-09-12)

Before this pass, a technique was "validated" only if some test's own `"technique"` string matched it
exactly — but several rules are honestly co-tagged with more than one MITRE ID (100117/100118 cover both
T1548.002 and T1112; 100015 covers both T1098.007 and T1098; 100200 covers T1204.002, T1059.004, *and*
T1071.001 all at once). `generate-coverage.py` now builds a rule→technique reverse map and credits *every*
tag on a rule a passing test's `expect_rules`/`rules` proves fired, not just the one word the test happened
to declare. One new test can validate a whole co-tagged cluster — which is exactly how the single "Suspicious
Execution From World-Writable Path" scenario above closes three techniques, honestly, off one real
`systemd-run` invocation.
