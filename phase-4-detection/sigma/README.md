# Sigma detection-as-code → Wazuh

Author portable **[Sigma](https://sigmahq.io/)** rules once, compile them to Wazuh XML, deploy them as
code, and prove they fire — the same detection-engineering loop the rest of Phase 4 uses, but with the
detection logic written in the vendor-neutral standard instead of hand-rolled Wazuh XML.

```
phase-4-detection/sigma/rules/*.yml          portable Sigma (the source of truth)
        │   sigma-to-wazuh.py                a small, lab-tuned compiler
        ▼
roles/siem/files/sigma_local_rules.xml       GENERATED Wazuh rules (build artifact)
        │   siem Ansible role  →  /var/ossec/etc/rules/   (Wazuh loads etc/rules/*.xml)
        ▼
   Wazuh manager (siem-01)                    detections live
        │   purple-team.py (ART on ws-01)  +  sigma-selftest.py
        ▼
   verified firing  →  generate-coverage.py   ATT&CK Navigator layer
```

## Why a purpose-built compiler (and not an off-the-shelf one)

I evaluated the "pro" path first — the same instinct that put MISP and DFIR-IRIS in this lab — and there
simply isn't a clean one for Wazuh:

| Option | Verdict |
|---|---|
| **pySigma** Wazuh backend | No official backend exists; community ones don't emit `<if_sid>`/`<if_group>`, so output matches *every* event. |
| **theflakes/sigma_to_wazuh** (Python) | Abandoned — *"I won't be updating the Python3 version anymore."* |
| **theflakes/StoW** (Go successor) | Maintained, arm64-native, but ships **generic** field maps that don't know this lab's decoders, and leaves `if_sid`/dedup as manual fixups. |
| **SigWaz** (sigwaz.com) | Web-only paste tool — against this lab's self-contained / no-web-app posture. |
| **Chainsaw + Sigma** (SOCFortress) | A different architecture (Sigma run live against EVTX), heavier and Windows-EVTX-bound — not the lighter "compile to native rules" track. |

The root cause is real: **Sigma's expressive detection logic doesn't map 1:1 onto Wazuh's less-expressive
XML rule engine** (no rule-level OR, no easy negation, correlation is a different mechanism). So — exactly
like `purple-team.py` and `generate-coverage.py` — this is a small script tuned to *this* lab's telemetry
rather than a generic dependency: Windows process-creation events that Wazuh decodes from **Sysmon EID 1**
into `win.eventdata.*`, anchored on the `<if_group>sysmon_event1</if_group>` the hand-written rules already
use.

## What the compiler does (`sigma-to-wazuh.py`)

- **logsource → anchor + field map** (a dispatch table, so adding a category is a few lines):
  - `windows/process_creation` (Sysmon EID 1) → `<if_group>sysmon_event1</if_group>` + `win.eventdata.*`
    (`Image`→`win.eventdata.image`, `CommandLine`→`…commandLine`, `OriginalFileName`→`…originalFileName`, …).
  - `windows/ps_script` (PowerShell Script Block Logging EID 4104) → `<if_sid>91802</if_sid>` +
    `ScriptBlockText`→`win.eventdata.scriptBlockText`.
- **modifiers** `|contains |startswith |endswith |re |all`; Sigma `*`/`?` wildcards → PCRE2; matches are
  case-insensitive (`(?i)`), emitted as `type="pcre2"`.
- **OR becomes multiple rules.** A value list is an in-field OR (`(a|b)`); a selection that is a *list of
  maps* (cross-field OR) and a top-level `or` / `1 of x*` are multiplied out (Cartesian) into several Wazuh
  rules — because Wazuh has no rule-level OR. This is the well-known "one Sigma rule → several Wazuh rules."
  (e.g. the certutil rule's `Image|endswith` **OR** `OriginalFileName` compiles to rules 100500 **and** 100501.)
- **negation** `and not filter` → `<field … negate="yes">`, for single-field filters (the common case).
- **MITRE + level** `attack.tXXXX` tags → `<mitre><id>`; Sigma `level` → Wazuh level
  (`critical→13, high→12, medium→8, low→5, informational→3`). Levels sit above the stock discovery band (L3)
  so a Sigma detection wins Wazuh's one-rule-per-event precedence and actually surfaces
  (see the vault's *Wazuh Rule Precedence* note).
- **stable IDs** each Sigma `id:` (GUID) maps to a fixed Wazuh id in `id-map.json` (base **100500**, clear of
  the hand-written 100010–100401 range), so a rule always compiles to the same id across runs.

**Honest limits** (the same ~10% the real tools drop): `| count`/aggregation, `near`, timeframe, parenthesised
conditions, keyword/full-text selections, and multi-field negation are **skipped with a printed reason** — never
emitted as a broken or over-broad rule.

```bash
./sigma-to-wazuh.py            # compile rules/*.yml -> the siem role's files/
./sigma-to-wazuh.py --check    # dry run, report only, non-zero if anything skipped (CI gate)
./sigma-selftest.py            # offline TP/precision unit test of the compiled rules (CI gate)
```

## Rules shipped

| Sigma source | Logsource | ATT&CK | Wazuh rules | Notes |
|---|---|---|---|---|
| `proc_creation_win_certutil_download.yml` | process_creation | T1105 / T1027 | 100500, 100501 | **Verbatim upstream SigmaHQ rule** — proves the compiler ingests real community Sigma, not just hand-authored. |
| `proc_creation_win_process_discovery_tasklist.yml` | process_creation | T1057 | 100502, 100503 | Authored here. |
| `proc_creation_win_system_owner_user_discovery.yml` | process_creation | T1033 | 100504, 100505 | whoami/quser/qwinsta. |
| `proc_creation_win_system_information_discovery.yml` | process_creation | T1082 | 100509, 100510 | systeminfo. |
| `proc_creation_win_service_discovery_sc.yml` | process_creation | T1007 | 100507, 100508 | `sc query`/`queryex` (bin **and** verb). |
| `posh_ps_defender_exclusion_added.yml` | **ps_script** | T1562.001 | 100506 | First PowerShell (EID 4104) rule — `Add-`/`Set-MpPreference` **and** an `-Exclusion*` arg. |
| `proc_creation_win_bitsadmin_download.yml` | process_creation | T1197 | 100511, 100512 | `bitsadmin.exe` **and** a transfer verb. **Found by the rare-process threat hunt** ([`../threat-hunting/`](../threat-hunting/README.md)) — a one-off LOLBin with no prior coverage. |
| `proc_creation_win_wmiprvse_child_exec.yml` | process_creation | T1047 | 100515 | `WmiPrvSE.exe` spawns a shell child — inbound WMI remote exec (parent-process lineage as the detection signal, not the command line). |
| `proc_creation_win_wsmprovhost_child_exec.yml` | process_creation | T1021.006 | 100516 | Any child of `wsmprovhost.exe` **or `winrshost.exe`** — inbound WinRM/PS-Remoting exec (the second alternative added 2026-09-07 after live-fire showed raw `-x <cmd>` execution uses `WinRShost.exe`, not `wsmprovhost.exe` — see Verification below). |
| `proc_creation_win_psexec_service_exec.yml` | process_creation | T1569.002 | 100513, 100514 | `PSEXESVC.exe` runs **or** spawns a child — Sysinternals/impacket PsExec. |
| `proc_creation_win_archive_collection.yml` | process_creation | T1560.001 | 100517, 100518 | rar.exe / 7-Zip (image **and** originalFileName variants) archiving data. |
| `ps_script_win_compress_archive_collection.yml` | **ps_script** | T1560.001 | 100519 | Fileless `Compress-Archive` staging — the same technique with no external binary. |
| `proc_creation_win_inhibit_system_recovery.yml` | process_creation | T1490 | 100520–100524 | `vssadmin` delete/resize, `wmic` shadowcopy delete, `wbadmin` delete, `bcdedit` recovery-disable — 5 rules from one `1 of selection_*` condition. |
| `proc_creation_win_lsass_comsvcs_minidump.yml` | process_creation | T1003.001 | 100525, 100526 | `comsvcs.dll`+`MiniDump` on the command line — catches the LOLBin even when the memory *read* is blocked (see the Defender finding below). |

> Note on upstream ps_script rules: several maintained SigmaHQ PowerShell rules tag `attack.t1685` (and the
> non-standard tactic `attack.defense-impairment`), an ATT&CK id I couldn't verify — so rather than pass an
> unverifiable technique into the coverage map, the ps_script rule here is authored with a checked
> `attack.t1562.001` tag. The certutil rule remains the verbatim-upstream-ingestion showcase.

## Verification

- **Live fire (`purple-team.py`, ART on ws-01): 14/14.** Five Sigma `process_creation` rules fire end-to-end —
  T1057 (tasklist), T1033 (whoami), T1082 (systeminfo), T1007 (`sc query`), and T1197 (`bitsadmin`, added by
  the rare-process threat hunt) — alongside the nine pre-existing detections. Coverage map →
  **39 techniques, 17 validated**.
- **ps_script path proven end-to-end (manual live-fire).** ART's offline bundle on this host has no T1562.001
  atomic, so the PowerShell rule was exercised directly: `Add-MpPreference -ExclusionPath …` → **rule 100506
  fired L12** (T1562.001) on the real EID 4104 script-block telemetry within ~5s; the exclusion was then removed.
  This is the proof the new `ps_script` → `if_sid 91802` → `win.eventdata.scriptBlockText` path works.
- **Rule logic (`sigma-selftest.py`): 18/18.** Emulates Wazuh's field AND/negate evaluation against sample
  events; asserts each rule fires on a true positive and stays quiet on look-alikes (benign `certutil -hashfile`,
  `sc create`, `bitsadmin /list`, and read-only `Get-MpPreference` / realtime-monitoring toggles all correctly
  do **not** fire — precision, no false positive).

- **Live fire (`purple-team.py`, ART on ws-01), 2026-09-07: 18/18 (100%).** Extended the battery to T1490 —
  4 of its 5 rules are ART-exercisable and all 4 fire clean: 100520 (`vssadmin delete shadows`), 100521
  (`vssadmin resize shadowstorage`), 100523 (`wbadmin delete catalog`), 100524 (`bcdedit` recovery-disable).
- **Live fire (`ad-validate.py`, attacks launched from atk-01), 2026-09-07.** T1190 (DMZ web attack), T1560.001
  (archive collection), and **T1021.006 WinRM** all confirmed firing on real telemetry — see the two findings
  immediately below for what it took. **T1047 WMI** did not fire that session (rule 100515) despite the attack
  producing exactly the expected `ParentImage=WmiPrvSE.exe` telemetry — Defender, the firewall, a load error,
  and rule precedence (tested at Wazuh's actual maximum level, 16) were all ruled out, leaving it a real, open
  question rather than a "pending" label covering for one. **Root-caused and fixed 2026-09-12** (see the
  catalog's row #39): a stock rule (92069) was silently winning Wazuh's one-rule-per-event resolution against
  100515 because 100515 sat as an unrelated top-level sibling instead of a child of 92069. Sigma can't express
  an `if_sid` chain to a specific stock rule, so the real fix is a new hand-written rule, 100527 — 100515
  stays as-is (still correct, Sigma-verified logic; it's just structurally pre-empted in this ruleset).

### Finding: nxc's `wmiexec`/`psexec` exec-methods don't work against this lab; the real tools do
`nxc smb --exec-method wmiexec` reliably fails its second SMB connection with "NETBIOS connection... timed
out" against ws-01 — not root-caused, but switching to `impacket-wmiexec` directly (the tool nxc itself
wraps) works cleanly. Separately, `--exec-method psexec` **isn't a valid choice at all** in this nxc version
(1.5.1 only offers `smbexec`/`atexec`/`mmcexec`/`wmiexec`) — `ad-validate.py`'s PsExec scenario had an
invalid argument and had never actually attacked anything until switched to `impacket-psexec` directly.
Lesson: verify a wrapper tool's actual behavior against *this* lab before trusting it in a harness, the same
"verify by exercising" discipline as everywhere else here — a plausible-looking CLI flag is not evidence it
does what its name suggests.

### Finding: WinRM's raw command execution uses a different parent process than PS-Remoting sessions
Rule 100516 was written assuming `wsmprovhost.exe` (the WS-Management/PowerShell-Remoting host) is *the*
tell of inbound WinRM — true for `Enter-PSSession`-style sessions, but `nxc winrm -x <cmd>` (and anything
else doing raw single-command execution over WinRM, i.e. the classic `winrs.exe` path) spawns **`WinRShost.exe`**
instead, which the rule never matched. Confirmed live 2026-09-07 by checking what Sysmon actually recorded as
the parent, not by assuming the Sigma rule's original research was complete. Fixed by widening `ParentImage`
to a value-list OR (`\wsmprovhost.exe`, `\winrshost.exe`) — both processes only exist to service an inbound
remote session, so either is a legitimate lateral-movement tell. Re-verified firing clean afterward.

### Finding: the offline ART bundle's test numbers don't always match the technique's public numbering
Mapped T1490's vssadmin-resize rule (100521) to what a fetched summary of the technique's test list called
"test 9" — wrong. `Invoke-AtomicTest T1490 -ShowDetailsBrief` run directly on ws-01 shows test 9 is actually
"Disable System Restore Through Registry"; vssadmin-resize is test 10. The rule itself was correct throughout
(confirmed by manually running the real command and watching it fire); the bug was purely in which ART test
number `tests.json` pointed at. Fixed by listing tests on the actual host rather than trusting a remembered
or fetched number — the same "verify by exercising" discipline the rest of this catalog already follows,
just applied to the test harness's own inputs instead of the detection logic.

### Finding: T1490's wmic rule is correct but unexercisable on this Windows 11 build
Rule 100522 (`wmic shadowcopy delete`) maps to the right ART test (test 2), but `wmic.exe` doesn't exist on
this ws-01 image — Windows 11 25H2 dropped it (`Test-Path` on both `System32\wmic.exe` and
`System32\wbem\WMIC.exe` returns `False`; `Get-Command wmic` finds nothing). Not removed from the ruleset —
the rule is still correct for any host old enough to have wmic — but pulled from the automated battery
(`tests.json`'s `_comment_not_in_battery`) since it can never pass here, and a permanently-red test is worse
than no test.

### Finding: comsvcs LSASS *is* live-fireable — Sysmon gets the telemetry before Defender acts
Rule 100525/100526 (`comsvcs.dll`+`MiniDump`) was written specifically to survive **LSASS PPL** blocking the
memory *read* — catalog gap #12's original problem. Live-fires: `rundll32.exe comsvcs.dll, MiniDump …` spawns
and Sysmon captures the full command line, and rule 100525 fires on it — 9 real hits across the session,
confirmed both historically and with a fresh test. **Correction:** an earlier pass tonight concluded the
opposite — that Defender kills the process pre-spawn (matching the certutil pattern below) and pulled this
from the active battery on that basis. Wrong: Defender *does* detect the pattern
(`Trojan:Win32/RundllLolBin.AF`, ThreatID 2147793100) and denies the actual dump — `Test-Path` on the output
file returns `Access is denied` — but that happens *after* process creation, not before, so PPL and Defender
both get bypassed for detection purposes even though neither lets the attacker walk away with a real dump.
Re-added to `tests.json`'s active battery. Separately: rule 100526 (the companion `rundll32`+`lsass` rule)
never independently registers as "the" fired alert for this event — it's a same-level sibling of 100525
matching the identical telemetry, and Wazuh's one-rule-per-event model only records one of two co-matching
same-level rules. Not itself evidence 100526's logic is wrong; `sigma-selftest.py`'s 38/38 still proves both.

### Finding: Defender blocks T1105, so a control *is* a detection layer
The certutil rule is **not** in the live purple-team battery on purpose. Microsoft Defender (real-time
protection on) **kills `certutil` download before the process spawns** (ThreatID 2147726914; even a Defender
process-exclusion still hit `Access is denied` at creation — it's behavioural/ASR, not a scan). With no
process, there is **no Sysmon telemetry to detect** — that's not a detection gap, it's defense-in-depth
working: the endpoint control stops the technique outright. The Sigma rule is the *second* layer that catches
it wherever that control is absent, weakened, or bypassed — and its logic is proven by `sigma-selftest.py`
(same class of finding as the lab's earlier mshta/regsvr32/vbscript-are-Defender-killed notes).

`wazuh-logtest` is **not** a substitute here: pasted JSON decodes as the generic `json` decoder, not
`windows_eventchannel`, so the stock Sysmon rule chain (which assigns `sysmon_event1`) never engages — a
logtest limitation for Windows events. Real agent telemetry decodes correctly, which is why the
structurally-identical tasklist/whoami rules fire live.

## Add a detection
1. Drop a Sigma `.yml` in `rules/` (Windows `process_creation` or `ps_script`; add a `LOGSOURCE` entry for a new category).
2. `./sigma-to-wazuh.py` → regenerates `sigma_local_rules.xml` + `id-map.json`.
3. `./sigma-selftest.py` (add a case for it) and, from the ansible dir, `ansible-playbook siem.yml -l siem-01`.
4. Add a scenario/test entry so it's provable, not just deployed — `../../phase-5-offense/purple-team/README.md`'s
   ["Extending" section](../../phase-5-offense/purple-team/README.md#extending) walks the two paths (a local
   ART atomic → `tests.json`; anything else, including inbound/lateral techniques no local atomic can fake →
   `ad-validate.py`'s `SCENARIOS`) and the exact object shape each needs.
5. Run that harness (`purple-team.py` or `make attack MODE=ad-validate`) and confirm a real PASS.
6. Only then, `attack-coverage/generate-coverage.py` to refresh the map — regenerating *before* step 5 actually
   passes reports a technique "validated" that has never fired; see the `README.md`'s own note on this failure
   mode. This also regenerates `attack-coverage/technique-index.md`, so link a new writeup (if you wrote one)
   into that flow for free.
