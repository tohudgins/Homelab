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
4. `phase-5-offense/purple-team/purple-team.py` to prove it fires; `attack-coverage/generate-coverage.py` to refresh the map.
