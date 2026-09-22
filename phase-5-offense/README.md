# Phase 5 — Offense in context

Attack scripts and writeups that exist to be re-run, not one-off exploit notes — each
proves a detection by actually triggering it. Three runners cover different shapes of
attack; pick by what you're trying to do, not by habit.

## Which script do I run?

| I want to... | Use | Runs from | Notes |
|---|---|---|---|
| Re-fire a single known-good technique locally on ws-01 (no new creds, fast) | [`purple-team/purple-team.py`](purple-team/purple-team.py) | the Mac (SSHes to ws-01 + siem-01 itself) | Reads `tests.json` — an Atomic Red Team test per technique, PASS/FAIL against the expected rule. |
| Attack something *from* another host — lateral movement into ws-01, a DMZ web attack, an AD attack against dc-01 | [`purple-team/ad-validate.py`](purple-team/ad-validate.py) | the Mac (SSHes to atk-01/dc-01/fs-01 itself) | Reads `SCENARIOS` in the same file. Needs `ADMIN_USER`/`ADMIN_PW` for the WMI/WinRM/PsExec scenarios — use `make attack MODE=ad-validate` instead of setting them by hand. |
| Run the **full chained intrusion** — initial access through impact, one scorecard at the end | [`apt-scenario/run-scenario.sh`](apt-scenario/run-scenario.sh) | **on atk-01 itself** (phases 1-4); phases 5-7 run directly on ws-01/fs-01, see its README | `make attack MODE=capstone` — syncs the script to atk-01 and forwards creds, instead of `scp` + a hand-typed `ssh atk-01 "ADMIN_USER=... ADMIN_PW=... ./run-scenario.sh"`. |

`atomic-red-team/` is the offline ART bundle staged on ws-01 (see `docs/design-decisions.md`
for why it's offline), not something you run directly — `purple-team.py` drives it.
`bloodhound-ce/` and `bloodhound-collections/` are the AD graph tooling, run separately
(see that directory's own README).

## Learn a technique / the tools used to run or detect it

- [`attack-detect-writeups/`](attack-detect-writeups/) — the polished narrative pieces: real
  commands, real bugs hit building the detection, the evasion that was tried. Start here for
  the handful of techniques that have one.
- [`TOOLS.md`](TOOLS.md) — one paragraph each on the offensive tools these scripts and writeups
  use (Impacket, NetExec, BloodHound, Sliver, iodine, Velociraptor VQL) — what each one is and
  does, for anyone reading a writeup that just gives the bare command.
- [`../phase-4-detection/attack-coverage/technique-index.md`](../phase-4-detection/attack-coverage/technique-index.md) —
  every covered technique, linked to wherever its real explanation actually lives (a writeup
  here, a feature README, or the Phase 4 detection catalog).

## Adding a new technique end to end

Authoring a detection and an offense scenario for it touches both this directory and
`phase-4-detection/sigma/` in a specific order — see
[`phase-4-detection/sigma/README.md`'s "Add a detection" section](../phase-4-detection/sigma/README.md#add-a-detection),
which walks the whole sequence (write the Sigma rule → compile → deploy → add the
scenario/test here → confirm PASS → regenerate coverage) rather than treating the two
sides as separate projects.

## Related

[`../phase-4-detection/`](../phase-4-detection/) (the detections these attacks trigger) ·
[`../phase-4-detection/attack-coverage/`](../phase-4-detection/attack-coverage/) (coverage map + technique index) ·
`docs/RUNBOOK.md` §2 (running a simulation, day to day)
