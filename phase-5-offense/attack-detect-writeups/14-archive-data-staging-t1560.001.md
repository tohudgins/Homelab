# Attack / Detect: Archive Collected Data — the only rule filling an entire empty ATT&CK tactic

**Phase 4 — Detection engineering.** [T1560.001](https://attack.mitre.org/techniques/T1560/001/) — Archive
Collected Data via Utility — is the step between "found something worth taking" and "got it out the door":
compressing (and often encrypting) staged files before exfiltration, whether through an external archiving
tool or a built-in, no-extra-binary cmdlet. Before this rule existed, this lab's coverage map had zero
techniques mapped to ATT&CK's **Collection** tactic at all — every other technique covered Discovery,
Credential Access, Lateral Movement, Defense Evasion, or Persistence, but nothing represented the step of an
attacker actually gathering data together before moving it.

> [!check] Verified live, 2026-09-07: fileless `Compress-Archive` staging fired rule 100519 on the real
> command line.

---

## 1. Two rules, two very different levels of confidence

Sigma-compiled from `proc_creation_win_archive_collection.yml` (native binaries) and a second,
purpose-authored `ps_script_win_compress_archive_collection.yml` (the fileless PowerShell path) — the same
technique, covered by fundamentally different telemetry because there are two fundamentally different ways
to actually do it:

| Rule | Method | Status |
|---|---|---|
| **100517, 100518** | `rar.exe` / 7-Zip (image **and** `originalFileName` variants) | Correct by inspection only |
| **100519** | Fileless `Compress-Archive` (PowerShell cmdlet, no external binary at all) | **Verified TP live** |

**100517/100518 remain unexercised, and honestly labeled as such:** `rar.exe` and `7z.exe` simply aren't
present on this Windows image — an environment gap, not a rule defect, the same class of "the tool the rule
expects doesn't exist on this exact build" finding as the `wmic` shadowcopy rule and the missing `rar`
offline-ART-atomic elsewhere in this lab's own exclusion notes. The rule logic is unchanged and correct for
any host that actually has either binary installed; it just has never fired here.

**100519 is the one that matters most, and it's the one that's proven.** `Compress-Archive` ships with every
modern PowerShell install, needs no separate download or install step, and leaves no suspicious external
binary on disk for an EDR to flag by name — the fileless variant is arguably the *more* realistic path a
careful attacker takes specifically to avoid tripping a rule that only watches for `rar.exe`/`7z.exe`.

## 2. Attack simulation

```powershell
New-Item -ItemType Directory -Path C:\stage
# (stage files worth collecting into C:\stage)
Compress-Archive -Path C:\stage\* -DestinationPath C:\stage.zip
```

No external tool, no download, no file that wasn't already a standard part of the OS. The rule matches on
the `Compress-Archive` cmdlet invocation itself in the PowerShell Script Block Logging (EID 4104) telemetry.

## 3. Verified

```
[PASS] Archive Collection  rules 100519  hits=1  Compress-Archive stages a fileless archive on ws-01
```

Wired into `ad-validate.py`'s automated battery and passing on every full-lab re-run — this technique gets
exercised and re-proven every time the battery runs, not just the one time it was first built.

## 4. Why this stages right upstream of the lab's own DNS-exfil detection

This technique doesn't exist in isolation in this lab's story — the natural next step after archiving data
is getting it out, and this lab separately has a real DNS-tunneling exfiltration path (`iodine`,
`phase-6-nsm/dns-tunneling.md`) with its own detection. A `Compress-Archive` alert followed shortly after by
DNS-tunneling telemetry from the same host is exactly the kind of multi-stage correlation a real SOC analyst
would piece together by hand from two separate, individually-modest alerts — this lab covers both halves of
that chain, even without an automated correlation rule tying them together.

## 5. Evasion / limits — named honestly

**The native-binary half of this technique (rar/7-Zip) is genuinely unproven here**, purely because of what
this specific Windows image ships with, not because the detection logic is wrong. Anyone extending this lab
with a build that actually has `rar.exe` or `7z.exe` installed should re-run that half of the battery before
trusting it as more than "correct by inspection."

**Fileless staging via anything other than `Compress-Archive`** — a hand-rolled `.NET`
`System.IO.Compression.ZipFile` call, for instance — produces none of the PowerShell cmdlet telemetry this
rule keys on. `Compress-Archive` is the common, idiomatic path; a determined attacker using raw .NET APIs
directly would slip past this rule entirely, the same evasion-by-going-lower-level tradeoff every
cmdlet-level detection in this lab accepts.

## Reproduce

```bash
ssh ws-01 'powershell -c "New-Item -ItemType Directory -Path C:\stage -Force; Compress-Archive -Path C:\stage -DestinationPath C:\stage.zip -Force"'
ssh siem-01 "sudo grep -a '\"id\":\"100519\"' /var/ossec/logs/alerts/alerts.json | tail -1"
```

## Related

`phase-4-detection/detection-catalog.md` #42 (the full original write-up this backfills) ·
`phase-4-detection/sigma/README.md`'s "Rules shipped" table (both rules' Sigma source files) ·
`phase-6-nsm/dns-tunneling.md` (the exfiltration step this technique naturally precedes) ·
`phase-5-offense/purple-team/tests.json`'s exclusion notes (the same rar/7-Zip environment-gap pattern, seen
again for other LOLBins)
