# ATT&CK coverage map

A single glance at *what this lab can detect*, mapped onto the MITRE ATT&CK matrix — the artifact a detection
team uses to see coverage, spot blind tactics, and prioritise the next rule. Crucially it is **generated from
the ruleset**, not hand-drawn, so it can never quietly drift from what's actually deployed.

## What it shows
`generate-coverage.py` parses the custom **Wazuh** rules (`<mitre>` tags) and **Suricata** rules
(`mitre_technique` metadata), cross-references the **purple-team** battery (`tests.json`), and emits an
ATT&CK **Navigator layer**:

- **56 techniques** currently have a custom detection.
- **52** of those are **validated end-to-end** (the purple-team harness runs the atomic and proves the rule
  fired — not just "a rule exists"). The remaining 4 are deliberately excluded from the automated battery,
  not gaps, each for its own documented reason in `detection-catalog.md`: T1027/T1105 (certutil download)
  and T1569.002 (PsExec) because Microsoft Defender blocks all three outright before the technique produces
  any telemetry (confirmed live — a permanently-red automated test would be worse than none, so they're
  proven true-negatives instead); T1055 (process injection, closed 2026-09-25) because the gap it closes is
  specifically a raw scripting-engine `CreateRemoteThread` call that none of Atomic Red Team's stock T1055
  tests reproduce (they ship as compiled Go binaries, not a scripting-engine source image) — proven instead
  by a reproducible manual live-fire, confirmed twice.
- Two shades encode that difference: **dark green = validated**, **light green = detection exists**.

Coverage now spans **13 of ATT&CK's 14 tactics** — everything except Resource Development — from
Reconnaissance (T1595.002) and Initial Access (T1190) through Execution, Persistence, Privilege Escalation,
Defense Evasion, Credential Access, Discovery, Lateral Movement, Collection, Command & Control,
Exfiltration, and Impact.

**Want to learn a specific technique, not just see that it's covered?** [`technique-index.md`](technique-index.md)
is the other generated artifact here — one row per technique linking to wherever its real explanation
actually lives (a dedicated [attack/detect writeup](../../phase-5-offense/attack-detect-writeups/), a feature
README, or [`detection-catalog.md`](../detection-catalog.md) as the fallback). It exists because those
explanations are scattered across ~20 files by design (each lives next to the code it documents) — this is
the one page that ties a technique ID back to where its story is.

## View it

**One click** (works once the repo is pushed and public — `raw.githubusercontent.com` needs to actually serve
the file):
[**Open this layer in ATT&CK Navigator**](https://mitre-attack.github.io/attack-navigator/enterprise/#layerURL=https%3A%2F%2Fraw.githubusercontent.com%2Ftohudgins%2FHomelab%2Fmain%2Fphase-4-detection%2Fattack-coverage%2Fattack-navigator-layer.json) —
loads this exact layer straight from `main` into the hosted Navigator, no download/upload step. It's a plain
link (`#layerURL=<url-encoded raw-file URL>`), so it always reflects whatever's currently on `main` — no
separate "publish" step after a `generate-coverage.py` re-run.

It's also embedded live on the [docs site](https://tohudgins.github.io/Homelab/phase-4-detection/attack-coverage/)
(an `<iframe>` of the same link) — GitHub strips `<iframe>` tags from rendered markdown, so this page shows
link-only here on GitHub itself.

<iframe src="https://mitre-attack.github.io/attack-navigator/enterprise/#layerURL=https%3A%2F%2Fraw.githubusercontent.com%2Ftohudgins%2FHomelab%2Fmain%2Fphase-4-detection%2Fattack-coverage%2Fattack-navigator-layer.json&tabs=false&selecting_techniques=false"
        width="100%" height="700" style="border:1px solid #ccc;" loading="lazy"></iframe>

**Manual method** (works for any fork/branch, or before the repo is public): load `attack-navigator-layer.json`
at **https://mitre-attack.github.io/attack-navigator/** → *Open Existing Layer* → *Upload from local*. The
covered techniques light up green across the matrix, each annotated with the rule id(s) and whether it's
validated.

## Regenerate (keep it honest)
```bash
python3 generate-coverage.py     # re-reads the rules + purple-team tests, rewrites the layer
```
Run it whenever rules change; because it's derived, the map is always exactly the deployed coverage — and
the `layerURL` link above always points at whatever's on `main`, so there's no separate "publish" step.
52 of 56 are validated (see above for the 4 deliberately-excluded exceptions) — extending coverage further
now means adding a *new* rule and a *new* test together, not chasing the automation gap that used to sit
between "detected" and "validated" (23 → 48, closed 2026-09-12/13: `phase-5-offense/purple-team/README.md`
has the full batch-by-batch story, including two real infra bugs the automation itself surfaced).
