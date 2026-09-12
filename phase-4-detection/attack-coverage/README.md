# ATT&CK coverage map

A single glance at *what this lab can detect*, mapped onto the MITRE ATT&CK matrix — the artifact a detection
team uses to see coverage, spot blind tactics, and prioritise the next rule. Crucially it is **generated from
the ruleset**, not hand-drawn, so it can never quietly drift from what's actually deployed.

## What it shows
`generate-coverage.py` parses the custom **Wazuh** rules (`<mitre>` tags) and **Suricata** rules
(`mitre_technique` metadata), cross-references the **purple-team** battery (`tests.json`), and emits an
ATT&CK **Navigator layer**:

- **50 techniques** currently have a custom detection.
- **23** of those are **validated end-to-end** (the purple-team harness runs the atomic and proves the rule
  fired — not just "a rule exists").
- Two shades encode that difference: **dark green = validated**, **light green = detection exists**.

Coverage now spans **13 of ATT&CK's 14 tactics** — everything except Resource Development — from
Reconnaissance (T1595.002) and Initial Access (T1190) through Execution, Persistence, Privilege Escalation,
Defense Evasion, Credential Access, Discovery, Lateral Movement, Collection, Command & Control,
Exfiltration, and Impact. Full per-technique detail lives in the generated layer itself (load it, per below)
or in [`../detection-catalog.md`](../detection-catalog.md).

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
the `layerURL` link above always points at whatever's on `main`, so there's no separate "publish" step. The
gap between the 50 *detected* and the 23 *validated* is itself the to-do list: extend the purple-team battery
(`phase-5-offense/purple-team/tests.json`) to promote more techniques from light to dark green.
