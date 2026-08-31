# ATT&CK coverage map

A single glance at *what this lab can detect*, mapped onto the MITRE ATT&CK matrix — the artifact a detection
team uses to see coverage, spot blind tactics, and prioritise the next rule. Crucially it is **generated from
the ruleset**, not hand-drawn, so it can never quietly drift from what's actually deployed
([[Single Source of Truth]]).

## What it shows
`generate-coverage.py` parses the custom **Wazuh** rules (`<mitre>` tags) and **Suricata** rules
(`mitre_technique` metadata), cross-references the **purple-team** battery (`tests.json`), and emits an
ATT&CK **Navigator layer**:

- **31 techniques** currently have a custom detection.
- **9** of those are **validated end-to-end** (the purple-team harness runs the atomic and proves the rule
  fired — not just "a rule exists").
- Two shades encode that difference: **dark green = validated**, **light green = detection exists**.

Coverage spans Discovery (T1016/T1018/T1049/T1069/T1087/T1201/T1482/T1518.001), Defense Evasion / Execution
(T1218.005/.010/.011, T1548.002, T1562.001, T1112, T1204.002, T1059.004), Credential Access (T1003.006,
T1552.001, T1558.003), Persistence (T1053.003, T1136.001, T1547.001, T1098), Lateral Movement (T1021.002),
Command & Control (T1071/.001/.004), Brute Force (T1110), and GPO abuse (T1484.001).

## View it
Load `attack-navigator-layer.json` at **https://mitre-attack.github.io/attack-navigator/** →
*Open Existing Layer* → *Upload from local*. The covered techniques light up green across the matrix, each
annotated with the rule id(s) and whether it's validated.

## Regenerate (keep it honest)
```bash
python3 generate-coverage.py     # re-reads the rules + purple-team tests, rewrites the layer
```
Run it whenever rules change; because it's derived, the map is always exactly the deployed coverage. The
gap between the 31 *detected* and the 9 *validated* is itself the to-do list: extend the purple-team battery
(`phase-5-offense/purple-team/tests.json`) to promote more techniques from light to dark green.
