#!/usr/bin/env python3
# ===========================================================================
# generate-coverage.py — build an ATT&CK Navigator layer from the detection
# rules, so the coverage map is DATA-DRIVEN, never hand-maintained (it can't
# drift from the ruleset, the way a hand-typed count of "N techniques covered"
# always eventually does).
#
# Sources (repo-relative):
#   - the Wazuh custom rules (each <mitre><id> tag = a covered technique)
#   - the Suricata custom rules (metadata mitre_technique)
#   - the purple-team battery (tests.json) = techniques VALIDATED end-to-end
#
# Scoring:  50 = a detection rule exists for the technique
#          100 = additionally proven by the purple-team harness (run->detect->PASS)
#
# Output: attack-navigator-layer.json — load at https://mitre-attack.github.io/attack-navigator/
# ===========================================================================
import json
import os
import re

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "..", ".."))
WAZUH_RULE_FILES = [
    os.path.join(REPO, "phase-7-automation/ansible/roles/siem/files/local_rules.xml"),
    # Sigma-compiled rules (phase-4-detection/sigma/) — a generated artifact, but
    # every <mitre><id> in it counts toward coverage the same as a hand-written rule.
    os.path.join(REPO, "phase-7-automation/ansible/roles/siem/files/sigma_local_rules.xml"),
]
SURICATA_RULES = os.path.join(REPO, "phase-7-automation/ansible/roles/router/files/suricata-local.rules")
PT_TESTS = os.path.join(REPO, "phase-5-offense/purple-team/tests.json")
AD_VALIDATE = os.path.join(REPO, "phase-5-offense/purple-team/ad-validate.py")

OUT = os.path.join(HERE, "attack-navigator-layer.json")


def norm(t):
    # T1071_001 (Suricata metadata style) -> T1071.001
    return t.replace("_", ".").upper().strip()


def wazuh_techniques():
    cov = {}  # technique -> set(rule ids)
    for path in WAZUH_RULE_FILES:
        if not os.path.exists(path):
            continue
        xml = open(path).read()
        for m in re.finditer(r'<rule id="(\d+)"[^>]*>(.*?)</rule>', xml, re.S):
            rid, body = m.group(1), m.group(2)
            for t in re.findall(r'<id>(T[0-9.]+)</id>', body):
                cov.setdefault(norm(t), set()).add(rid)
    return cov


def suricata_techniques():
    cov = {}
    if not os.path.exists(SURICATA_RULES):
        return cov
    for line in open(SURICATA_RULES):
        sid = re.search(r'sid:(\d+)', line)
        for t in re.findall(r'mitre_technique[ _]?(?:id)?[,: ]+(T[0-9_.]+)', line):
            cov.setdefault(norm(t), set()).add("suricata:" + (sid.group(1) if sid else "?"))
    return cov


def validated_techniques():
    # A technique is "validated" when an automated harness runs the attack and proves
    # the detection fired: purple-team.py (Atomic tests on ws-01, tests.json) OR
    # ad-validate.py (real domain attacks from atk-01 — scenarios that declare a technique).
    v = set()
    if os.path.exists(PT_TESTS):
        v |= {norm(t["technique"]) for t in json.load(open(PT_TESTS)).get("tests", [])}
    if os.path.exists(AD_VALIDATE):
        v |= {norm(m) for m in re.findall(r'"technique":\s*"(T[0-9.]+)"', open(AD_VALIDATE).read())}
    return v


def main():
    cov = wazuh_techniques()
    for t, rids in suricata_techniques().items():
        cov.setdefault(t, set()).update(rids)
    validated = validated_techniques()

    techniques = []
    for tech in sorted(cov):
        rids = sorted(cov[tech])
        is_val = tech in validated
        techniques.append({
            "techniqueID": tech,
            "score": 100 if is_val else 50,
            "color": "#2e7d32" if is_val else "#66bb6a",
            "comment": ("VALIDATED (purple-team) — " if is_val else "detection — ") + ", ".join(rids),
            "enabled": True,
        })

    layer = {
        "name": "Homelab — detection coverage",
        "versions": {"attack": "14", "navigator": "4.9.1", "layer": "4.5"},
        "domain": "enterprise-attack",
        "description": (f"Detection coverage generated from the homelab ruleset: "
                        f"{len(cov)} techniques with a custom detection, "
                        f"{len(validated & set(cov))} validated end-to-end by the "
                        f"purple-team harness. Dark green = validated, light green = "
                        f"detection exists. Regenerate with generate-coverage.py."),
        "techniques": techniques,
        "gradient": {"colors": ["#66bb6a", "#2e7d32"], "minValue": 50, "maxValue": 100},
        "legendItems": [
            {"label": "Validated (run->detect->PASS)", "color": "#2e7d32"},
            {"label": "Detection rule exists", "color": "#66bb6a"},
        ],
        "showTacticRowBackground": True,
        "tacticRowBackground": "#205b2e",
        "selectTechniquesAcrossTactics": True,
    }
    json.dump(layer, open(OUT, "w"), indent=2)
    print(f"wrote {OUT}")
    print(f"  {len(cov)} techniques covered; {len(validated & set(cov))} validated end-to-end")
    print("  covered:", ", ".join(sorted(cov)))


if __name__ == "__main__":
    main()
