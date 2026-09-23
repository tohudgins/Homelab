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
#   - ad-validate.py's SCENARIOS = techniques validated via a live AD attack
#   - osquery/README.md's own "Verified live" differential-promotion table =
#     techniques hand-verified once against a real host, outside both harnesses
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
WRITEUPS_DIR = os.path.join(REPO, "phase-5-offense/attack-detect-writeups")
OSQUERY_README = os.path.join(REPO, "phase-4-detection/osquery/README.md")

OUT = os.path.join(HERE, "attack-navigator-layer.json")
INDEX_OUT = os.path.join(HERE, "technique-index.md")


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


def validated_techniques(cov):
    # A technique is "validated" when an automated harness runs the attack and proves
    # the detection fired: purple-team.py (Atomic tests on ws-01, tests.json) OR
    # ad-validate.py (real domain attacks from atk-01 — scenarios with a "rules" list).
    #
    # A harness entry declares ONE "technique" string alongside the rule ID(s) it expects
    # to fire — but several rules are honestly tagged with more than one MITRE ID (e.g.
    # 100117/100118 cover both T1548.002 and T1112; 100015 covers both T1098.007 and
    # T1098). Proving one of those rules fired proves EVERY technique it's tagged with,
    # not just the one word the test happened to type in "technique" — so cross-reference
    # each entry's rule ID(s) against the rule->technique map (built from `cov`, i.e.
    # wazuh_techniques() + suricata_techniques()) rather than only collecting the
    # literal declared strings. One new test can then validate a whole co-tagged
    # cluster at once, and a future rule split doesn't silently strand a sibling
    # technique as unvalidated.
    rule_to_techs = {}
    for tech, rids in cov.items():
        for rid in rids:
            rule_to_techs.setdefault(rid, set()).add(tech)

    v = set()
    if os.path.exists(PT_TESTS):
        for t in json.load(open(PT_TESTS)).get("tests", []):
            v.add(norm(t["technique"]))
            for rid in t.get("expect_rules", []):
                v |= rule_to_techs.get(rid, set())
    if os.path.exists(AD_VALIDATE):
        # Import as a module (SCENARIOS is a plain top-level list; execution is
        # guarded by `if __name__ == "__main__":`) rather than regex-scraping the
        # source text — a scenario dict is structured data, and a regex spanning
        # "technique" and "rules" risks matching across two adjacent scenarios.
        import importlib.util
        spec = importlib.util.spec_from_file_location("ad_validate", AD_VALIDATE)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        for s in getattr(mod, "SCENARIOS", []):
            tech = s.get("technique")
            if not tech:
                continue
            v.add(norm(tech))
            for rid in s.get("rules", []):
                v |= rule_to_techs.get(rid, set())
    v |= osquery_readme_verified_techniques()
    return v


def osquery_readme_verified_techniques():
    # osquery/README.md §4 has its own "differentials promoted to real alerts"
    # table (| Rule | Fires on | Level | MITRE | Verified live (DATE) |) — each
    # row was hand-fired and confirmed against a real host (a real
    # `python3 -m http.server`, `crontab` addition, or `useradd`), but that
    # verification isn't wired through tests.json or ad-validate.py's
    # SCENARIOS, so it was invisible to validated_techniques() below and those
    # techniques silently under-reported as "detection only" even though
    # they're genuinely proven. Only rows with a non-empty evidence cell in
    # the last column count — a row with no "Verified live" text (or "—")
    # is deliberately NOT counted, same honesty bar as everywhere else here.
    v = set()
    if not os.path.exists(OSQUERY_README):
        return v
    for line in open(OSQUERY_README):
        line = line.strip()
        if not line.startswith("| **"):
            continue
        cells = [c.strip() for c in line.strip("|").split("|")]
        if len(cells) < 5:
            continue
        mitre_cell, evidence_cell = cells[3], cells[4]
        if not evidence_cell or evidence_cell == "—":
            continue
        for t in re.findall(r"T[0-9]{4}(?:\.[0-9]{3})?", mitre_cell):
            v.add(norm(t))
    return v


def technique_counts_in_file(path):
    """technique -> how many times its ID appears in this file. A count, not
    just a set: a file substantively about a technique typically names its ID
    more than once (a rule table row, a verification section, a related-links
    footer), while a passing cross-reference ("the same bug the T1047 fix
    hit") names it exactly once — the count is the signal that tells those
    two cases apart.
    """
    if not os.path.exists(path):
        return {}
    counts = {}
    for t in re.findall(r"T[0-9]{4}(?:\.[0-9]{3})?", open(path).read()):
        t = norm(t)
        counts[t] = counts.get(t, 0) + 1
    return counts


# Directory names never worth descending into while looking for narrative docs:
# version control, the mkdocs build output (gitignored, and `docs/` below is a
# symlink mirror of the same phase-*/ files so walking it would just duplicate
# or shadow the canonical path with a `docs/...` one), and this script's own
# generated output.
SKIP_DIRS = {".git", "site", "docs", "attack-coverage", "__pycache__", "node_modules",
             "collections", ".venv", "venv", "isos"}


def feature_readmes():
    """Every narrative .md in the repo that isn't a curated attack/detect
    writeup — the feature READMEs (threat-hunting/, deception/, velociraptor/,
    yara-fim/, sliver-c2/, ...), standalone writeups (dns-tunneling.md,
    soc-ops-iris.md, ...), and detection-catalog.md itself. Excludes only
    WRITEUPS_DIR, which is a genuinely higher-priority, deliberately curated
    tier (see `build_references`) — detection-catalog.md is included here
    rather than kept as its own always-wins-or-always-loses tier, because it's
    real content with genuine per-technique table rows, just narrower in
    scope than its name implies (see its own top-of-file note); it should
    compete on the same density basis as every other feature doc, not be
    structurally forced to lose to a single passing mention elsewhere.
    """
    writeups_abs = os.path.abspath(WRITEUPS_DIR)
    for dirpath, dirnames, filenames in os.walk(REPO):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        if os.path.abspath(dirpath) == writeups_abs:
            continue
        for fname in filenames:
            if not fname.endswith(".md"):
                continue
            path = os.path.join(dirpath, fname)
            yield path


def _tier_refs(paths):
    """technique -> repo-relative file, resolved within one tier (a list of
    candidate paths). When more than one file in the tier mentions the same
    technique, the file where that technique is the most CONCENTRATED wins —
    its mention count divided by how many distinct techniques the file
    discusses at all. Raw count alone isn't enough: a big multi-technique
    status file (purple-team.py's own README, covering ~45 techniques across
    its test-battery write-ups) can rack up as many raw mentions of any one
    technique as a short file that's actually *about* just that one (e.g.
    sliver-c2/README.md, ~6 techniques total) purely by being long — density
    is what tells "this file is specifically about T1071" apart from "this
    file happens to mention T1071 among dozens of others in passing."
    Raw count, then path, are the tiebreaks for a genuine density tie.

    Known limitation: density still under-ranks a genuinely comprehensive
    reference (detection-catalog.md documents ~50 techniques, each with a
    real per-technique row) against a short file that mentions a technique
    only once in passing — a handful of techniques resolve to a thinner
    source than the catalog's own row for that reason. Not worth a more
    elaborate heuristic to chase the last few percent; every technique still
    resolves to a file that genuinely mentions it, and nothing points at an
    unrelated technique's writeup, which was the actual bug this exists to
    prevent.
    """
    file_data = []
    for path in paths:
        counts = technique_counts_in_file(path)
        total_distinct = len(counts) or 1
        file_data.append((path, counts, total_distinct))

    refs = {}
    best_key = {}
    for path, counts, total_distinct in file_data:
        rel = os.path.relpath(path, REPO)
        for t, n in counts.items():
            key = (n / total_distinct, n, rel)
            if t not in best_key or key > best_key[t]:
                best_key[t] = key
                refs[t] = rel
    return refs


def build_references():
    """technique -> best repo-relative file to learn it from, in two tiers:
    a dedicated attack/detect writeup (curated, deliberately highest priority)
    > every other narrative doc in the repo (feature READMEs and
    detection-catalog.md, competing with each other on equal footing — see
    `_tier_refs`). Scanned by which techniques each file actually MENTIONS —
    data-driven the same way the rule coverage above is, so a new writeup is
    picked up automatically and there's no hand-maintained technique->doc
    table to drift out of sync as writeups get added.
    """
    writeup_paths = []
    if os.path.isdir(WRITEUPS_DIR):
        writeup_paths = [os.path.join(WRITEUPS_DIR, f) for f in sorted(os.listdir(WRITEUPS_DIR)) if f.endswith(".md")]

    refs = {}
    refs.update(_tier_refs(list(feature_readmes())))
    refs.update(_tier_refs(writeup_paths))  # the curated tier's assignment fully overrides the previous
    return refs


def write_index(rows):
    lines = [
        "<!-- Generated by generate-coverage.py — do not hand-edit, it will be overwritten. -->",
        "# Technique index — where each covered technique is explained",
        "",
        "One row per technique with a custom detection in this lab. **Learn** links to the best",
        "available narrative for it: a dedicated attack/detect writeup first, then any other",
        "feature README that mentions it (threat-hunting/, deception/, velociraptor/, sigma/, ...),",
        "then the original Phase 4 detection catalog as a fallback. An em-dash means the technique",
        "has a rule (and maybe a validated test) but no narrative anywhere yet — a real gap, not an",
        "oversight; see `phase-5-offense/attack-detect-writeups/` to add one.",
        "",
        "| Technique | Status | Rule ID(s) | Learn |",
        "|---|---|---|---|",
    ]
    for tech, rids, is_val, ref in rows:
        status = "validated" if is_val else "detection only"
        if ref:
            href = os.path.relpath(os.path.join(REPO, ref), HERE)
            ref_cell = f"[{ref}]({href})"
        else:
            ref_cell = "—"
        lines.append(f"| {tech} | {status} | {', '.join(rids)} | {ref_cell} |")
    with open(INDEX_OUT, "w") as f:
        f.write("\n".join(lines) + "\n")
    print(f"wrote {INDEX_OUT}")


def main():
    cov = wazuh_techniques()
    for t, rids in suricata_techniques().items():
        cov.setdefault(t, set()).update(rids)
    validated = validated_techniques(cov)
    references = build_references()

    techniques = []
    index_rows = []
    for tech in sorted(cov):
        rids = sorted(cov[tech])
        is_val = tech in validated
        ref = references.get(tech)
        learn_note = f" | learn: {ref}" if ref else ""
        techniques.append({
            "techniqueID": tech,
            "score": 100 if is_val else 50,
            "color": "#2e7d32" if is_val else "#66bb6a",
            "comment": ("VALIDATED (purple-team) — " if is_val else "detection — ") + ", ".join(rids) + learn_note,
            "enabled": True,
        })
        index_rows.append((tech, rids, is_val, ref))

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

    write_index(index_rows)
    no_writeup = sum(1 for _, _, _, ref in index_rows if not ref)
    print(f"  {len(index_rows) - no_writeup} of {len(index_rows)} techniques have a learn reference; {no_writeup} have none yet")


if __name__ == "__main__":
    main()
