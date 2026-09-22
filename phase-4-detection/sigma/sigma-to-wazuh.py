#!/usr/bin/env python3
# ===========================================================================
# sigma-to-wazuh.py — a focused Sigma -> Wazuh rule compiler for this homelab.
#
# WHY THIS EXISTS (evaluate-pro-first finding, 2026-09-03):
#   There is no clean, official Sigma -> Wazuh path. pySigma has no official
#   Wazuh backend (the community ones don't set <if_sid>, so output matches
#   every event); theflakes/sigma_to_wazuh (Python) is abandoned ("I won't be
#   updating the Python3 version anymore") and its Go successor StoW ships
#   generic field maps that don't know this lab's decoders. Sigma's expressive
#   logic simply doesn't map 1:1 onto Wazuh's less-expressive XML rule engine.
#   So — same pattern as purple-team.py / generate-coverage.py — this is a
#   small, purpose-built compiler tuned to THIS lab's telemetry: Windows
#   process-creation events decoded by Wazuh from Sysmon EID 1 into
#   win.eventdata.* fields, anchored on the <if_group>sysmon_event1</if_group>
#   the hand-written rules already use.
#
# WHAT IT DOES:
#   Sigma YAML (portable source of truth)  ->  Wazuh <rule> XML (build artifact)
#   - logsource product=windows, category=process_creation
#   - Sigma field modifiers: |contains |startswith |endswith |re |all
#   - value lists  = OR ; the |all modifier = AND (multiple <field> lines)
#   - condition:  selection | A and B | A or B | A and not filter |
#                 1 of sel* | all of sel* | (1|all) of them
#     (an OR condition compiles to multiple Wazuh rules — expected; Wazuh has
#      no rule-level OR. Anything using near/timeframe/count/aggregation is
#      SKIPPED with a printed reason — the same honest ~12% the real tools drop.)
#   - MITRE technique tags -> <mitre>; Sigma level -> Wazuh level
#   - stable Sigma-GUID -> Wazuh-ID mapping persisted in id-map.json, so a rule
#     always compiles to the same 100xxx id across runs (id-base 100500, chosen
#     to clear the hand-written 100010-100401 range).
#
# USAGE (from this directory, on the operator host):
#   ./sigma-to-wazuh.py            # compile ./rules/*.yml -> the siem role's files/
#   ./sigma-to-wazuh.py --check    # dry run: report only, write nothing (CI gate)
# ===========================================================================
import argparse
import glob
import itertools
import json
import os
import re
import sys
from xml.sax.saxutils import escape as xml_escape  # nosemgrep: python.lang.security.use-defused-xml.use-defused-xml — output-escaping only, never parses XML, no XXE surface

import yaml

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "..", ".."))
DEFAULT_OUT = os.path.join(
    REPO, "phase-7-automation/ansible/roles/siem/files/sigma_local_rules.xml")
DEFAULT_IDMAP = os.path.join(HERE, "id-map.json")
DEFAULT_RULES = os.path.join(HERE, "rules")

# --- Sigma logsource -> Wazuh (anchor + field map) ---------------------------
# Each supported Sigma logsource is pinned to (a) the Wazuh rule this lab's stock
# ruleset already uses as the parent for that telemetry, and (b) the decoded
# field names Wazuh exposes. Keeping these explicit — rather than a generic
# tool's guess — is the whole point of a lab-tuned compiler.
#
# process_creation  = Sysmon EID 1  -> group sysmon_event1, win.eventdata.*
# ps_script         = PowerShell Script Block Logging EID 4104 -> stock rule
#                     91802 ("PowerShell executed a ScriptBlock"), scriptBlockText
PROC_FIELDS = {
    "Image": "win.eventdata.image",
    "OriginalFileName": "win.eventdata.originalFileName",
    "CommandLine": "win.eventdata.commandLine",
    "ParentImage": "win.eventdata.parentImage",
    "ParentCommandLine": "win.eventdata.parentCommandLine",
    "CurrentDirectory": "win.eventdata.currentDirectory",
    "User": "win.eventdata.user",
    "ParentUser": "win.eventdata.parentUser",
    "IntegrityLevel": "win.eventdata.integrityLevel",
    "Company": "win.eventdata.company",
    "Product": "win.eventdata.product",
    "Description": "win.eventdata.description",
    "Hashes": "win.eventdata.hashes",
}
PS_FIELDS = {
    "ScriptBlockText": "win.eventdata.scriptBlockText",
    "Path": "win.eventdata.path",
    "ScriptBlockId": "win.eventdata.scriptBlockId",
}
# (product, category) -> {"anchor": (kind, value), "fields": {...},
#                         "show": preferred field to interpolate into the description}
LOGSOURCE = {
    ("windows", "process_creation"): {
        "anchor": ("if_group", "sysmon_event1"), "fields": PROC_FIELDS,
        "show": ("win.eventdata.commandLine", "win.eventdata.image")},
    ("windows", "ps_script"): {
        "anchor": ("if_sid", "91802"), "fields": PS_FIELDS,
        "show": ("win.eventdata.scriptBlockText",)},
}

# Sigma severity -> Wazuh level. L12 = "confirmed attack technique" in this lab's
# convention (and clears stock discovery rules at L3, so a Sigma detection wins
# the one-rule-per-event precedence and actually surfaces, instead of losing a
# tie to a lower-specificity stock rule).
LEVEL_MAP = {"critical": 13, "high": 12, "medium": 8, "low": 5, "informational": 3}

SUPPORTED_MODIFIERS = {"contains", "startswith", "endswith", "re", "all"}


class SkipRule(Exception):
    """Raised when a rule can't be faithfully compiled — reported, not hidden."""


def sigma_wildcard_to_regex(val):
    """Translate a Sigma string literal (may embed * and ? wildcards) to PCRE2."""
    out = []
    for ch in str(val):
        if ch == "*":
            out.append(".*")
        elif ch == "?":
            out.append(".")
        else:
            out.append(re.escape(ch))
    return "".join(out)


def build_pattern(values, modifiers):
    """One Sigma field spec -> one PCRE2 pattern (list values are OR'd here;
    the |all case is handled by the caller emitting multiple <field> lines)."""
    is_re = "re" in modifiers
    frags = []
    for v in values:
        if is_re:
            frag = str(v)                      # already a regex; trust it
        else:
            frag = sigma_wildcard_to_regex(v)
            if "startswith" in modifiers:
                frag = "^" + frag
            elif "endswith" in modifiers:
                frag = frag + "$"
            elif "contains" in modifiers:
                pass                            # unanchored substring
            else:
                frag = "^" + frag + "$"         # plain = full match (Sigma default)
        frags.append(frag)
    body = frags[0] if len(frags) == 1 else "(" + "|".join(frags) + ")"
    return "(?i)" + body


def _compile_map(sel, field_map):
    """A Sigma map {field|mod: value(s)} -> AND-list of Wazuh field matchers:
       [(wazuh_field, pcre2_pattern), ...]  (all AND'd together)."""
    matchers = []
    for key, raw in sel.items():
        parts = key.split("|")
        field, mods = parts[0], set(parts[1:])
        unknown = mods - SUPPORTED_MODIFIERS
        if unknown:
            raise SkipRule(f"unsupported field modifier(s) {sorted(unknown)} on '{key}'")
        if field not in field_map:
            raise SkipRule(f"field '{field}' not mapped for this logsource")
        if raw is None:
            raise SkipRule(f"null match on '{key}' (field-exists test) unsupported")
        wfield = field_map[field]
        values = raw if isinstance(raw, list) else [raw]
        if "all" in mods:
            # every value must be present -> one <field> per value (Wazuh AND's them)
            for v in values:
                matchers.append((wfield, build_pattern([v], mods - {"all"})))
        else:
            matchers.append((wfield, build_pattern(values, mods)))  # list = OR in one field
    return matchers


def compile_selection(sel, field_map):
    """A Sigma selection -> list of ALTERNATIVES (an OR), where each alternative
    is an AND-list of (wazuh_field, pcre2) matchers.
      - a map            -> 1 alternative
      - a list of maps   -> N alternatives (Sigma's cross-field OR)
    Wazuh AND's <field> lines and has no rule-level OR, so a multi-alternative
    selection is later multiplied out into multiple Wazuh rules (Cartesian)."""
    if isinstance(sel, dict):
        return [_compile_map(sel, field_map)]
    if isinstance(sel, list):
        if not all(isinstance(x, dict) for x in sel):
            raise SkipRule("selection is a list of keywords (full-text search) "
                           "— no field context to map to a Wazuh field")
        return [_compile_map(x, field_map) for x in sel]
    raise SkipRule(f"unsupported selection type {type(sel).__name__}")


# --- condition -> variants ---------------------------------------------------
# Each "variant" is one Wazuh rule: a set of positive selections (AND'd) plus a
# set of negated selections. A top-level OR yields multiple variants.
def resolve_names(token, selections):
    """Expand 'sel*' / 'them' to concrete selection names."""
    if token == "them":
        return list(selections)
    if token.endswith("*"):
        pref = token[:-1]
        return [n for n in selections if n.startswith(pref)]
    if token in selections:
        return [token]
    raise SkipRule(f"condition references unknown selection '{token}'")


def parse_condition(cond, selections):
    """Return a list of variants: [{'pos': [names], 'neg': [names]}, ...].
    Handles the shapes that cover the vast majority of process_creation rules;
    anything else is skipped with a reason (aggregation/near/timeframe)."""
    c = cond.strip()
    low = c.lower()
    for bad in (" | count", "| count", " near ", "|near", " by "):
        if bad in low:
            raise SkipRule(f"condition uses aggregation/correlation ('{bad.strip()}')")

    # "X of sel*" / "X of them"
    m = re.fullmatch(r"(1|all) of (\S+)", c)
    if m:
        quant, names = m.group(1), resolve_names(m.group(2), selections)
        if not names:
            raise SkipRule(f"'{c}' matched no selections")
        if quant == "all":
            return [{"pos": names, "neg": []}]
        return [{"pos": [n], "neg": []} for n in names]        # 1 of ... = OR

    # top-level OR of simple terms (no parentheses handling — skip if nested)
    if "(" in c or ")" in c:
        raise SkipRule("parenthesised condition not supported")
    if " or " in low:
        variants = []
        for term in re.split(r"\s+or\s+", c, flags=re.I):
            variants.extend(parse_condition(term, selections))
        return variants

    # AND-chain with optional 'not'
    pos, neg = [], []
    tokens = re.split(r"\s+and\s+", c, flags=re.I)
    i = 0
    while i < len(tokens):
        tok = tokens[i].strip()
        if tok.lower() == "not":                # "and not X"
            i += 1
            if i >= len(tokens):
                raise SkipRule("dangling 'not' in condition")
            neg.extend(resolve_names(tokens[i].strip(), selections))
        elif tok.lower().startswith("not "):
            neg.extend(resolve_names(tok[4:].strip(), selections))
        else:
            pos.extend(resolve_names(tok, selections))
        i += 1
    if not pos:
        raise SkipRule("condition has no positive selection")
    return [{"pos": pos, "neg": neg}]


def mitre_ids(tags):
    ids = []
    for t in tags or []:
        m = re.fullmatch(r"attack\.t(\d+(?:\.\d+)?)", str(t).lower())
        if m:
            ids.append("T" + m.group(1).upper())
    return ids


def tactic_groups(tags):
    known = {"reconnaissance", "resource_development", "initial_access", "execution",
             "persistence", "privilege_escalation", "defense_evasion", "credential_access",
             "discovery", "lateral_movement", "collection", "command_and_control",
             "exfiltration", "impact"}
    out = []
    for t in tags or []:
        s = str(t).lower()
        if s.startswith("attack."):
            name = s[7:].replace("-", "_")   # Sigma writes tactics with hyphens
            if name in known:
                out.append(name)
    return out


# --- id allocation -----------------------------------------------------------
class IdAllocator:
    def __init__(self, path, base):
        self.path = path
        self.base = base
        self.map = json.load(open(path)) if os.path.exists(path) else {}
        self._used = set(self.map.values())

    def get(self, key):
        if key in self.map:
            return self.map[key]
        nid = self.base
        while nid in self._used:
            nid += 1
        self.map[key] = nid
        self._used.add(nid)
        return nid

    def save(self):
        json.dump(dict(sorted(self.map.items(), key=lambda kv: kv[1])),
                  open(self.path, "w"), indent=2)


# --- emit --------------------------------------------------------------------
def render_rule(rid, level, anchor, matchers, negs, desc, techniques, groups, comment):
    kind, value = anchor          # ("if_group", "sysmon_event1") | ("if_sid", "91802")
    lines = [f"  <!-- {comment} -->", f'  <rule id="{rid}" level="{level}">']
    lines.append(f"    <{kind}>{value}</{kind}>")
    for wfield, pat in matchers:
        lines.append(f'    <field name="{wfield}" type="pcre2">{xml_escape(pat)}</field>')
    for wfield, pat in negs:
        lines.append(f'    <field name="{wfield}" type="pcre2" negate="yes">{xml_escape(pat)}</field>')
    lines.append("    <options>no_full_log</options>")
    lines.append(f"    <description>{xml_escape(desc)}</description>")
    if techniques:
        lines.append("    <mitre>")
        for t in techniques:
            lines.append(f"      <id>{t}</id>")
        lines.append("    </mitre>")
    grp = ",".join(groups + ["sigma"]) + ","
    lines.append(f"    <group>{grp}</group>")
    lines.append("  </rule>")
    return "\n".join(lines)


def compile_file(path, alloc):
    """Compile one Sigma YAML file -> (list of rendered <rule> strings, meta)."""
    docs = [d for d in yaml.safe_load_all(open(path)) if isinstance(d, dict)]
    # ignore Sigma "collection" globals; take the first doc carrying a detection
    doc = next((d for d in docs if "detection" in d and "logsource" in d), None)
    if doc is None:
        raise SkipRule("no logsource+detection document")

    ls = doc.get("logsource", {})
    lskey = (ls.get("product"), ls.get("category"))
    cfg = LOGSOURCE.get(lskey)
    if cfg is None:
        raise SkipRule(f"logsource {lskey[0]}/{lskey[1]} unsupported "
                       f"(have: {', '.join(f'{p}/{c}' for p, c in LOGSOURCE)})")
    anchor, field_map, show_pref = cfg["anchor"], cfg["fields"], cfg["show"]

    detection = doc["detection"]
    cond = detection.get("condition")
    if isinstance(cond, list):
        raise SkipRule("multiple conditions (rule aggregation) unsupported")
    selections = {k: v for k, v in detection.items() if k != "condition"}

    # pre-compile every named selection (raises SkipRule on anything unmappable)
    compiled = {name: compile_selection(sel, field_map) for name, sel in selections.items()}
    variants = parse_condition(cond, selections)

    guid = doc.get("id") or os.path.basename(path)
    title = doc.get("title", os.path.basename(path))
    level = LEVEL_MAP.get(str(doc.get("level", "medium")).lower(), 8)
    techniques = mitre_ids(doc.get("tags"))
    groups = tactic_groups(doc.get("tags")) or ["windows"]

    # Expand to concrete Wazuh rules. Each variant AND's its positive selections;
    # a selection may carry several alternatives (OR), so the positive selections
    # are multiplied out (Cartesian) — this is where "one Sigma rule -> several
    # Wazuh rules" comes from, since Wazuh has no rule-level OR.
    emitted = []  # (matchers, negs)
    for var in variants:
        negs = []
        for name in var["neg"]:
            alts = compiled[name]
            if len(alts) != 1 or len(alts[0]) != 1:
                raise SkipRule(f"negated selection '{name}' isn't a single field "
                               "— only single-field negation maps to one Wazuh rule")
            negs.extend(alts[0])
        pos_alt_lists = [compiled[name] for name in var["pos"]]
        for combo in itertools.product(*pos_alt_lists):
            matchers = [m for alt in combo for m in alt]
            if not matchers:
                raise SkipRule("variant has no positive field matcher")
            emitted.append((matchers, negs))

    rendered = []
    multi = len(emitted) > 1
    for idx, (matchers, negs) in enumerate(emitted):
        key = guid if not multi else f"{guid}#{idx}"
        rid = alloc.get(key)
        # interpolate a helpful field into the description if present
        present = {wf for wf, _ in matchers}
        shown = next((wf for wf in show_pref if wf in present), None)
        suffix = f" — $({shown})" if shown else ""
        desc = f"[Sigma] {title}{suffix}"
        comment = f"Sigma: {title} | id={guid} | src={os.path.basename(path)}"
        if multi:
            comment += f" | variant {idx + 1}/{len(emitted)}"
        rendered.append(render_rule(rid, level, anchor, matchers, negs, desc,
                                    techniques, groups, comment))
    return rendered, {"title": title, "techniques": techniques, "variants": len(emitted)}


def main():
    ap = argparse.ArgumentParser(description="Compile Sigma rules to Wazuh XML (lab-tuned).")
    ap.add_argument("--rules-dir", default=DEFAULT_RULES)
    ap.add_argument("--out", default=DEFAULT_OUT)
    ap.add_argument("--id-map", default=DEFAULT_IDMAP)
    ap.add_argument("--id-base", type=int, default=100500)
    ap.add_argument("--check", action="store_true", help="dry run: report only, write nothing")
    args = ap.parse_args()

    files = sorted(glob.glob(os.path.join(args.rules_dir, "*.yml")) +
                   glob.glob(os.path.join(args.rules_dir, "*.yaml")))
    if not files:
        print(f"no Sigma rules found in {args.rules_dir}", file=sys.stderr)
        sys.exit(2)

    alloc = IdAllocator(args.id_map, args.id_base)
    rendered_all, skipped = [], []
    for path in files:
        base = os.path.basename(path)
        try:
            rules, meta = compile_file(path, alloc)
            rendered_all.extend(rules)
            techs = ",".join(meta["techniques"]) or "-"
            print(f"  [ok]   {base:45} {techs:12} "
                  f"-> {meta['variants']} rule(s)")
        except SkipRule as e:
            skipped.append((base, str(e)))
            print(f"  [skip] {base:45} {e}")
        except Exception as e:                          # noqa: BLE001 — report, don't crash the batch
            skipped.append((base, f"ERROR: {e}"))
            print(f"  [ERR]  {base:45} {e}")

    print(f"\n  {len(rendered_all)} Wazuh rule(s) from "
          f"{len(files) - len(skipped)}/{len(files)} Sigma file(s); "
          f"{len(skipped)} skipped")

    header = (
        "<!--\n"
        "  sigma_local_rules.xml — GENERATED by phase-4-detection/sigma/sigma-to-wazuh.py\n"
        "  DO NOT EDIT BY HAND. Edit the Sigma YAML under phase-4-detection/sigma/rules/\n"
        "  and re-run the compiler. Deployed to /var/ossec/etc/rules/ by the siem role.\n"
        f"  Source rules: {', '.join(os.path.basename(f) for f in files)}\n"
        "-->\n"
        '<group name="local,windows,sysmon,sigma,">\n\n')
    body = "\n\n".join(rendered_all)
    out_xml = header + body + "\n\n</group>\n"

    if args.check:
        print("\n--check: no files written.")
        sys.exit(1 if skipped else 0)

    with open(args.out, "w") as f:
        f.write(out_xml)
    alloc.save()
    print(f"\n  wrote {args.out}")
    print(f"  id map -> {args.id_map}")


if __name__ == "__main__":
    main()
