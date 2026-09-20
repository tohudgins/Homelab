#!/usr/bin/env python3
# ===========================================================================
# custom-iris.py — Wazuh integratord -> DFIR-IRIS alert creation + the soc-ops
# playbook (auto-escalate-or-merge into a case, no analyst click required).
#
# integratord runs this on every alert matching the <integration> filter
# (level >= N). It turns the Wazuh alert into a DFIR-IRIS *alert* via the IRIS
# REST API (POST /alerts/add) — the SOC-operations layer: a high-severity
# detection becomes a triageable analyst work item in IRIS instead of scrolling
# past in the SIEM. The raw Wazuh alert rides along in alert_source_content (so
# the analyst has everything), and the MITRE techniques + rule groups + involved
# IPs become IRIS tags. The alert also carries structured IOCs and an asset (the
# Wazuh agent) — not just text tags — because that structure is what the
# playbook below and IRIS's own alert-filter correlation actually key on.
#
# PLAYBOOK (added 2026-09-20, see phase-4-detection/soc-ops-iris.md #7): what
# section 6 of that doc did by hand — escalate an alert to a case, or merge a
# related one into an existing case — now happens automatically, every time:
#   1. Create the alert with its IOCs/asset attached.
#   2. Ask IRIS (GET /alerts/filter?alert_assets=<agent>) whether an OPEN case
#      already touches this same asset. IRIS's own filter, not a hand-rolled
#      correlation — real, documented query params, not the UI similarity-graph
#      endpoint (/alerts/similarities), which returns a vis.js node/edge graph
#      meant for rendering, not programmatic parsing.
#   3. Found one -> merge this alert into it (POST /alerts/merge). This is the
#      mechanism that threads an automated-response confirmation (rules
#      100530-100532, see local_rules.xml) into the SAME case as the detection
#      that triggered the response — both alerts share the agent asset, no
#      state-passing between the two Wazuh events required.
#   4. Found none -> escalate to a brand-new case (POST /alerts/escalate).
#   5. If this alert's rule has an automated response wired in ossec.conf
#      (AR_WIRED_RULES below), add a case task noting it — so an analyst
#      opening the case sees "there's an automated response for this" even
#      before/without a confirmation event arriving.
#
# Honest scope boundary: firewall-drop (sshd brute force, rules 100010/100011/
# 100013) is a stock Wazuh binary. It gets the static task note in step 5, not
# a live-confirmed merge like disable-ad-account does — modifying vendor code
# to self-report wasn't worth it for one AR command.
#
# Invoked by Wazuh as: custom-iris <alert_file> <api_key> <hook_url> [options]
#   api_key  = an IRIS user API key (<api_key> in the <integration> block)
#   hook_url = the IRIS base URL, e.g. https://10.10.30.20:8443 (<hook_url>)
# Deployed to /var/ossec/integrations/ by the `siem` role.
# ===========================================================================
import sys
import json
import re

try:
    import requests
    import urllib3
    urllib3.disable_warnings()
except ImportError:
    sys.exit("iris: python3 requests/urllib3 not installed")

ALERT_FILE = sys.argv[1]
API_KEY = sys.argv[2]
IRIS_BASE = sys.argv[3].rstrip("/")
HEADERS = {"Authorization": f"Bearer {API_KEY}", "Content-Type": "application/json"}

# rule_id -> human description of the automated response ossec.conf (siem role)
# wires to it. Static, hand-maintained — Wazuh's alert JSON doesn't expose "what
# AR is linked to this rule", so this has to mirror the <active-response> blocks
# in phase-7-automation/ansible/roles/siem/tasks/main.yml by hand. Keep in sync.
AR_WIRED_RULES = {
    "100010": "firewall-drop — 10 min source-IP block (sshd brute force)",
    "100011": "firewall-drop — 10 min source-IP block (sshd brute force)",
    "100013": "firewall-drop — 10 min source-IP block (sshd brute force, mixed-failure-type)",
    "100041": "disable-ad-account — Samba AD account disabled (confirmation: rules 100530-100532)",
    "100450": "yara — on-write malware scan of the changed file",
}

# How many of the most recent alerts on the same asset to inspect for an
# already-open case to merge into.
CORRELATION_LOOKBACK_ALERTS = 10

# agent name -> IRIS asset_type_id (GET /manage/asset-type/list on a live IRIS
# to regenerate this if the seed data ever changes). dc-01 is "Linux - Server"
# not "Windows - DC" — it's a Samba AD DC, not Windows Server (see
# docs/design-decisions.md); the asset type should reflect the real OS.
ASSET_TYPE_BY_AGENT = {
    "dc-01": 3, "fs-01": 3, "rtr-01": 3, "dmz-01": 3, "siem-01": 3, "misp-01": 3,
    "ws-01": 9,     # Windows - Computer
    "scan-01": 3,
}
DEFAULT_ASSET_TYPE_ID = 3  # Linux - Server


def severity_id(level):
    # Wazuh level (0-15) -> IRIS severity_id. IRIS ids are NOT ordinal:
    # 2=Unspecified 3=Informational 4=Low 1=Medium 5=High 6=Critical.
    if level >= 12:
        return 6   # Critical
    if level >= 9:
        return 5   # High
    if level >= 6:
        return 1   # Medium
    return 4       # Low


def collect_ips(alert):
    data = alert.get("data", {})
    out = []
    for key in ("src_ip", "dest_ip", "srcip", "dstip"):
        for v in (data.get(key), alert.get(key)):
            if v and re.match(r"^\d{1,3}(\.\d{1,3}){3}$", str(v)):
                out.append(str(v))
    seen = set()
    return [x for x in out if not (x in seen or seen.add(x))]


def find_open_case(asset_name):
    """Return the case_id of the most recent OPEN case already touching this
    asset, or None. Two calls, both documented API (not the UI similarity
    graph at /alerts/similarities, which returns vis.js nodes/edges meant for
    rendering, not programmatic parsing — verified empirically 2026-09-20):
      1. GET /alerts/filter?alert_assets=<name> — each alert's `cases` field
         is a plain list of case ids it's linked to (escalated or merged).
      2. GET /manage/cases/<id> for the first candidate, check close_date.
    """
    try:
        r = requests.get(
            f"{IRIS_BASE}/alerts/filter",
            headers=HEADERS,
            params={"alert_assets": asset_name, "per_page": CORRELATION_LOOKBACK_ALERTS, "sort": "desc"},
            verify=False, timeout=15)
        if r.status_code >= 300:
            sys.stderr.write(f"iris: correlation filter failed http={r.status_code}: {r.text[:200]}\n")
            return None
        candidate_case_ids = []
        for a in r.json().get("data", {}).get("alerts", []):
            candidate_case_ids += a.get("cases") or []
        for case_id in dict.fromkeys(candidate_case_ids):  # de-dup, keep order (most recent first)
            cr = requests.get(f"{IRIS_BASE}/manage/cases/{case_id}", headers=HEADERS,
                              verify=False, timeout=15)
            if cr.status_code < 300 and cr.json().get("data", {}).get("close_date") is None:
                return case_id
    except Exception as e:
        sys.stderr.write(f"iris: correlation exception {str(e)[:200]}\n")
    return None


def escalate_or_merge(alert_id, asset_name, case_title, source_note, case_tags):
    """The playbook decision: merge into a related open case, or start a new
    one. Returns the case_id, or None on failure (both are best-effort — a
    failure here still leaves the plain IRIS alert from main() in place for an
    analyst to triage by hand). One find_open_case call decides both the
    branch and the note wording, so main() doesn't need a second lookup.
    """
    existing_case_id = find_open_case(asset_name)
    if existing_case_id:
        note = f"Auto-merged by the soc-ops playbook — correlated by asset with case #{existing_case_id}. {source_note}"
        r = requests.post(
            f"{IRIS_BASE}/alerts/merge/{alert_id}", headers=HEADERS,
            data=json.dumps({
                "target_case_id": existing_case_id,
                "assets_import_list": [asset_name],
                "iocs_import_list": [],
                "note": note,
                "case_tags": case_tags,
            }), verify=False, timeout=15)
        action, case_id = "merged into", existing_case_id
    else:
        note = f"Auto-escalated by the soc-ops playbook — no correlated open case found. {source_note}"
        r = requests.post(
            f"{IRIS_BASE}/alerts/escalate/{alert_id}", headers=HEADERS,
            data=json.dumps({
                "case_title": case_title,
                "assets_import_list": [asset_name],
                "iocs_import_list": [],
                "note": note,
                "case_tags": case_tags,
            }), verify=False, timeout=15)
        action, case_id = "escalated to new", None

    if r.status_code >= 300 or r.json().get("status") != "success":
        sys.stderr.write(f"iris: {action} case failed http={r.status_code}: {r.text[:300]}\n")
        return None

    case_id = case_id or r.json().get("data", {}).get("case_id")
    sys.stderr.write(f"iris: alert {alert_id} -> {action} case #{case_id}\n")
    return case_id


def add_ar_task(case_id, rule_id, ar_note):
    r = requests.post(
        f"{IRIS_BASE}/case/tasks/add", headers=HEADERS, params={"cid": case_id},
        data=json.dumps({
            "task_title": f"Automated response wired to rule {rule_id}",
            "task_description": ar_note,
            "task_status_id": 1,
            "task_assignees_id": [],
            "task_tags": "soar,automated-response",
        }), verify=False, timeout=15)
    if r.status_code >= 300 or r.json().get("status") != "success":
        sys.stderr.write(f"iris: add AR task failed http={r.status_code}: {r.text[:200]}\n")


def main():
    with open(ALERT_FILE) as f:
        alert = json.load(f)
    rule = alert.get("rule", {})
    agent = alert.get("agent", {})
    agent_name = agent.get("name", "?")
    level = int(rule.get("level", 0))
    rule_id = str(rule.get("id", ""))
    techniques = (rule.get("mitre", {}) or {}).get("id", []) or []
    ips = collect_ips(alert)

    tags = ["wazuh", f"agent:{agent_name}", f"rule:{rule_id}"]
    tags += techniques + [f"ioc:{v}" for v in ips]
    tag_str = ",".join(t for t in tags if t)

    title = f"[Wazuh] {rule.get('description', 'alert')}"[:250]
    desc = (f"**Wazuh detection** on `{agent_name}` "
            f"({agent.get('ip', '?')})\n\n"
            f"- Rule **{rule.get('id')}** (level {level})\n"
            f"- MITRE: {', '.join(techniques) or 'n/a'}\n"
            f"- Groups: {', '.join(rule.get('groups', []))}\n"
            f"- IPs: {', '.join(ips) or 'n/a'}\n"
            f"- Full log: `{str(alert.get('full_log', ''))[:500]}`")

    # IRIS parses a naive ISO datetime; drop Wazuh's trailing tz offset (+0000 / Z).
    evt = re.sub(r"([+-]\d{4}|Z)$", "", str(alert.get("timestamp", ""))).strip()

    payload = {
        "alert_title": title,
        "alert_description": desc,
        "alert_source": "Wazuh",
        "alert_source_ref": str(alert.get("id", "")),   # external ref -> IRIS dedups on it
        "alert_source_content": alert,                   # full raw alert for the analyst
        "alert_severity_id": severity_id(level),
        "alert_status_id": 2,        # New
        "alert_customer_id": 1,      # IrisInitialClient (default)
        "alert_tags": tag_str,
        # Structured, not just a text tag — this is what the playbook's
        # asset-based correlation (find_open_case) actually queries on.
        "alert_assets": [{
            "asset_name": agent_name,
            "asset_type_id": ASSET_TYPE_BY_AGENT.get(agent_name, DEFAULT_ASSET_TYPE_ID),
        }],
    }
    if evt:
        payload["alert_source_event_time"] = evt

    try:
        r = requests.post(f"{IRIS_BASE}/alerts/add", headers=HEADERS,
                          data=json.dumps(payload), verify=False, timeout=15)
        if r.status_code >= 300 or r.json().get("status") != "success":
            sys.stderr.write(f"iris: add failed http={r.status_code}: {r.text[:300]}\n")
            return
        alert_id = r.json().get("data", {}).get("alert_id")
    except Exception as e:
        sys.stderr.write(f"iris: exception {str(e)[:200]}\n")
        return

    try:
        case_id = escalate_or_merge(
            alert_id, agent_name,
            case_title=f"[Auto] {rule.get('description', 'Wazuh detection')} — {agent_name}"[:250],
            source_note=f"Source: Wazuh alert {alert.get('id', '?')} (rule {rule_id}, level {level}).",
            case_tags=tag_str)
        ar_note = AR_WIRED_RULES.get(rule_id)
        if case_id and ar_note:
            add_ar_task(case_id, rule_id, ar_note)
    except Exception as e:
        sys.stderr.write(f"iris: playbook exception {str(e)[:200]}\n")


if __name__ == "__main__":
    main()
