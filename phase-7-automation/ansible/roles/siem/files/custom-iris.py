#!/usr/bin/env python3
# ===========================================================================
# custom-iris.py — Wazuh integratord -> DFIR-IRIS alert creation.
#
# integratord runs this on every alert matching the <integration> filter
# (level >= N). It turns the Wazuh alert into a DFIR-IRIS *alert* via the IRIS
# REST API (POST /alerts/add) — the SOC-operations layer: a high-severity
# detection becomes a triageable analyst work item in IRIS that promotes into a
# full case, instead of scrolling past in the SIEM. The raw Wazuh alert rides
# along in alert_source_content (so the analyst has everything), and the MITRE
# techniques + rule groups + involved IPs become IRIS tags.
#
# IRIS's own iris_misp_module can then enrich the alert's indicators against MISP,
# closing the loop: SIEM -> case management -> threat intel, all professional tools.
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


def main():
    with open(ALERT_FILE) as f:
        alert = json.load(f)
    rule = alert.get("rule", {})
    agent = alert.get("agent", {})
    level = int(rule.get("level", 0))
    techniques = (rule.get("mitre", {}) or {}).get("id", []) or []
    ips = collect_ips(alert)

    tags = ["wazuh", f"agent:{agent.get('name', '?')}", f"rule:{rule.get('id', '?')}"]
    tags += techniques + [f"ioc:{v}" for v in ips]

    title = f"[Wazuh] {rule.get('description', 'alert')}"[:250]
    desc = (f"**Wazuh detection** on `{agent.get('name', '?')}` "
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
        "alert_tags": ",".join(t for t in tags if t),
    }
    if evt:
        payload["alert_source_event_time"] = evt

    try:
        r = requests.post(
            f"{IRIS_BASE}/alerts/add",
            headers={"Authorization": f"Bearer {API_KEY}",
                     "Content-Type": "application/json"},
            data=json.dumps(payload), verify=False, timeout=15)
        if r.status_code >= 300 or r.json().get("status") != "success":
            sys.stderr.write(f"iris: add failed http={r.status_code}: {r.text[:300]}\n")
    except Exception as e:
        sys.stderr.write(f"iris: exception {str(e)[:200]}\n")


if __name__ == "__main__":
    main()
