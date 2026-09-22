#!/usr/bin/env python3
# ===========================================================================
# custom-misp.py — Wazuh integratord -> MISP IOC lookup.
#
# integratord runs this on every alert matching the <integration> filter. It
# pulls the alert's indicators (IPs, file hashes) and asks MISP whether any is a
# known IOC via /attributes/restSearch. On a hit it injects a NEW alert back into
# Wazuh through the analysisd queue socket (location "misp"), which fires the
# custom MISP rules (100300+). This makes MISP — a real threat-intel platform,
# correlating and sharing IOCs — the live IOC engine behind the SIEM, replacing
# the static CDB list (phase-4-detection/threat-intel-cdb-enrichment.md).
#
# Invoked by Wazuh as: custom-misp <alert_file> <api_key> <hook_url> [options]
# Deployed to /var/ossec/integrations/ by the `siem` role.
# ===========================================================================
import sys
import json
import re
from socket import socket, AF_UNIX, SOCK_DGRAM

try:
    import requests
    import urllib3
    urllib3.disable_warnings()
except ImportError:
    sys.exit("misp: python3 requests/urllib3 not installed")

# verify=False below (flagged by Semgrep's disabled-cert-validation rule) is the
# same accepted, documented risk as custom-iris.py's identical call: MISP's cert
# is self-signed, and this is siem-01 talking to misp-01 over the internal SOC
# segment only. See custom-iris.py's fuller note.

# Wazuh passes: [1]=alert file, [2]=api_key, [3]=hook_url (MISP base URL)
ALERT_FILE = sys.argv[1]
API_KEY = sys.argv[2]
MISP_BASE = sys.argv[3].rstrip("/")

SOCKET_ADDR = "/var/ossec/queue/sockets/queue"
HASH_RE = re.compile(r"^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$")


def send_event(msg, agent=None):
    """Inject an event into analysisd (location 'misp') so rules can match it."""
    payload = json.dumps(msg)
    if agent is None or agent.get("id") == "000":
        string = f"1:misp:{payload}"
    else:
        string = f"1:[{agent['id']}] ({agent['name']}) {agent.get('ip','any')}->misp:{payload}"
    sock = socket(AF_UNIX, SOCK_DGRAM)
    sock.connect(SOCKET_ADDR)
    sock.send(string.encode())
    sock.close()


def collect_iocs(alert):
    """Return [(misp_type_hint, value)] of candidate indicators in the alert."""
    data = alert.get("data", {})
    out = []
    # IPs — Suricata (src_ip/dest_ip), stock decoders (srcip/dstip), both nests.
    for key in ("src_ip", "dest_ip", "srcip", "dstip"):
        for v in (data.get(key), alert.get(key)):
            if v and re.match(r"^\d{1,3}(\.\d{1,3}){3}$", str(v)):
                out.append(("ip", str(v)))
    # File hashes — FIM (syscheck) and Sysmon.
    sc = alert.get("syscheck", {})
    for hk in ("md5_after", "sha1_after", "sha256_after"):
        if sc.get(hk):
            out.append(("hash", sc[hk]))
    win = data.get("win", {}).get("eventdata", {}) if isinstance(data.get("win"), dict) else {}
    for token in re.split(r"[;,]", str(win.get("hashes", ""))):
        h = token.split("=")[-1].strip()
        if HASH_RE.match(h):
            out.append(("hash", h))
    # de-dup, preserve order
    seen = set()
    return [x for x in out if not (x[1] in seen or seen.add(x[1]))]


def misp_lookup(value):
    """Query MISP for an IOC value; return the first matching Attribute or None."""
    try:
        r = requests.post(
            f"{MISP_BASE}/attributes/restSearch",
            headers={"Authorization": API_KEY, "Accept": "application/json",
                     "Content-Type": "application/json"},
            data=json.dumps({"returnFormat": "json", "value": value, "limit": 1,
                             "enforceWarninglist": True}),
            verify=False, timeout=15)  # nosemgrep: python.requests.security.disabled-cert-validation.disabled-cert-validation
        attrs = r.json().get("response", {}).get("Attribute", [])
        return attrs[0] if attrs else None
    except Exception as e:
        send_event({"integration": "misp", "misp": {"error": str(e)[:200]}})
        return None


def main():
    with open(ALERT_FILE) as f:
        alert = json.load(f)
    agent = alert.get("agent", {})
    for _, value in collect_iocs(alert):
        attr = misp_lookup(value)
        if not attr:
            continue
        send_event({
            "integration": "misp",
            "misp": {
                "value": value,
                "category": attr.get("category"),
                "type": attr.get("type"),
                "event_id": attr.get("event_id"),
                "comment": (attr.get("comment") or "")[:200],
                "source": {
                    "alert_id": alert.get("id"),
                    "rule": alert.get("rule", {}).get("id"),
                    "level": alert.get("rule", {}).get("level"),
                    "description": alert.get("rule", {}).get("description"),
                },
            },
        }, agent)


if __name__ == "__main__":
    main()
