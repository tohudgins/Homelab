#!/usr/bin/env bash
# ===========================================================================
# greenbone-scan.sh — one command to vuln-scan the CORP hosts from scan-01.
#
# Drives Greenbone's GMP API (via the stack's gvm-tools container) to create —
# idempotently — a scan Target + Task for the given hosts and start it. Turns
# "run a vulnerability scan against CORP" into a single command, the same way
# lab.sh turns "run the lab" into one.
#
# Deployed to scan-01 by the `scan` Ansible role. Run it there:
#   ssh scan-01 'sudo /opt/greenbone/greenbone-scan.sh'
# Then watch progress:
#   ssh scan-01 'sudo /opt/greenbone/greenbone-scan.sh status'
#
# Prereq: the GVMD_DATA feed must have finished syncing (that's where the "Full
# and fast" scan config comes from). Check with:  <get_feeds/> — no
# <currently_syncing> under GVMD_DATA. On a fresh stack that's ~20-40 min.
# ===========================================================================
set -euo pipefail

PROJECT="${PROJECT:-greenbone-community-edition}"
DEPLOY_DIR="${DEPLOY_DIR:-/opt/greenbone}"
GMP_USER="${GMP_USER:-admin}"
GMP_PASS="${GMP_PASS:-GreenboneAdmin2026!}"

# What to scan. dc-01 (Samba AD DC) + ws-01 (Windows victim), both on CORP —
# reachable because rtr-01 allows REDTEAM -> CORP.
TARGET_NAME="${TARGET_NAME:-CORP hosts}"
TARGET_HOSTS="${TARGET_HOSTS:-10.10.10.10,10.10.10.50}"
TASK_NAME="${TASK_NAME:-CORP full-and-fast}"

# Feed-provided scan config + scanner. Names are resolved from the feed; the
# well-known stable UUIDs are used as a fallback if a lookup comes back empty.
CONFIG_NAME="${CONFIG_NAME:-Full and fast}"
CONFIG_ID_FALLBACK="daba56c8-73ec-11df-a475-002264764cea"   # Full and fast
SCANNER_ID="${SCANNER_ID:-08b69003-5fc2-4037-a479-93b440211c73}"  # OpenVAS Default
# A target needs a port list (create_target 400s without one). "All IANA assigned
# TCP" is a well-known feed UUID and the sensible default — the CORP services
# (SMB/Kerberos/RPC/LDAP) are all TCP. Override for UDP coverage if needed.
PORT_LIST_ID="${PORT_LIST_ID:-33d0cd82-57c6-11e1-8ed1-406186ea4fc5}"  # All IANA assigned TCP
# Scan across the router (REDTEAM -> CORP): the default host-alive check is
# unreliable over the routed hop (ARP can't cross subnets; ws-01 blocks ICMP),
# so hosts get marked dead and skipped (a 40s scan, 0 results). We KNOW they're
# up, so tell OpenVAS to scan regardless.
ALIVE_TEST="${ALIVE_TEST:-Consider Alive}"

cd "$DEPLOY_DIR"

gmp() {  # send one GMP command, echo ONLY the XML response.
  # --no-deps + 2>/dev/null are load-bearing: without them `docker compose run`
  # re-runs the one-shot feed containers and prints "Container ... Running/Healthy"
  # chatter to stderr, which otherwise pollutes the XML the callers parse.
  docker compose -p "$PROJECT" run --rm --no-deps -T gvm-tools \
    gvm-cli --gmp-username "$GMP_USER" --gmp-password "$GMP_PASS" \
    socket --socketpath /run/gvmd/gvmd.sock --xml "$1" 2>/dev/null
}

# id of the first <elem> whose <name> equals $2 (stdin = GMP response XML).
# Uses `python3 -c` (program as an arg): `python3 - <<HEREDOC` would make the
# heredoc *become* stdin, so the piped XML would never reach sys.stdin.
pick_id() {
  python3 -c '
import sys, xml.etree.ElementTree as ET
elem, want = sys.argv[1], sys.argv[2]
try:
    root = ET.fromstring(sys.stdin.read())
except ET.ParseError:
    sys.exit(0)
for e in root.iter(elem):
    if (e.findtext("name") or "") == want:
        print(e.get("id") or ""); break
' "$1" "$2"
}
attr_id() { python3 -c "import sys,xml.etree.ElementTree as ET;print(ET.fromstring(sys.stdin.read()).get('id') or '')"; }

# ---- status subcommand: show task run state + progress ----------------------
if [ "${1:-}" = "status" ]; then
  echo "== Tasks =="
  gmp '<get_tasks/>' | python3 -c '
import sys, xml.etree.ElementTree as ET
try:
    r = ET.fromstring(sys.stdin.read())
except Exception:
    print("  (gvmd not ready / no response)"); sys.exit(0)
found = False
for t in r.iter("task"):
    found = True
    print("  %-26s %-12s %s%%" % ((t.findtext("name") or ""), (t.findtext("status") or ""), (t.findtext("progress") or "")))
if not found:
    print("  (no tasks yet)")
'
  exit 0
fi

echo "== Resolving feed objects =="
# "Full and fast" has a stable, well-known UUID. Listing ALL configs returns a
# large response that `docker compose run` truncates into malformed XML — so
# verify the config by UUID with a FILTERED (small) query instead of parsing the
# whole list. Same reasoning applies to any large GMP list: filter it down.
CONFIG_ID="$CONFIG_ID_FALLBACK"
if ! gmp "<get_configs config_id=\"$CONFIG_ID\"/>" | grep -q "$CONFIG_ID"; then
  echo "!! Scan config '$CONFIG_NAME' ($CONFIG_ID) not present yet."
  echo "   The GVMD_DATA feed is probably still syncing — try again shortly."
  exit 1
fi
echo "   config  '$CONFIG_NAME' = $CONFIG_ID"
echo "   scanner OpenVAS Default = $SCANNER_ID"

# Capture-then-parse (not gmp|parser directly): a gmp pipeline can exit non-zero
# on an expected-empty list (SIGPIPE / docker compose run teardown), which under
# `set -euo pipefail` would abort the whole script. `|| true` on the parse keeps
# an empty result from being fatal; we validate the ids explicitly instead.
echo "== Target =="
targets_xml="$(gmp '<get_targets/>')"
TARGET_ID="$(printf '%s' "$targets_xml" | pick_id target "$TARGET_NAME" || true)"
if [ -z "$TARGET_ID" ]; then
  create_xml="$(gmp "<create_target><name>${TARGET_NAME}</name><hosts>${TARGET_HOSTS}</hosts><port_list id=\"${PORT_LIST_ID}\"/><alive_tests>${ALIVE_TEST}</alive_tests></create_target>")"
  TARGET_ID="$(printf '%s' "$create_xml" | attr_id || true)"
  echo "   created target '$TARGET_NAME' ($TARGET_HOSTS) = $TARGET_ID"
else
  echo "   reusing target '$TARGET_NAME' = $TARGET_ID"
fi
[ -n "$TARGET_ID" ] || { echo "!! could not create/find target"; exit 1; }

echo "== Task =="
tasks_xml="$(gmp '<get_tasks/>')"
TASK_ID="$(printf '%s' "$tasks_xml" | pick_id task "$TASK_NAME" || true)"
if [ -z "$TASK_ID" ]; then
  create_xml="$(gmp "<create_task><name>${TASK_NAME}</name><config id=\"${CONFIG_ID}\"/><target id=\"${TARGET_ID}\"/><scanner id=\"${SCANNER_ID}\"/></create_task>")"
  TASK_ID="$(printf '%s' "$create_xml" | attr_id || true)"
  echo "   created task '$TASK_NAME' = $TASK_ID"
else
  echo "   reusing task '$TASK_NAME' = $TASK_ID"
fi
[ -n "$TASK_ID" ] || { echo "!! could not create/find task"; exit 1; }

echo "== Start =="
gmp "<start_task task_id=\"${TASK_ID}\"/>" | grep -o 'status="[0-9]*"[^>]*' | head -1 || true
echo
echo "Scan launched. Watch it with:  sudo $DEPLOY_DIR/$(basename "$0") status"
echo "Or in the GSA web UI (Scans > Tasks) — from the Mac: 'make dashboards', then https://localhost:9392."
