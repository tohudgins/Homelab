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

cd "$DEPLOY_DIR"

gmp() {  # send one GMP command, echo the XML response
  docker compose -p "$PROJECT" run --rm -T gvm-tools \
    gvm-cli --gmp-username "$GMP_USER" --gmp-password "$GMP_PASS" \
    socket --socketpath /run/gvmd/gvmd.sock --xml "$1"
}

# id of the first <elem> whose <name> equals $2 (stdin = GMP response XML)
pick_id() {
  python3 - "$1" "$2" <<'PY'
import sys, xml.etree.ElementTree as ET
elem, want = sys.argv[1], sys.argv[2]
try:
    root = ET.fromstring(sys.stdin.read())
except ET.ParseError:
    sys.exit(0)
for e in root.iter(elem):
    n = e.find('name')
    if n is not None and (n.text or '') == want:
        print(e.get('id') or ''); break
PY
}
attr_id() { python3 -c "import sys,xml.etree.ElementTree as ET;print(ET.fromstring(sys.stdin.read()).get('id') or '')"; }

# ---- status subcommand: show task run state + latest report summary ---------
if [ "${1:-}" = "status" ]; then
  echo "== Tasks =="
  gmp '<get_tasks/>' | python3 - <<'PY'
import sys, xml.etree.ElementTree as ET
r = ET.fromstring(sys.stdin.read())
for t in r.iter('task'):
    name = (t.findtext('name') or '')
    status = (t.findtext('status') or '')
    prog = (t.findtext('progress') or '')
    print(f"  {name:24} {status:12} {prog}%")
PY
  exit 0
fi

echo "== Resolving feed objects =="
CONFIG_ID="$(gmp '<get_configs/>' | pick_id config "$CONFIG_NAME")"
CONFIG_ID="${CONFIG_ID:-$CONFIG_ID_FALLBACK}"
if ! gmp '<get_configs/>' | grep -q "$CONFIG_ID"; then
  echo "!! Scan config '$CONFIG_NAME' ($CONFIG_ID) not present yet."
  echo "   The GVMD_DATA feed is probably still syncing — try again shortly."
  exit 1
fi
echo "   config  '$CONFIG_NAME' = $CONFIG_ID"
echo "   scanner OpenVAS Default = $SCANNER_ID"

echo "== Target =="
TARGET_ID="$(gmp '<get_targets/>' | pick_id target "$TARGET_NAME")"
if [ -z "$TARGET_ID" ]; then
  TARGET_ID="$(gmp "<create_target><name>${TARGET_NAME}</name><hosts>${TARGET_HOSTS}</hosts></create_target>" | attr_id)"
  echo "   created target '$TARGET_NAME' ($TARGET_HOSTS) = $TARGET_ID"
else
  echo "   reusing target '$TARGET_NAME' = $TARGET_ID"
fi

echo "== Task =="
TASK_ID="$(gmp '<get_tasks/>' | pick_id task "$TASK_NAME")"
if [ -z "$TASK_ID" ]; then
  TASK_ID="$(gmp "<create_task><name>${TASK_NAME}</name><config id=\"${CONFIG_ID}\"/><target id=\"${TARGET_ID}\"/><scanner id=\"${SCANNER_ID}\"/></create_task>" | attr_id)"
  echo "   created task '$TASK_NAME' = $TASK_ID"
else
  echo "   reusing task '$TASK_NAME' = $TASK_ID"
fi

echo "== Start =="
gmp "<start_task task_id=\"${TASK_ID}\"/>" | grep -o 'status="[0-9]*"[^>]*' | head -1
echo
echo "Scan launched. Watch it with:  sudo $DEPLOY_DIR/$(basename "$0") status"
echo "Or in the GSA web UI (Scans > Tasks) via an SSH tunnel to 127.0.0.1:9392."
