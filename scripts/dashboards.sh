#!/usr/bin/env bash
# ===========================================================================
# dashboards.sh — one command to reach every lab web UI that needs a tunnel.
#
# The lab's segmented network (docs/00-ip-plan.md) routes admin access through
# rtr-01 as a jump host by design (same ProxyJump path as SSH) — this doesn't
# bypass that, it just stops you from having to hand-type a `ssh -L ...`
# per tool per session. Five UIs live behind three hosts:
#
#   siem-01  -> Wazuh dashboard   https://localhost:9001  (remote :443)
#   siem-01  -> Velociraptor GUI  https://localhost:8889  (remote :8889)
#   misp-01  -> MISP              https://localhost:9002  (remote :443)
#   misp-01  -> DFIR-IRIS         https://localhost:8443  (remote :8443)
#   scan-01  -> Greenbone/OpenVAS https://localhost:9392  (remote :443 — nginx's
#                own :9392 is a plain-HTTP redirect-to-:443 compat port, not a
#                second TLS listener; see phase-7-automation/ansible/roles/scan
#                /defaults/main.yml for how that was root-caused)
#
# BloodHound CE is deliberately NOT here: it runs locally via `docker compose`
# (phase-5-offense/bloodhound-ce/), already at http://localhost:8080 with no
# tunnel needed at all.
#
# Credentials for all of these: vault Virtual Machines note.
#
#   ./scripts/dashboards.sh          # open every tunnel, print the URLs, block
#   Ctrl+C closes every tunnel this script opened.
# ===========================================================================
set -euo pipefail

PIDS=()
cleanup() { echo; echo "Closing tunnels..."; kill "${PIDS[@]}" 2>/dev/null || true; }
trap cleanup EXIT INT TERM

open_tunnel() {
  local host="$1"; shift
  ssh -N "$@" "$host" &
  PIDS+=("$!")
}

echo "Opening tunnels (through rtr-01, same as SSH)..."
open_tunnel siem-01 -L 9001:127.0.0.1:443 -L 8889:127.0.0.1:8889
open_tunnel misp-01 -L 9002:127.0.0.1:443 -L 8443:127.0.0.1:8443
open_tunnel scan-01 -L 9392:127.0.0.1:443

sleep 1
cat <<'EOF'

  Wazuh dashboard   https://localhost:9001
  Velociraptor GUI  https://localhost:8889
  MISP              https://localhost:9002
  DFIR-IRIS         https://localhost:8443
  Greenbone/OpenVAS https://localhost:9392
  BloodHound CE     http://localhost:8080   (local docker compose, no tunnel — see phase-5-offense/bloodhound-ce/)

All tunnels open. Ctrl+C to close.
EOF
wait
