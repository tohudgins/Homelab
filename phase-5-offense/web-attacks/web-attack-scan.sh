#!/usr/bin/env bash
# ===========================================================================
# web-attack-scan.sh — exercise the DMZ web-attack detection (T1190) from atk-01.
#
# Fires web attacks at OWASP Juice Shop (dmz-01, DMZ 10.10.20.10:3000) so the
# detections light up end to end:
#   rtr-01 inline Suricata (custom sigs 9100020-9100024)  ->  eve.json
#     ->  Wazuh (stock rule 86601)  ->  lab rules 100440/100441/100442 (T1190)
#
# Run it from atk-01 (Kali, REDTEAM). The traffic crosses rtr-01 (REDTEAM->DMZ),
# which is exactly where the inline sensor sees it:
#   ssh atk-01 'bash /path/web-attack-scan.sh'
#
# The DETERMINISTIC battery below sends one request per signature (guaranteed
# match — the point is provable, per-rule verification, same discipline as
# purple-team.py). sqlmap/nikto then add a realistic burst that also trips the
# 100442 correlation rule (>=8 web-attack sigs / 60s from one source).
#
# This is deliberately loud, obvious attack traffic against a lab target only.
# ===========================================================================
set -uo pipefail

TARGET="${TARGET:-http://10.10.20.10:3000}"
CURL=(curl -sk --max-time 10 -o /dev/null -w '  -> HTTP %{http_code}\n')

hr(){ printf '\n=== %s ===\n' "$1"; }

hr "Target: $TARGET (run from atk-01 / REDTEAM)"
if ! curl -sk --max-time 8 -o /dev/null "$TARGET/"; then
  echo "WARNING: $TARGET not reachable — is dmz-01 up and Juice Shop running?"
fi

# --- Deterministic battery: one guaranteed hit per Suricata signature ---------

hr "1) SQLi in URI  -> Suricata 9100020 / Wazuh 100440 (T1190)"
"${CURL[@]}" "$TARGET/rest/products/search?q=test%27%20OR%201=1--"
"${CURL[@]}" "$TARGET/rest/products/search?q=1'))%20UNION%20SELECT%20*%20FROM%20information_schema.tables--"

hr "2) SQLi in POST body (login bypass)  -> Suricata 9100021 / Wazuh 100440 (T1190)"
"${CURL[@]}" -X POST "$TARGET/rest/user/login" \
  -H 'Content-Type: application/json' \
  --data '{"email":"'"'"' OR 1=1--","password":"x"}'

hr "3) Reflected XSS in URI  -> Suricata 9100022 / Wazuh 100440 (T1190)"
"${CURL[@]}" "$TARGET/rest/products/search?q=<script>alert(1)</script>"

hr "4) Path traversal / LFI  -> Suricata 9100023 / Wazuh 100440 (T1190)"
"${CURL[@]}" "$TARGET/rest/products/../../../../etc/passwd"
"${CURL[@]}" "$TARGET/ftp/%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd"

hr "5) Automated-scanner User-Agent  -> Suricata 9100024 / Wazuh 100441 (T1595.002)"
"${CURL[@]}" -A "sqlmap/1.8#stable (https://sqlmap.org)" "$TARGET/rest/products/search?q=1"
"${CURL[@]}" -A "Mozilla/5.00 (Nikto/2.5.0)" "$TARGET/"

# --- Optional realistic tools: also trips the 100442 burst-correlation rule ----

hr "6) Realistic tooling (optional — trips the 100442 burst rule >=8 sigs/60s)"
if command -v sqlmap >/dev/null 2>&1; then
  echo "[*] sqlmap against the product-search parameter (batch, non-interactive)..."
  sqlmap -u "$TARGET/rest/products/search?q=1" --batch --level=2 --risk=2 \
         --flush-session --technique=BU --smart 2>/dev/null | tail -5 || true
else
  echo "[-] sqlmap not installed — skipping (apt install sqlmap on Kali)"
fi
if command -v nikto >/dev/null 2>&1; then
  echo "[*] nikto quick scan (Tuning 9 = SQLi/XSS/injection)..."
  nikto -host "$TARGET" -Tuning 9 -maxtime 60s 2>/dev/null | tail -8 || true
else
  echo "[-] nikto not installed — skipping (apt install nikto on Kali)"
fi

hr "Done. Verify on siem-01:"
cat <<'VERIFY'
  # Suricata saw it (on rtr-01):
  ssh rtr-01 "sudo grep 'LAB WEB ATTACK' /var/log/suricata/fast.log | tail"

  # Wazuh labeled it T1190 (on siem-01):
  ssh siem-01 "sudo grep -E '100440|100441|100442' /var/ossec/logs/alerts/alerts.log | tail"
VERIFY
