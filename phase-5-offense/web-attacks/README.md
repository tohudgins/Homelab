# Web attacks — DMZ / OWASP Juice Shop (T1190)

Offensive exercise that drives the **DMZ web-attack detection** (T1190 Exploit Public-Facing Application)
end to end, from `atk-01` (Kali, REDTEAM) against Juice Shop on `dmz-01` (`10.10.20.10:3000`).

- **`web-attack-scan.sh`** — fires a deterministic battery (one guaranteed request per Suricata signature)
  plus optional `sqlmap`/`nikto` for a realistic burst. Run it from atk-01.

## The detection it exercises

```
atk-01 (REDTEAM)  --HTTP-->  dmz-01 Juice Shop :3000
      |  (crosses rtr-01, where the inline sensor sees it)
      v
rtr-01 Suricata  custom sigs 9100020-9100024   (roles/router/files/suricata-local.rules)
      |  eve.json
      v
siem-01 Wazuh    86601 -> 100440 (SQLi/XSS/traversal, T1190)
                       -> 100441 (scanner UA, T1595.002)
                       -> 100442 (burst correlation, T1190, L12)
```

**Key finding:** ET Open's web-attack rules match on `$HTTP_PORTS` (default 80) and so were structurally
blind to Juice Shop on port 3000. The `router` role now adds 3000 to `HTTP_PORTS`, and the lab's own sigs
are scoped directly to `10.10.20.10:3000`.

Full writeup: [`../attack-detect-writeups/03-web-attack-juiceshop-t1190.md`](../attack-detect-writeups/03-web-attack-juiceshop-t1190.md).

> Status: detection-as-code built 2026-09-06; live verification pending (see the writeup's §5).
