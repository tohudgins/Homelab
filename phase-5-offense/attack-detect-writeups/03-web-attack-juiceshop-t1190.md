# Attack / Detect: web attack on the DMZ app → T1190, and the blind spot that let it in

**Phase 5 — Offense in context.** A paired attacker/defender walkthrough of a **web application attack**
against the DMZ's OWASP Juice Shop (`dmz-01`, `10.10.20.10:3000`), executed from `atk-01` (Kali, REDTEAM),
and the detection built to catch it. This closes the one hole left in the lab: **every host had a verified
attack→detect story except the DMZ** — Juice Shop was running and its container logs were ingested into
Wazuh, but nothing on the wire or in the SIEM actually fired on a web attack. T1190 (Exploit Public-Facing
Application) was uncovered.

Domain: DMZ segment `10.10.20.0/24` · Target: `dmz-01` (Juice Shop, Docker) · Attacker: `atk-01` (REDTEAM) ·
Sensor: `rtr-01` (inline Suricata) · SIEM: `siem-01` (Wazuh manager).

> [!warning] Built 2026-09-06 as detection-as-code — live fire pending.
> Rules, the `HTTP_PORTS` fix, and the exercise harness are written and deployed via Ansible, but the lab
> was powered off this session so this has **not yet been fired end-to-end**. The exact verification commands
> are in §5; run `web-attacks/web-attack-scan.sh` from atk-01 with the lab up to confirm and flip this note.

---

## 1. The blind spot (why this is a real finding, not a formality)

The DMZ exists to host a deliberately vulnerable, internet-facing-style app. But two things meant a web
attack against it was **invisible**:

1. **Suricata was blind to port 3000.** ET Open's entire web-attack ruleset matches on the `$HTTP_PORTS`
   variable, which defaults to `80` (+443/8080). Juice Shop runs on **3000**, so out of the box *not one* ET
   web signature would ever evaluate against it — the ruleset was loaded but structurally could not fire on
   the DMZ app.
2. **The ingested logs fed nothing.** The `dmz` role tails the Juice Shop container logs into Wazuh "so DMZ
   web attacks are actually visible" — but there were no rules keyed on them, so the telemetry flowed into a
   void.

This is the kind of gap that looks fine on a diagram (sensor ✓, log ingestion ✓) and is silent in practice —
the same class as the SCA policy that self-skipped and the `log.smbd` source that was never read.

---

## 2. Detection design

Two layers, network-primary because it doesn't depend on what the app chooses to log:

**(a) `rtr-01` inline Suricata — custom sigs `9100020–9100024`** (`roles/router/files/suricata-local.rules`),
scoped by destination to `10.10.20.10:3000` (so atk-01's DHCP REDTEAM address is irrelevant):

| sid | Attack | Match | ATT&CK |
|---|---|---|---|
| 9100020 | SQLi in URI | `union select` / `or 1=1` / `information_schema` / `sleep(` in `http.uri` | T1190 |
| 9100021 | SQLi in POST body | tautology/UNION in `http.request_body` (Juice Shop login bypass) | T1190 |
| 9100022 | Reflected XSS | `<script` / `onerror=` / `javascript:` in `http.uri` | T1190 |
| 9100023 | Path traversal / LFI | `../` / `%2e%2e%2f` / `/etc/passwd` in `http.uri` | T1190 |
| 9100024 | Scanner User-Agent | `sqlmap`/`nikto`/`gobuster`/`nuclei`… in `http.user_agent` | T1595.002 |

Suricata parses HTTP on 3000 via protocol detection (intra-segment traffic is plain HTTP), so the `http.*`
sticky buffers work. The router role **also adds 3000 to `HTTP_PORTS`**, which fixes blind spot #1 for the
*entire* ET web ruleset — so the custom sigs are the labeled, MITRE-mapped complement on top of restored ET
breadth, not a replacement for it.

**(b) `siem-01` Wazuh — labeled T1190 alerts** (`roles/siem/files/local_rules.xml`). Suricata's `eve.json`
already feeds Wazuh (surfacing as stock rule `86601`); these children turn a generic NSM hit into a labeled
SIEM detection:

- **`100440`** (level 10, T1190) — a SQLi/XSS/traversal signature fired against the DMZ app.
- **`100441`** (level 8, T1595.002) — automated-scanner User-Agent (the "a tool is running" tell).
- **`100442`** (level 12, T1190) — **correlation**: ≥8 web-attack sigs from one `src_ip` in 60s = an active
  exploitation run (sqlmap/nikto), not a stray probe.

---

## 3. Attack — executed from atk-01

`web-attacks/web-attack-scan.sh` fires a deterministic battery (one guaranteed request per signature — the
same per-rule provability discipline as `purple-team.py`), then optional `sqlmap`/`nikto` for a realistic
burst that also trips `100442`:

```
$ bash web-attack-scan.sh
=== 1) SQLi in URI  -> Suricata 9100020 / Wazuh 100440 (T1190) ===
  GET /rest/products/search?q=test' OR 1=1--            -> HTTP 500
  GET /rest/products/search?q=1')) UNION SELECT ...     -> HTTP 500
=== 2) SQLi in POST body (login bypass) -> 9100021 / 100440 ===
  POST /rest/user/login  {"email":"' OR 1=1--", ...}    -> HTTP 200   (auth bypass!)
=== 3) Reflected XSS in URI -> 9100022 / 100440 ===
=== 4) Path traversal / LFI -> 9100023 / 100440 ===
=== 5) Automated-scanner User-Agent -> 9100024 / 100441 ===
=== 6) Realistic tooling (sqlmap/nikto) -> trips 100442 burst rule ===
```

(Output above is the intended shape; fill with the real run when the lab is up.)

---

## 4. Why realistic, not contrived

Juice Shop's sinks are real, documented vulnerabilities: the product-search endpoint is genuinely SQL-
injectable, and `POST /rest/user/login` with `' OR 1=1--` is its canonical authentication-bypass challenge.
An external-facing web app being probed by an automated scanner from an untrusted segment is the single most
common real-world initial-access vector (T1190) — which is exactly why leaving the DMZ undetected was the
lab's most important gap.

---

## 5. Verification (run when the lab is up)

```bash
# bring up the segments this needs: networking (rtr-01) + services (dmz-01) + soc (siem-01) + attack (atk-01)
make up PROFILE=services      # + networking + soc + attack per your profiles

# fire the attacks from the attacker box
ssh atk-01 'bash /path/to/web-attack-scan.sh'

# (1) Suricata saw it on the wire (rtr-01):
ssh rtr-01 "sudo grep 'LAB WEB ATTACK' /var/log/suricata/fast.log | tail"

# (2) Wazuh labeled it T1190 (siem-01):
ssh siem-01 "sudo grep -E '100440|100441|100442' /var/ossec/logs/alerts/alerts.log | tail"

# (2b) confirm the decoded Suricata signature field name matches the rule:
ssh siem-01 "echo '<paste an eve.json alert line>' | sudo /var/ossec/bin/wazuh-logtest"
```

**One thing to confirm on first fire:** the Wazuh rules key on `alert.signature` (Wazuh's decoded Suricata
signature text). If `wazuh-logtest` shows a different decoded key for the signature in this Wazuh version,
it's a one-line change in the three rules — flagged here rather than assumed.

---

## 6. Notes & follow-ups

- **Host-side complement (optional):** the `dmz` role already ingests the Juice Shop container logs. If
  Juice Shop is confirmed to log request lines to stdout, a Wazuh decoder + rules on `data.log` would add a
  host-side detection independent of the network path. Left as a documented next step rather than shipping a
  decoder against an unverified log format.
- **Coverage:** adds T1190 (Initial Access) and T1595.002 (Reconnaissance) to the map → **44 techniques**
  (`generate-coverage.py`, regenerated). Both score "detection exists"; they move to "validated" once the
  exercise is run and (optionally) wired into the purple-team battery.
- **The `HTTP_PORTS` fix is the reusable lesson:** any app on a non-standard port silently falls outside a
  signature IDS's HTTP inspection unless you tell the sensor the port is HTTP. Worth auditing for every
  service the lab adds.
