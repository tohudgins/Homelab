# Attack / Detect: web attack on the DMZ app → T1190, and the blind spot that let it in

**Phase 5 — Offense in context.** A paired attacker/defender walkthrough of a **web application attack**
against the DMZ's OWASP Juice Shop (`dmz-01`, `10.10.20.10:3000`), executed from `atk-01` (Kali, REDTEAM),
and the detection built to catch it. This closes the one hole left in the lab: **every host had a verified
attack→detect story except the DMZ** — Juice Shop was running and its container logs were ingested into
Wazuh, but nothing on the wire or in the SIEM actually fired on a web attack. T1190 (Exploit Public-Facing
Application) was uncovered.

Domain: DMZ segment `10.10.20.0/24` · Target: `dmz-01` (Juice Shop, Docker) · Attacker: `atk-01` (REDTEAM) ·
Sensor: `rtr-01` (inline Suricata) · SIEM: `siem-01` (Wazuh manager).

> [!check] Live-fired end-to-end on 2026-09-07 — 100440 fires clean, correctly labeled T1190.
> Two real bugs found and fixed along the way: Suricata's PCRE matched the raw URL-encoded request
> instead of the decoded one (fixed with a `url_decode` transform on rules 20–23), and Wazuh silently
> lost the alert to a rule-precedence collision with the threat-intel CDB hit 100211 (fixed by raising
> 100440/100441 to level 13). Full verification in §5.

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

## 5. Verification — run live 2026-09-07, two real bugs found and fixed

```bash
make up PROFILE=soc; make up PROFILE=attack; make up PROFILE=services   # 7 of 8 VMs
ssh atk-01 'curl -sk "http://10.10.20.10:3000/rest/products/search?q=test%27%20OR%201=1--"'
ssh rtr-01-root "grep 'LAB WEB ATTACK' /var/log/suricata/fast.log | tail"   # note: sudo isn't installed on
                                                                            # rtr-01, use the root SSH alias
ssh siem-01 "sudo grep -E '100440|100441' /var/ossec/logs/alerts/alerts.json | tail"
```

`alert.signature` was never the problem — confirmed correct via the interpolated `$(alert.signature)` text in
live 86601 alerts. Two *other* bugs were:

1. **Suricata matched the raw, URL-encoded request.** The PCREs assumed a decoded buffer (`' OR 1=1`), but
   `%27%20OR%201=1--` never satisfies `\bor\b\s+1` — no literal space/quote, and no word boundary between the
   "0" of `%20` and "OR". Confirmed by pulling the exact eve.json `http.url` field and testing the regex
   against it directly. Fixed with a `url_decode` transform on every URI/body-based rule (20/21/22/23) — took
   two iterations to get right: the keyword is `url_decode` (underscore), not `urldecode` (confirmed via
   `suricata --list-keywords=all`, since a guessed keyword just silently drops the rule with "unknown rule
   keyword" — caught in `suricata.log`, not in any alert output, so *check the engine's own startup log after
   any rule change*, not just whether traffic produces alerts); and rule 20's embedded literal `;` inside the
   PCRE broke Suricata's option parser once combined with the transform keyword — worked around with the
   PCRE hex-escape `\x3b` instead of a literal semicolon.
2. **Wazuh silently lost the alert to a different rule.** Even with Suricata firing correctly, no SIEM alert
   appeared. `wazuh-logtest` fed the exact eve.json line and returned rule **100211** ("known-malicious source
   IP", L12) instead of **100440** (T1190, was L10) — atk-01's own IP is in the threat-intel CDB from unrelated
   exercises, so both rules matched the same event and Wazuh's one-rule-per-event precedence (highest level
   among matching `if_sid=86601` siblings) picked the wrong one every time. Fixed by raising 100440/100441 to
   L13. Same shape as Sigma rules needing to clear the stock discovery band — just a different competing rule.

**Result: 100440 fires clean and correctly labeled T1190**, confirmed via `ad-validate.py`'s DMZ Web Attack
scenario (added the same night) and by hand, twice.

---

## 6. Notes & follow-ups

- **Host-side complement (optional):** the `dmz` role already ingests the Juice Shop container logs. If
  Juice Shop is confirmed to log request lines to stdout, a Wazuh decoder + rules on `data.log` would add a
  host-side detection independent of the network path. Left as a documented next step rather than shipping a
  decoder against an unverified log format.
- **Coverage:** T1190 is verified TP live (2026-09-07) and wired into `ad-validate.py`'s SCENARIOS as the
  "DMZ Web Attack" entry, so it counts toward "validated" once `generate-coverage.py` is next regenerated
  (deliberately not done mid-session — see the honesty note in `purple-team/README.md`'s Extending section).
- **The `HTTP_PORTS` fix is the reusable lesson:** any app on a non-standard port silently falls outside a
  signature IDS's HTTP inspection unless you tell the sensor the port is HTTP. Worth auditing for every
  service the lab adds.
