# SOC operations — DFIR-IRIS case management + Wazuh → IRIS

**The analyst-workflow layer.** A SIEM tells you *something fired*; it doesn't give you a place to **work the
incident** — triage, assign, timeline, collect evidence, link intel, write it up. That's case management, and
it's what a real SOC/DFIR analyst lives in. This adds it with **DFIR-IRIS** and wires Wazuh into it, so a
high-severity detection becomes a triageable case automatically.

Platform host: `misp-01` (SOC segment, `10.10.30.20`) · SIEM: `siem-01` · Attacker: `atk-01`.

> [!check] Built + verified live end-to-end on 2026-09-02.
> A live Wazuh detection (rule 100011, level 12) was **auto-forwarded by integratord** into IRIS as a
> Critical alert with zero manual steps — the SOC-ops pipeline works.

---

## 1. Why IRIS, not TheHive + Cortex

TheHive + Cortex is the "default" open-source SOAR/case stack, and the original plan. De-risking killed it for
*this* host, honestly:

- **Architecture:** `strangebee/thehive` and `cortexneurons/cortex` ship **single-arch amd64-only** images.
  On this all-ARM64 lab they'd run under **qemu emulation**.
- **Weight:** the stack is **four JVMs** (TheHive + Cassandra + Elasticsearch + Cortex). Emulated, on a 24 GB
  host already running Wazuh + MISP, that's slow and OOM-prone — it would teach frustration, not SOC skills.

**DFIR-IRIS** delivers the same capability (alerts → cases, triage, IR timeline, evidence, intel linking) and
is **arm64-native** — verified in ghcr for all three images (`iriswebapp_app` / `_db` / `_nginx`) — with a far
lighter footprint (Python app + Postgres + nginx + rabbitmq, no JVM sprawl). It runs comfortably *alongside*
MISP on the SOC Docker host. Picking the tool that fits the constraint, and documenting why, is the point.

## 2. Deployment (IaC: the `iris` role)

Deployed on misp-01 from the official `iris-web` repo, pinned to **v2.4.20**, codified as
`phase-7-automation/ansible/roles/iris/` (mirrors the `misp` role): clone → seed `.env` → set port/tags/
secrets → `docker compose up` → wait for the UI. One deliberate config point:

- **Port 8443, not 443** — MISP already binds 443 on this host, so IRIS's nginx listens on 8443
  (`INTERFACE_HTTPS_PORT=8443`). Two SOC platforms, one host, no collision.

UI: `https://10.10.30.20:8443` (self-signed). Verified: all five containers up, `/login` → 200, and IRIS
auto-registered its **MISP module** and **webhooks module** on first boot.

## 3. Wazuh → IRIS integration (`custom-iris`)

Same pattern as the MISP integration: Wazuh **integratord** runs `custom-iris` (siem role) on every alert
**level ≥ 10**; the script POSTs to the IRIS REST API (`/alerts/add`) to create an IRIS alert.

- **Severity mapping** (IRIS ids are not ordinal): Wazuh 12+ → **Critical (6)**, 9–11 → High (5),
  6–8 → Medium (1), else Low (4).
- **What rides along:** the full raw Wazuh alert in `alert_source_content` (the analyst gets everything),
  MITRE technique ids + rule id + agent + involved IPs as **tags**, `alert_source_ref` = the Wazuh alert id
  (so IRIS can dedup), status **New**.
- **level ≥ 10** keeps IRIS focused on real incidents (the level-12 custom attack rules), not SIEM noise.

Config: `roles/siem/` — `custom-iris` + `custom-iris.py` deployed to `/var/ossec/integrations/`, and an
`<integration>` block (`hook_url` = `https://10.10.30.20:8443`, `api_key` = an IRIS admin key, `level` 10).

## 4. Verified end-to-end

| Path | Result |
|---|---|
| Manual (script on a real 100401 spray alert) | IRIS alert **#2** "[Wazuh] Password spray suspected…" — **Critical** |
| **Automatic (integratord, live)** | rule **100011** (sshd brute, level 12) → IRIS alert **#3** "[Wazuh] sshd: brute force…" — **Critical**, no manual step |

The automatic path is the real proof: a detection fired, integratord forwarded it, and it landed in the IRIS
alert queue ready to triage into a case — the SOC-ops loop, closed.

## 5. Honest finding — the active-response blocked my own path

Generating the live brute-force test *also* tripped the lab's **SSH brute-force active-response** (rule
100011 → `firewall-drop`), which added `iptables DROP` rules for the source IP as seen by siem-01 — which,
because the test came through the SSH jump host, was **`10.10.30.1` (rtr-01's gateway)**. That silently cut
siem-01 off from everything arriving via rtr-01, including my own admin session.

- **This is exactly the AR-as-DoS risk the detection catalog already flagged** — realized in practice: an
  attacker (or an operator) who trips the AR against a shared/gateway IP can blackhole legitimate traffic.
- **Recovery** used the segmentation itself: `misp-01` (same SOC segment, a *different* unblocked source IP)
  could still reach siem-01, so I jumped `-J misp-01` onto siem-01 and removed the two DROP rules.
- **Fixed (2026-09-03):** on inspection the block was *not* unbounded — the `firewall-drop` AR already carries
  `<timeout>600</timeout>` (rules_id 100010,100011), so any block self-heals in 10 minutes. The real gap was the
  allow-list: only loopback sat in the AR `<global>` `<white_list>`, so the segment gateways / jump host could
  still be blackholed for those 10 minutes. Added the four segment-gateway IPs (`10.10.10.1` CORP / `10.10.20.1`
  DMZ / `10.10.30.1` SOC-jump / `10.10.40.1` REDTEAM, all = rtr-01) to the whitelist and codified it in the
  `siem` role (`ansible-playbook siem.yml` converges `changed=0`). **Verified:** re-running the same brute-force
  through the jump still fires rule 100011 (L12) but adds **no** `iptables DROP` for `10.10.30.1`
  (`wazuh-analysisd: INFO: White listing IP: '10.10.30.1'`), and the admin path stays up. A whitelisted source
  is filtered at analysisd *before* the AR is dispatched, so `active-responses.log` shows no firewall-drop this
  time — the exact opposite of the original incident.

## Reproduce
```bash
# deploy IRIS (from the ansible dir):        ansible-playbook iris.yml
# the Wazuh->IRIS integration ships with:    ansible-playbook siem.yml
# prove it (any level>=10 detection works), then:
ssh siem-01 "sudo grep -a 'custom-iris' /var/ossec/logs/ossec.log"   # integratord ran it
curl -sk https://10.10.30.20:8443/alerts/filter -H 'Authorization: Bearer <iris_api_key>'  # alert landed
```
- IRIS UI: `https://10.10.30.20:8443` — `administrator` / (see the private VM inventory note).

## 6. The analyst workflow, demonstrated (2026-09-03)
Closed the loop the way an analyst would, all via the IRIS API against real data:
1. **Escalated** the spray alert (#2) into **Case #2** — the full Wazuh context carried into the case.
2. **Investigated:** added the attacker IP (`10.10.40.119`) and the compromised account (`svc-sql`) as
   **IOCs**, and a **timeline** event for the detection.
3. **Responded:** added a remediation **task** ("rotate svc-sql + all svc-* passwords; audit Kerberoastable
   SPN accounts").
4. **Enriched with intel:** cross-referenced the indicators against **MISP** — `10.10.40.119` → **0 matches**
   (internal origin, no known-bad-infra overlap), with the enrichment path verified live against a real feed
   C2 IP (`218.106.246.195` → MISP event 5, "C2 IP"). Verdict recorded on the case timeline.

That is the whole point of the layer: **Wazuh detects → integratord opens an IRIS alert → the analyst
escalates to a case, builds the timeline and tasks, and enriches with MISP intel** — three professional tools
working as one SOC.
