# MISP → Wazuh integration — the TIP as the live IOC engine behind the SIEM

The static Wazuh CDB list (`threat-intel-cdb-enrichment.md`) proved the *concept* of reputation enrichment,
but a flat blocklist isn't what a SOC runs. This is the professional version: **MISP**, a real
Threat Intelligence Platform correlating 43k+ IOCs from live feeds, wired to Wazuh so **every alert is checked
against MISP in real time**. It supersedes the CDB rules (100210/100211) with a platform that can correlate,
share, expire, and warninglist indicators.

Manager: `siem-01` (Wazuh) · TIP: `misp-01` (`10.10.30.20`, SOC) · both intra-SOC, no routing.

> [!check] Built and verified live on 2026-08-30 — three ways (positive manual, positive automatic, negative).

## How it works
Wazuh's **`integratord`** is the hook: it runs an external script on every alert matching a filter. The
`custom-misp` integration (`roles/siem/files/custom-misp{,.py}`, deployed to `/var/ossec/integrations/`):

1. **Triggers** on every alert `level >= 3` (`<integration>` in `ossec.conf`). Cheap: the script
   **self-filters** — it only calls MISP for alerts that actually carry an indicator.
2. **Extracts IOCs** from the alert: IPs (Suricata `data.src_ip`/`dest_ip`, stock decoders' `srcip`/`dstip`)
   and file hashes (FIM `syscheck.*_after`, Sysmon `hashes`).
3. **Queries MISP** — `POST /attributes/restSearch` (`enforceWarninglist: true`, so MISP's known-good lists
   suppress false positives at the source).
4. **On a hit, injects** `1:misp:{"integration": "misp", "misp": {...}}` into analysisd via the queue socket
   (`/var/ossec/queue/sockets/queue`), carrying the IOC, its MISP category, and the alert that triggered it.

```
alert (level>=3) ──▶ integratord ──▶ custom-misp.py ──▶ MISP /attributes/restSearch
                                                              │  (hit)
   rule 100301  ◀── analysisd ◀── queue socket ◀── inject ───┘
   "MISP: known IoC <ip> matched … triggered by rule <n>"  (level 12)
```

## Rules (`local_rules.xml`, group `misp,threat_intel`)
The injected event is valid JSON, so Wazuh's **built-in `json` decoder** flattens it (`integration`,
`misp.value`, `misp.source.*`). The rules key on that:
- **100300** — `decoded_as json` + `integration=misp` → base "MISP integration event".
- **100301** — child, `misp.value` present → **level 12** "known IoC matched", with the value, category, and
  the source rule that triggered it.
- **100302** — `misp.error` present → level 5 integration error (so a MISP outage is visible, not silent).

## Verified (three ways — positive *and* negative)
1. **Manual** (exactly what integratord runs): `custom-misp <alert.json> <key> <url>` with an alert whose
   `dest_ip` is a real MISP IOC (`218.106.246.195`) → **rule 100301, level 12** in `alerts.json`.
2. **Automatic** (integratord end-to-end): a real sshd-failure alert from that IP (rule 5760) → integratord
   auto-ran the script → MISP hit → **100301 with `misp.source.rule = 5760`**. The integration fires on live
   alerts, unattended.
3. **Negative**: an sshd failure from `8.8.8.8` (not in MISP) fired the base alert but produced **zero**
   100301 — no false positive, verified, not assumed.

## Gotchas (found by exercising)
- **Don't use a custom `decoded_as` for the injected event.** The injected line is JSON, so Wazuh's built-in
  `json` decoder claims it and flattens the fields. A custom `<decoded_as>misp</decoded_as>` rule silently
  never matches (the json decoder already won). Key on `decoded_as json` + the `integration` field instead.
- **`requests` lives in system python3, not the Wazuh-bundled one.** The `custom-misp` wrapper prefers the
  bundled interpreter only if it can `import requests`, else falls back to `/usr/bin/env python3`.
- **`enforceWarninglist: true`** on the MISP query pushes false-positive suppression to MISP (RFC1918,
  CDN/cloud ranges, etc.) — better than filtering in the script.

## CDB list vs MISP — why keep both
| | CDB list (100210/211) | MISP integration (100301) |
|---|---|---|
| Source | flat file, staged offline | live platform, feeds + API, 43k+ IOCs |
| Match | in-pipeline, per-alert field | post-alert lookup, any IOC type |
| Ops | edit + redeploy the file | correlate/expire/warninglist/share in MISP |
| Role | fast, air-gapped fallback | the real IOC source of truth |

Both stay: the CDB list is a fast, no-dependency fallback if MISP is down; MISP is the engine. Platform build:
`phase-7-automation/provisioning/misp-01/`.
