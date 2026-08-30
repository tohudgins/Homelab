# Threat-intelligence enrichment in Wazuh (CDB blocklist lookup)

Detection tells you *an alert fired*. Threat intelligence adds *and the peer is a known-bad actor*. This is
the Wazuh-native way to get that second half without a separate platform: a **CDB list** (Constant Database —
a compiled `key:value` lookup table) of malicious indicators, and rules that look up each alert's IP against
it and escalate a hit. It plugs straight into the existing NSM feed and ties the Phase 8 Sliver C2 finding to
a real reputation feed.

Manager: `siem-01` (Wazuh) · Feed source: [ipsum](https://github.com/stamparm/ipsum) · Integrated with the
Suricata NSM alerts from `rtr-01`.

> [!check] Built and verified live on 2026-08-29.
> `wazuh-logtest` against a Suricata alert whose peer is on the blocklist fires **rule 100210/100211 at
> level 12** with the matched IP in the message; the same alert with a benign IP (`8.8.8.8`) fires only the
> base Suricata rule (86601, level 3) — no false positive. Verified with both the lab C2 IP and a real
> feed IP (`77.90.185.20`).

---

## 1. The list

`roles/siem/files/lists/threat-intel-ips` — a pure `key:value` CDB list (`<ip>:<label>`), **735
high-confidence malicious IPs** plus the lab's own C2 server:

```
10.10.40.119:lab-sliver-c2-atk01
77.90.185.20:ipsum-malicious-6plus
193.47.62.69:ipsum-malicious-6plus
...
```

- **Source:** the ipsum aggregated blocklist, **level 6** — IPs appearing on **≥6 independent blocklists**
  (high confidence; level 3 has ~14k IPs, level 8 only ~26 — level 6's ~735 is the balance of coverage and
  precision).
- **Staged offline.** `siem-01` sits in the SOC segment with **no external egress**, so it can't pull a feed
  live. The snapshot is committed to the repo and deployed by Ansible — the same offline-staging pattern as
  the Atomic Red Team install. Refresh procedure is in `roles/siem/files/lists/README.md`.
- **The lab C2 IP (`10.10.40.119`, atk-01)** is included so the Phase 8 beacon traffic produces a
  threat-intel hit end to end — see `phase-5-offense/sliver-c2/`.

## 2. The wiring (all as code, `siem` role)

1. **Deploy** the list to `/var/ossec/etc/lists/threat-intel-ips` (the manager compiles `etc/lists/*` into
   `.cdb` at restart).
2. **Register** it in `ossec.conf` `<ruleset>`: `<list>etc/lists/threat-intel-ips</list>` (Wazuh even ships
   empty `malicious-ioc/*` list stubs there by default — this is the populated version).
3. **Rules** `100210`/`100211` (`roles/siem/files/local_rules.xml`), children of the Suricata alert rule
   **86601**, look up `dest_ip` / `src_ip` against the list and escalate to level 12:

```xml
<rule id="100210" level="12">
  <if_sid>86601</if_sid>
  <list field="dest_ip" lookup="address_match_key">etc/lists/threat-intel-ips</list>
  <description>Threat intel: NSM alert to a known-malicious destination IP (blocklist match) — $(dest_ip)</description>
</rule>
```

`lookup="address_match_key"` is CIDR-aware, so the list can hold networks as well as hosts.

## 3. Verified

```
# malicious dest (10.10.40.119, in list):
  id: 100210  level: 12  "Threat intel: NSM alert to a known-malicious destination IP ... 10.10.40.119"
# malicious src (77.90.185.20, a real ipsum IP):
  id: 100211  level: 12  "Threat intel: NSM alert from a known-malicious source IP ... 77.90.185.20"
# benign dest (8.8.8.8, not in list):
  id: 86601   level: 3   (base Suricata alert only — no escalation, no false positive)
```

So the Sliver C2 beacon — already caught behaviourally (Suricata rule 9100002) and by fingerprint (9100001)
— now *also* lights up as a **known-malicious-destination** hit the moment its traffic crosses the sensor:
detection and reputation in one alert.

## 4. What this exercise taught (the gotchas)

- **Suricata alerts decode to `src_ip` / `dest_ip`, not `srcip` / `dstip`.** Wazuh's standard decoders
  (sshd, firewall) populate `srcip`/`dstip`, but the Suricata **eve.json → `json` decoder** keeps Suricata's
  own key names. A `<list field="srcip">` rule silently never matches a Suricata alert. Confirm the real
  field name with `wazuh-logtest` (Phase 2 output) before writing the rule — don't assume.
- **CDB lists must be pure `key:value`.** A `#`-comment header is parsed as a bogus key, not skipped — keep
  provenance in a sibling `README`, not in the list file.
- **Verify the negative too.** A reputation rule that fires on *everything* is worse than none; the
  benign-IP test (no escalation) is as important as the malicious-IP test.
- **The feed is a snapshot, honestly.** An internal-only SIEM can't self-update its intel. In production this
  list would be refreshed on a schedule (or driven from MISP); here it's a documented point-in-time capture,
  which is the right trade for an air-gapped SOC segment but must be *stated*, not hidden.

## Reproduce

```bash
# rebuild the list from the live feed (on an internet-connected host), then redeploy the siem role
curl -s https://raw.githubusercontent.com/stamparm/ipsum/master/levels/6.txt \
  | grep -E '^[0-9.]+$' | sed 's/$/:ipsum-malicious-6plus/' > threat-intel-ips
sed -i '1i 10.10.40.119:lab-sliver-c2-atk01' threat-intel-ips   # keep the lab C2 entry

# verify a hit (on siem-01):
printf '%s\n' '{"event_type":"alert","src_ip":"10.10.10.20","dest_ip":"10.10.40.119","dest_port":443,"proto":"TCP","alert":{"signature_id":9100001,"signature":"x","category":"A Network Trojan was detected","severity":1}}' \
  | sudo /var/ossec/bin/wazuh-logtest
```
