# Wazuh CDB threat-intel lists

CDB (Constant Database) lists are `key:value` lookup tables the Wazuh manager
compiles and rules query with `<list ... lookup="...">`. Registered in
`ossec.conf` `<ruleset>` and deployed by the `siem` role to `/var/ossec/etc/lists/`.

## `threat-intel-ips`
Known-malicious IPs. Rules **100210** (srcip) / **100211** (dstip) look up every
alert's IP against it with `lookup="address_match_key"` (CIDR-aware) and raise a
level-12 threat-intel match.

- **Source:** [ipsum](https://github.com/stamparm/ipsum) aggregated blocklist,
  **level 6** — IPs appearing on ≥6 independent blocklists (high confidence).
- **Staged offline:** siem-01 is internal-only (SOC segment, no external egress),
  so the feed is a point-in-time snapshot committed here, not fetched live —
  same offline-staging pattern as the Atomic Red Team install.
- **Refresh:** `curl -s https://raw.githubusercontent.com/stamparm/ipsum/master/levels/6.txt | grep -E '^[0-9.]+$' | sed 's/$/:ipsum-malicious-6plus/'`
  then re-prepend the lab C2 line and redeploy the `siem` role.
- **Lab entry:** `10.10.40.119` (atk-01, the Sliver C2 server) is added so the
  Phase 8 C2 traffic produces a threat-intel match end-to-end — see
  `phase-5-offense/sliver-c2/`.
