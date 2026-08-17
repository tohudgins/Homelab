# IP Plan & Naming Convention

## Naming convention

- **Hostnames:** `<role>-<sequence>`, lowercase — `rtr-01`, `dc-01`, `ws-01`, `fs-01`, `siem-01`, `dmz-01`, `atk-01`, `scan-01`.
- **AD domain:** `lab.internal` (never `.local` — collides with Bonjour/mDNS on macOS).
- **Domain membership:** `dc-01`, `ws-01`, and `fs-01` join the domain. `rtr-01`, `siem-01`, `dmz-01`, `atk-01`, and `scan-01` deliberately stay outside it — the SOC segment shouldn't be reachable via the identity plane it exists to monitor, and the router/attacker/scanner boxes have no reason to trust the domain either.
- **FQDNs:** domain members resolve as `<hostname>.lab.internal` via dc-01's DNS; everything else resolves via rtr-01's `dnsmasq`.
- **Snapshots:** `<vm>-phase<N>-<short-description>`, e.g. `rtr-01-phase1-nftables-baseline`.

## Segments & addressing

| Segment | vmnet | Subnet | Gateway | DHCP owner |
|---|---|---|---|---|
| WAN uplink | vmnet8 (NAT) | Fusion-assigned | — | Fusion |
| CORP | vmnet3 | `10.10.10.0/24` | `10.10.10.1` (rtr-01) | dc-01 |
| SOC / MGMT | vmnet5 | `10.10.30.0/24` | `10.10.30.1` (rtr-01) | rtr-01 |
| DMZ *(optional)* | vmnet4 | `10.10.20.0/24` | `10.10.20.1` (rtr-01) | rtr-01 |
| REDTEAM *(on-demand)* | vmnet6 | `10.10.40.0/24` | `10.10.40.1` (rtr-01) | rtr-01 |

> [!WARNING]
> On every internal vmnet, uncheck **"Provide addresses via DHCP"** in Fusion → Settings → Network. Fusion's own DHCP fighting the router/DC for address assignment is the #1 thing that breaks this kind of lab.

## Host assignments

| Host | Segment | IP | Role |
|---|---|---|---|
| rtr-01 | all internal segments (gateway) + WAN | `.1` on each internal segment | Firewall, DHCP/DNS/NTP, inline Suricata + Zeek |
| dc-01 | CORP | `10.10.10.10` | AD DS, DNS, GPO, PDC time source (Samba AD DC on Ubuntu ARM64 — see `design-decisions.md`) |
| ws-01 | CORP | `10.10.10.50` (DHCP reservation) | Domain-joined victim workstation |
| fs-01 | CORP | `10.10.10.20` | Samba file server, domain member (not a DC) — deliberately weak share/ACL config to give BloodHound a real lateral-movement path |
| siem-01 | SOC/MGMT | `10.10.30.10` | Wazuh all-in-one |
| dmz-01 | DMZ | `10.10.20.10` | Vulnerable web apps |
| atk-01 | REDTEAM | `10.10.40.10` (DHCP — rebuilt often) | Attack tooling, BloodHound collector |
| scan-01 | REDTEAM | `10.10.40.20` (DHCP) | OpenVAS/Greenbone scanning |

## Ports crossing segment boundaries

| From | To | Port | Why |
|---|---|---|---|
| dc-01, ws-01, rtr-01 (agents) | siem-01 | 1514/tcp | Wazuh agent data |
| dc-01, ws-01, rtr-01 (agents) | siem-01 | 1515/tcp | Wazuh agent enrollment |

Everything else stays inside its segment or is explicitly denied — see Phase 1's segmentation test matrix (`phase-1-network/segmentation-test-matrix.md`) once it exists.
