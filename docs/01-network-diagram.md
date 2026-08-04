# Network Diagram

```mermaid
flowchart TB
    WAN(("Internet")) -->|vmnet8 NAT| RTR
    subgraph RTR["rtr-01 — Router/Firewall (Debian 13)"]
        FW["nftables + Suricata + Zeek (inline)
dnsmasq (DHCP/DNS) + FRR + chrony (NTP)"]
    end
    RTR -->|"vmnet3 · 10.10.10.0/24"| CORP
    RTR -->|"vmnet5 · 10.10.30.0/24"| SOC
    RTR -.->|"vmnet4 · 10.10.20.0/24 (optional)"| DMZ
    RTR -.->|"vmnet6 · 10.10.40.0/24 (on-demand)"| RED

    subgraph CORP["CORP"]
        DC["dc-01 — AD DS, DNS, GPO"]
        WS["ws-01 — Win11 workstation
Sysmon + Wazuh agent"]
        FS["fs-01 — Samba file server (planned)
domain member, deliberate share/ACL misconfig"]
    end
    subgraph SOC["SOC / MGMT"]
        SIEM["siem-01 — Wazuh all-in-one"]
    end
    subgraph DMZ["DMZ (optional)"]
        DMZH["dmz-01 — Juice Shop / DVWA / WebGoat"]
    end
    subgraph RED["REDTEAM (on-demand)"]
        ATK["atk-01 — Kali + BloodHound collector"]
        SCAN["scan-01 — OpenVAS/Greenbone"]
    end
```

## Reading it

- **Solid lines** are always-on segments (CORP, SOC). **Dashed lines** are optional (DMZ) or on-demand (REDTEAM) — never all running at once; see the run-profile table in the build plan.
- **rtr-01 is the only host with a leg in every segment**; every other host is single-homed.
- **SOC never initiates connections outward** except to reach agents for enrollment/data — it reaches everything, nothing reaches back in except the two Wazuh agent ports (see `00-ip-plan.md`).
- **REDTEAM can reach CORP and DMZ, never SOC** — the SIEM observing the attack must not be reachable by the box generating it.
