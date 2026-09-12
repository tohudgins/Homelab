# Cybersecurity Homelab

A segmented, reproducible security lab built on Apple Silicon (VMware Fusion, ARM64-only) — Active Directory,
a hand-built Linux router/firewall, Wazuh SIEM, and a full detection-engineering loop from attack simulation
to written detection to evasion attempt.

**All 8 build phases (0–7) complete.** The detection catalog runs to **50 ATT&CK techniques** across
**13 of ATT&CK's 14 tactics**, almost all verified end-to-end against real, live-fired attacks — not just
written and assumed to work. A capstone end-to-end intrusion emulation chains 7 phases into one detected
kill chain. Full status and rationale: [`README`](https://github.com/tohudgins/Homelab).

## Where to start

- **New here?** [Design Decisions](design-decisions.md) explains the constraints that shaped every choice
  below (ARM64-only, no nested virtualization, why the DC is Samba not Windows Server) — read this first,
  most other pages assume it.
- **Want the headline story?** [Phase 5 · Capstone — APT Scenario](phase-5-offense/apt-scenario/README.md)
  is one realistic intrusion, initial access → impact, showing the lab detect a *chained* campaign the way a
  SOC actually sees one.
- **Want the detection engineering depth?** [Phase 4 · Detection Catalog](phase-4-detection/detection-catalog.md)
  is the technique-by-technique record: attack simulated → raw telemetry observed → rule written → verified
  true positive → evasion attempted → false-positive risk named. Every entry is a real finding, including
  the ones that didn't work and why.
- **Want to run it yourself?** [Runbook](RUNBOOK.md) covers starting the lab, running a simulation, hunting
  the results, and adding a new host — the lab is driven as a platform, not a pile of VMs.

## Build phases

| Phase | Focus |
|---|---|
| 0–1 | Foundation, routing & segmentation (hand-built `nftables`, no GUI firewall product) |
| 2 | Identity — Active Directory (Samba AD DC, deliberate misconfigurations) → [Known Weaknesses Register](phase-2-identity/known-weaknesses.md) |
| 3 | Visibility — Wazuh SIEM stood up |
| 4 | Detection engineering → [Detection Catalog](phase-4-detection/detection-catalog.md) · [ATT&CK Coverage Map](phase-4-detection/attack-coverage/README.md) · [Sigma Detection-as-Code](phase-4-detection/sigma/README.md) |
| 5 | Offense in context → [Capstone](phase-5-offense/apt-scenario/README.md) · [Attack/Detect Writeups](phase-5-offense/attack-detect-writeups/01-fs01-credential-theft-to-dcsync.md) · [BloodHound](phase-5-offense/bloodhound-ce/README.md) |
| 6 | Network security monitoring → [Suricata + Zeek, DNS tunneling, PCAP reports](phase-6-nsm/README.md) |
| 7 | Automation — full Ansible IaC → [`site.yml` converges all seven hosts at `changed=0`](phase-7-automation/README.md) |

## Skills demonstrated

- **Network engineering** — segmentation, firewalling, and routing built from an empty `nftables` ruleset
- **Identity infrastructure** — AD forest design, GPO, deliberately-introduced, documented misconfigurations
- **Detection engineering** — ATT&CK-mapped rules written and verified against real attack simulation
- **SOC operations** — Wazuh SIEM tuning, FIM, SCA benchmarking, active response
- **Offensive security in context** — AD attack-path mapping (BloodHound) through to executed technique through to detection
- **Network security monitoring** — paired Suricata + Zeek analysis, PCAP investigation
- **Infrastructure as code** — Ansible-driven rebuild of the entire lab
