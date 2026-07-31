# Design Decisions

## Why build the router by hand instead of pfSense/OPNsense

Apple Silicon rules them out anyway (x86-only) — but even without that constraint, writing `nftables` rules from an empty ruleset demonstrates understanding of the underlying mechanics in a way that clicking through a firewall GUI product doesn't. The lab is not the router; the *documented, reproducible build* of the router is the point.

## Why Wazuh over Splunk/Elastic directly

Free at any scale — no ingest-volume licensing wall to hit in a homelab — and genuinely open-source. The detection-engineering surface (custom rules/decoders, FIM, SCA, active response) maps directly onto what the phase plan exercises. Tradeoff: a smaller community/documentation surface than Splunk, and its Windows agent on ARM64 runs via x64 emulation rather than natively — validated in Phase 3 before anything gets built on top of it.

## Why ARM64-only, build-your-own vulnerable environment

Apple Silicon has no x86 virtualization and no nested virtualization, which rules out most pre-built vulnerable labs (Metasploitable, most VulnHub, GOAD, Security Onion, FLARE-VM) outright. Rather than a limitation to work around, this is the differentiator: anyone can `vagrant up` a pre-built lab — fewer people can explain the AD forest, the firewall ruleset, and the detection rules they built themselves from nothing.

## Why five segments instead of a flatter network

CORP/SOC/DMZ/REDTEAM/WAN mirrors a real enterprise's actual boundary logic. Most importantly, the SOC segment is isolated even from the identity plane it monitors — `siem-01` never joins the AD domain — and REDTEAM can reach CORP/DMZ but is explicitly walled off from SOC. Being able to explain *why* that asymmetry exists is itself a portfolio artifact, not just a network diagram.

## Why Zeek runs from Phase 1, not just Phase 6

Standing up Suricata + Zeek together from the start — even before rule-tuning begins — means every later phase generates real historical NSM data, instead of Phase 6 needing to backfill weeks of context in a rush.

These decisions get revisited as the build progresses — see the phase writeups linked from the [README](../README.md).
