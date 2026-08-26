# Design Decisions

## Why build the router by hand instead of pfSense/OPNsense

Apple Silicon rules them out anyway (x86-only) — but even without that constraint, writing `nftables` rules from an empty ruleset demonstrates understanding of the underlying mechanics in a way that clicking through a firewall GUI product doesn't. The lab is not the router; the *documented, reproducible build* of the router is the point.

## Why Wazuh over Splunk/Elastic directly

Free at any scale — no ingest-volume licensing wall to hit in a homelab — and genuinely open-source. The detection-engineering surface (custom rules/decoders, FIM, SCA, active response) maps directly onto what the phase plan exercises. Tradeoff: a smaller community/documentation surface than Splunk, and its Windows agent on ARM64 runs via x64 emulation rather than natively — validated in Phase 3 before anything gets built on top of it.

## Why ARM64-only, build-your-own vulnerable environment

Apple Silicon has no x86 virtualization and no nested virtualization, which rules out most pre-built vulnerable labs (Metasploitable, most VulnHub, GOAD, Security Onion, FLARE-VM) outright. Rather than a limitation to work around, this is the differentiator: anyone can `vagrant up` a pre-built lab — fewer people can explain the AD forest, the firewall ruleset, and the detection rules they built themselves from nothing.

## Why five segments instead of a flatter network

CORP/SOC/DMZ/REDTEAM/WAN mirrors a real enterprise's actual boundary logic. Most importantly, the SOC segment is isolated even from the identity plane it monitors — `siem-01` never joins the AD domain — and REDTEAM can reach CORP/DMZ but is explicitly walled off from SOC. Being able to explain *why* that asymmetry exists is itself a portfolio artifact, not just a network diagram.

## Why dc-01 is Samba AD DC, not Windows Server

The original plan called for Windows Server ARM64 on dc-01. Microsoft doesn't publish an ARM64 Windows Server ISO at all — Azure and OEM partners get it, the public doesn't — so the only route in is [UUP dump](https://uupdump.net), which packages Windows Insider Preview builds. In practice this proved unreliable: the newest arm64 Server Insider build UUP dump indexed had already been pulled from Windows Update (`EMPTY_FILELIST`), and a second attempt at an older build turned out to be x64 despite the listing, caught only by checking the actual PE header of `setup.exe` inside the ISO rather than trusting the filename. Insider builds also expire on a schedule regardless, meaning even a successful build would need periodic rebuilding indefinitely.

Samba AD DC sidesteps all of it — a real, open-source implementation of the Active Directory protocols (Kerberos, LDAP, GPO-compatible SYSVOL) that runs natively on ARM64 Linux with no unofficial builds involved. `ws-01` domain-joins it exactly like it would real AD, and the attack/detection scenarios Phase 4/5 plan (Kerberoasting, NTLM, GPO misconfig) exercise the same protocol behavior either way, since they target the protocol, not the specific server implementation. Documenting a real constraint and a reasoned pivot away from the original plan is itself the kind of judgment call worth showing in a portfolio, not something to hide.

## Why Zeek runs from Phase 1, not just Phase 6

Standing up Suricata + Zeek together from the start — even before rule-tuning begins — means every later phase generates real historical NSM data, instead of Phase 6 needing to backfill weeks of context in a rush.

## Why CORP resolves only internal names, and tooling is installed offline

The lab is internal and self-contained by design: it must not depend on anything outside itself to operate or to be rebuilt. `ws-01` — like every CORP host — resolves through `dc-01`'s Samba AD DNS, which is authoritative for `lab.internal` and has **no external forwarder**, so internal names resolve and public names (`github.com`, …) deliberately do not. Tooling such as Atomic Red Team is therefore staged **offline** — pulled once on the admin/management host and pushed to the target over the existing SSH path — rather than fetched from the internet by the endpoint itself. That mirrors how real segmented enterprises actually distribute software into isolated zones (internal package repos / WSUS / SCCM), where a workstation in a secured segment has no direct line to the public internet.

The obvious alternative — adding a DNS forwarder on `dc-01` so `ws-01` could reach GitHub and the stock `Install-AtomicRedTeam` one-liner would "just work" — was rejected precisely because it makes the lab reach outside itself for a routine operation, which is the opposite of the property we want. (`rtr-01` still permits CORP→WAN at L3/L4; the isolation that matters for how the lab operates is at name resolution. Enforcing it at the firewall as well is a stricter variant, not required for the self-contained property, and left open keeps a workstation's latent internet path realistic.)

These decisions get revisited as the build progresses — see the phase writeups linked from the [README](../README.md).
