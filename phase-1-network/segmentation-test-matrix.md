# Segmentation test matrix

The **expected** column is derived directly from the authoritative firewall ruleset
(`phase-7-automation/ansible/roles/router/files/nftables.conf`, mirrored here as
`nftables.conf`). Both `forward`-chain policies are `drop`, so anything not listed as
ALLOW is denied by the default rule and logged (`nft-forward-drop:`). All chains are
stateful (`ct state established,related accept`), so every ALLOW below implies its
return traffic works without a separate reverse rule.

Referenced by [`docs/00-ip-plan.md`](../docs/00-ip-plan.md). Run it with
[`segmentation-test.sh`](segmentation-test.sh) from rtr-01 (or drive each host over
SSH), which probes each cell with `nc -z -w2` / `ping -c1` and diffs the result
against the expected value below.

## Segments
`CORP 10.10.10.0/24` · `DMZ 10.10.20.0/24` · `SOC 10.10.30.0/24` · `REDTEAM 10.10.40.0/24` · `WAN` (Fusion NAT uplink)

## Forward (segment-to-segment)

| From → To | Expected | Rationale |
|---|---|---|
| CORP → WAN | ALLOW (all) | normal corp internet egress |
| CORP → DMZ | ALLOW (all) | corp users reach the DMZ web apps |
| CORP → SOC | ALLOW **only** tcp 1514/1515/8000; else DROP | agent→manager (Wazuh) + Velociraptor client→server; nothing else may reach the SIEM |
| CORP → REDTEAM | ALLOW **only** tcp 80/443, udp/tcp 53; else DROP | models permitted corp egress a C2 implant abuses (web + DNS), routed past Suricata/Zeek so it's detectable |
| DMZ → WAN | ALLOW (all) | package updates for the DMZ hosts |
| DMZ → SOC | ALLOW **only** tcp 1514/1515; else DROP | DMZ agent→manager only |
| DMZ → CORP | **DROP** | a deliberately-vulnerable host must not pivot into the domain |
| DMZ → REDTEAM | **DROP** | no rule; default drop |
| SOC → CORP / DMZ / REDTEAM / WAN | ALLOW (all) | Wazuh manager initiates to agents; SOC is the trusted management plane |
| REDTEAM → CORP | ALLOW (all) | the attack surface — atk-01 attacks dc-01/ws-01/fs-01 |
| REDTEAM → DMZ | ALLOW (all) | atk-01 attacks the DMZ web apps |
| REDTEAM → WAN | ALLOW (all) | attacker tooling downloads |
| **REDTEAM → SOC** | **DROP** | headline control: the box generating the attack must not reach the SIEM observing it |

## Input (to rtr-01 itself)

| From → rtr-01 | Expected | Rationale |
|---|---|---|
| any → tcp 22 | ALLOW | SSH management (WAN path is Fusion NAT, not the real internet) |
| any → ICMP echo | ALLOW | reachability/segmentation testing |
| DMZ/SOC/REDTEAM → udp 67, udp/tcp 53 | ALLOW | dnsmasq DHCP/DNS for those segments |
| CORP → udp 67 / 53 | **DROP** | dc-01 owns CORP's DHCP/DNS (Phase 2), not rtr-01 |
| CORP/DMZ/SOC/REDTEAM → udp 123 | ALLOW | chrony NTP for every internal segment |
| any → anything else | **DROP** | default-deny input |

## Known-permissive notes (by design, not gaps)
- **SOC → REDTEAM is allowed** even though REDTEAM normally runs no Wazuh agent — SOC
  is the trusted plane and the rule is a broad "manager reaches every segment." Unused,
  not a hole.
- **REDTEAM → SOC is blocked, but REDTEAM → CORP → SOC agent ports is not** — a
  compromised CORP host could still reach the SIEM's 1514/1515/8000. That's the
  intended agent channel; SOC inbound is restricted to exactly those ports even from
  CORP, which is the defense-in-depth point, not an oversight.

## Verification status
Expected values are derived from the enforced ruleset above (the source of truth).
**Live run: 2026-09-28 — 9/9 cells match**, including the headline REDTEAM→SOC block
(1514 and a high random port both filtered) and every allow/drop cell above, probed
with `segmentation-test.sh` (services profile + atk-01 booted for the RED rows).
Re-run it after any firewall change. ICMP is intentionally open on the input chain
specifically so this matrix can be probed.

One gotcha surfaced during that run, unrelated to the firewall: the DMZ Juice Shop
cell first read as a false DROP because dmz-01's `docker0` bridge had lost its IPv4
after a VM suspend/resume (docker-proxy still listened on :3000 but couldn't forward).
That's a container-networking artifact, not a segmentation failure — the dmz role now
self-heals it on converge (restarts docker when docker0 is link-DOWN *or* missing its
IPv4). REDTEAM→DMZ reachability at L3/L4 is independently confirmed by the host being
reachable on :22.
