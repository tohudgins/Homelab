# Windows endpoint telemetry — Sysmon config + DNS threat-intel

The quality of Windows detection is capped by the quality of Sysmon's config: a thin config simply never
generates the events your rules would match. This is the endpoint-telemetry-visibility piece — adopting a
professional Sysmon config and then making the newly-gained telemetry *actionable*.

Applies to `ws-01` (managed manually — the Windows host has no WinRM/Ansible automation yet; staged here +
documented, same pattern as the Atomic Red Team install).

## The gap
ws-01's original config logged a decent range (Sysmon EID 1/3/7/10/11/13/17/26) but **no EID 22 (DnsQuery)** —
zero DNS telemetry. DNS is where C2 domains, DGA, and DNS tunnelling show up; missing it is a real SOC blind
spot. (Sysmon keeps its live config in the registry, not re-exportable as XML, so the fix is to apply a known
complete config rather than diff the current one.)

## The fix — SwiftOnSecurity config
`sysmonconfig.xml` here is the community-standard [SwiftOnSecurity sysmon-config](https://github.com/SwiftOnSecurity/sysmon-config)
(`sysmonconfig-export.xml`): comprehensive, noise-tuned, and it **includes DnsQuery**. Apply it (elevated):
```powershell
C:\WINDOWS\Sysmon64a.exe -c C:\path\to\sysmonconfig.xml
```
Verified: after applying, resolving a domain produced a Sysmon **EID 22** event.

**Regression-tested.** Swapping a working config risks silently dropping the process-creation telemetry the
existing rules (100100–100113) depend on. The purple-team harness (`phase-5-offense/purple-team/`) is exactly
the automated regression gate for this: re-run after the swap → **9/9 (100%)**, so every existing detection
survived *and* DNS was added. Never change endpoint telemetry without re-running it.

## Making DNS actionable — DNS → threat-intel (rule 100310)
Telemetry you don't act on is just noise you pay to store. Wazuh decodes EID 22 into `win.eventdata.queryName`
(group `sysmon_event_22`, base level 0 = not alerted). Rule **100310** (`siem` role `local_rules.xml`) does a
fast CDB lookup of the queried name against `etc/lists/malicious-domains` (~1,190 ThreatFox malicious domains
+ a lab test domain) and escalates a hit to **level 12** (T1071.004, Application Layer Protocol: DNS).

- **CDB lookup, not a per-query API call** — DNS is high-volume, so this is the right tool (the domain
  analogue of the IP list 100210/100211; the MISP integration handles the lower-volume IP/hash events).
- **Verified end-to-end:** a DNS query to `malicious-test-lab.io` on ws-01 → EID 22 → Wazuh → **rule 100310,
  level 12**: "DNS query to a known-malicious domain".
- **Known limitation:** `match_key` is an exact match, so a *subdomain* of a listed domain won't match (Wazuh
  has no suffix-match lookup). Documented, not hidden. Refresh the list from the ThreatFox `domain` IOCs.

## Reproduce
```bash
# apply the config on ws-01 (elevated), then regression-test:
phase-5-offense/purple-team/purple-team.py           # expect 9/9

# verify the DNS detection:
#   (on ws-01)  Resolve-DnsName malicious-test-lab.io
ssh siem-01 "sudo grep -a '\"id\":\"100310\"' /var/ossec/logs/alerts/alerts.json | tail -1"
```
