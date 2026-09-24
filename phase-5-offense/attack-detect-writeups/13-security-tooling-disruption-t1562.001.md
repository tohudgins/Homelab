# Attack / Detect: Security Tooling Disruption — the rule that questions every other rule's assumption

**Phase 4 — Detection engineering.** [T1562.001](https://attack.mitre.org/techniques/T1562/001/) — Impair
Defenses: Disable or Modify Tools — is arguably the single highest-value rule in this entire catalog. Every
other technique this lab detects assumes the SIEM is still watching when the attack happens. This is the one
that detects an attacker trying to make that assumption false, on both platforms in the lab: a Linux
detection on dc-01 (disabling the Wazuh agent itself) and a Windows detection on ws-01 (disabling Defender).

> [!check] Verified live on both platforms. Linux: `systemctl disable wazuh-agent` → rule 100060, level 13.
> Windows: `Add-MpPreference -ExclusionPath` → rule 100506, level 12, within ~5 seconds of the real EID 4104
> script-block telemetry.

---

## 1. Linux — disabling the Wazuh agent itself (dc-01, rule 100060)

**Objective:** detect an attempt to stop, disable, or mask the security tooling running on dc-01 — the
Wazuh agent, `auditd`, or the `samba-ad-dc` service whose logs feed most of this catalog's other
detections.

**No new telemetry needed.** The rule chains directly off the stock sudo rule (`5402`, any successful
sudo-to-root, already firing constantly throughout normal operation) rather than requiring a new logging
facility, decoder, or FIM path — it's pure escalation on what's already flowing, a regex over the `command`
field the stock `sudo` decoder already extracts.

**Attack simulation, handled honestly around a self-defeating test:** the obvious test —
`systemctl stop wazuh-agent` — has an irony baked in: an agent that's just been killed can't report that it
was killed, so a naive test would risk "failing" for a reason that has nothing to do with whether the rule
actually works. Used `systemctl disable wazuh-agent` instead — it matches the exact same detection pattern
(and is a real, meaningfully dangerous action in its own right: it prevents the agent from surviving the
*next* reboot, a realistic low-and-slow persistence-denial move) while leaving the agent running long enough
to actually report the alert it just triggered.

```xml
<rule id="100060" level="13">
  <if_sid>5402</if_sid>
  <field name="command" type="pcre2">systemctl\s+(stop|disable|mask)\s+\S*(wazuh-agent|auditd|samba-ad-dc)|service\s+(wazuh-agent|auditd|samba-ad-dc)\s+stop</field>
  <description>Security tooling disruption attempt — $(command)</description>
  <mitre><id>T1562.001</id></mitre>
  <group>defense_evasion,attack,</group>
</rule>
```

**Verified live:**

```
Rule: 100060 (level 13) -> 'Security tooling disruption attempt — /usr/bin/systemctl disable wazuh-agent'
```

Level 13 — one level above everything else in the Linux/AD side of this catalog, deliberately: this alert
type should never get lost in a busy queue behind routine credential-access noise.

**Evasion — real, and worth being upfront about:** this only catches the *obvious* path (systemctl/service
managing the named unit by name). A more careful attacker sends `SIGSTOP`/`SIGKILL` directly to the
`wazuh-agent` process, blocks `1514/tcp` outbound at the host firewall, or corrupts the agent's own config —
none of which touch this rule, since none of them are a sudo command matching this text pattern at all. A
production deployment would pair this with **manager-side "agent went silent unexpectedly" monitoring**
(Wazuh's own agent-disconnection alerting) as the real backstop — that path doesn't depend on the
compromised agent reporting anything, which is the whole point once an attacker is sophisticated enough to
avoid the obvious command-line path this rule watches.

**False-positive risk:** low in a small lab (legitimate reasons to stop the agent — patching, planned
maintenance — are rare and usually scheduled), but real in any environment with routine agent
upgrades/restarts as part of normal ops; those would need an allowlist window rather than firing this as an
incident every time.

## 2. Windows — disabling Microsoft Defender (ws-01, rule 100506)

**Objective:** the Windows counterpart to the same idea — an attacker (or malware) adding a Defender
exclusion path so a payload can sit on disk without being scanned, one of the most common real-world
pre-execution steps before dropping a tool that would otherwise get quarantined.

**A genuine harness gap, worked around honestly:** this host's offline Atomic Red Team bundle has no
T1562.001 atomic at all, so it couldn't be exercised through the standard `Invoke-AtomicTest` battery the
way most Windows techniques in this lab are. Live-fired manually instead —
`Add-MpPreference -ExclusionPath C:\some\path` — specifically to prove the `ps_script` → Wazuh pipeline
fires end-to-end on real EID 4104 script-block telemetry, not just to exercise the technique in the abstract.
The exclusion was removed immediately after.

**This was also the first `ps_script`-logsource Sigma rule** compiled for this lab (`sigma-to-wazuh.py`'s
second logsource, after `process_creation`) — proving the compiler pipeline itself worked on PowerShell
script-block content, not just Sysmon process events.

**Verified live:** fired **within ~5 seconds** of the real script-block event reaching Wazuh, at **level
12** — correctly tagged `T1562.001`.

## 3. Why both platforms get their own rule, not one shared pattern

The two detections have nothing in common mechanically — one is a regex over a sudo command line chained
off a stock correlation rule, the other is a Sigma-compiled PowerShell script-block match — because the
underlying *telemetry* is completely different per platform. That's the honest reality of covering "an
attacker disables the security tooling" across a mixed Linux/Windows environment: the technique is one ATT&CK
ID, but closing it for real means two separate, platform-native detections, not one clever generic rule.

## Reproduce

```bash
# Linux (dc-01)
ssh dc-01 'sudo systemctl disable wazuh-agent'
ssh siem-01 "sudo grep -a '\"id\":\"100060\"' /var/ossec/logs/alerts/alerts.json | tail -1"
ssh dc-01 'sudo systemctl enable wazuh-agent'

# Windows (ws-01)
ssh ws-01 'powershell -c "Add-MpPreference -ExclusionPath C:\\test-exclusion"'
ssh siem-01 "sudo grep -a '\"id\":\"100506\"' /var/ossec/logs/alerts/alerts.json | tail -1"
ssh ws-01 'powershell -c "Remove-MpPreference -ExclusionPath C:\\test-exclusion"'
```

## Related

`phase-4-detection/detection-catalog.md` #7 "T1562.001 — Impair Defenses" (the full original write-up this
backfills, Linux side) · `phase-4-detection/sigma/README.md`'s "Rules shipped" table and Verification section
(the Windows `ps_script` side, and the compiler's own second-logsource story) · `phase-5-offense/purple-team/tests.json`'s
exclusion note (why this stays a manual live-fire rather than an ART battery entry)
