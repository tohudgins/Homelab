# CIS compliance scanning (Wazuh SCA) — and fixing the silent skip

Detection answers "is someone attacking me?" **Compliance/configuration assessment** answers a question a SOC
also owns: "is this host actually hardened, or is it wide open before anyone even shows up?" Wazuh's **SCA**
(Security Configuration Assessment) runs CIS-benchmark policies on every agent and reports pass/fail per
control — continuous, agent-based, no extra tooling. This is the config-hygiene half of the monitoring story.

Manager: `siem-01` · agents run SCA on start + every 12h.

> [!check] Assessed and fixed live on 2026-08-30. fs-01 now scores **47% (93 pass / 103 fail / 207 checks)**
> against CIS Ubuntu — up from **0 checks actually run**, because the policy was silently skipping itself.

## The silent skip (the real finding)
SCA was *enabled* (`<sca><enabled>yes</enabled>`), the agent had the CIS policy, and the scan "succeeded" —
but its log read:
```
sca: INFO: Skipping policy 'cis_ubuntu22-04.yml': 'Check Ubuntu version.'
sca: INFO: Security Configuration Assessment scan finished. Duration: 0 seconds.
```
**Zero checks ran.** Every CIS policy starts with a `requirements:` gate; the Ubuntu one is
`f:/etc/os-release -> r:Ubuntu 22.04` (condition `all`). The lab hosts run **Ubuntu 26.04**, for which Wazuh
ships **no** CIS policy, so the closest one (22.04) self-skips on the version mismatch. A "0 seconds / scan
finished" that looks healthy but measured nothing — the same silent-fallback trap as everywhere else in this
catalog that reports "ran successfully" without checking it actually did anything: the green status hides
that nothing happened.

## The fix (`sca-ubuntu2604-fix.yml`)
Relax the version gate to match any Ubuntu — the overwhelming majority of CIS Linux controls (SSH config,
file permissions, kernel params, partition mount options, auditd, PAM, …) are version-agnostic:
```yaml
- replace:
    path: /var/ossec/ruleset/sca/cis_ubuntu22-04.yml
    regexp: 'f:/etc/os-release -> r:Ubuntu 22\.04'
    replace: 'f:/etc/os-release -> r:Ubuntu'
  notify: Restart wazuh-agent
```
After that, the scan runs in ~4s and reports a real posture. Codified as an idempotent playbook targeting the
Ubuntu agents (fileservers/domain_controllers/dmz); re-running is `changed=0`.

## What it found — and the tie to the attack work
fs-01 fails **103** CIS controls (47% compliant — a realistic unhardened-box score). The top failures are
filesystem/partition hardening, and the very first one closes a loop with the Sliver C2 exercise
(`phase-5-offense/sliver-c2/`):

```
FAIL: Ensure noexec option set on /tmp partition        <-- would have blocked the beacon run from /tmp
FAIL: Ensure separate partition exists for /var, /var/tmp, /var/log
FAIL: Ensure nodev/nosuid/noexec on /var* partitions
```

`noexec` on `/tmp` is exactly the control that would have *prevented* the Sliver beacon (which executed from
`/tmp`, caught by Wazuh rule 100200). Compliance and detection are two views of the same risk: **hardening
removes the attack surface; detection catches what hardening missed.** A SOC analyst uses SCA to drive the
first, and the detections in this repo to do the second.

## How a SOC analyst uses this
- **Posture over time:** the compliance % per host, trending as hosts get hardened.
- **Triage:** `GET /sca/<agent>/checks?result=failed` — the actionable remediation list, per control, with the
  CIS rationale and the exact check.
- **Reporting:** the Wazuh dashboard's SCA module renders per-policy scores and the failed-control drill-down.

## Reproduce
```bash
ansible-playbook -i inventory/hosts.yml sca-ubuntu2604-fix.yml     # enable scanning on Ubuntu 26.04 agents
# score + failed controls via the API (agent 004 = fs-01):
curl -k -H "Authorization: Bearer $TOKEN" https://siem-01:55000/sca/004
curl -k -H "Authorization: Bearer $TOKEN" 'https://siem-01:55000/sca/004/checks/cis_ubuntu22-04?result=failed'
```
