# YARA-on-FIM — malware detection on file write (fs-01)

Adds real malware detection to the lab: when a file is written to the fs-01 share,
Wazuh scans it with **YARA** and alerts on a signature match. File Integrity
Monitoring answers *"a file changed"*; YARA answers *"…and it matches known
malware."* This is the capability the lab was missing between FIM and the endpoint
monitors.

> [!warning] Built 2026-09-06 as IaC — **live AR verification required.**
> Unlike the Sigma rules (proven offline by `sigma-selftest.py`), an active-response
> loop can only be validated live: the AR JSON parsing, the agent→manager log ship,
> the decoder, and the rule all have to line up on a running system. The shell and
> XML are validated (shellcheck + xmllint in CI), but **run §Verify before trusting
> this** — it's the one piece in the session's gap-closing work that isn't
> offline-provable.

## How it works

```
file written to /srv/samba/public          (fs-01)
      │  realtime FIM (syscheck)
      ▼
Wazuh rule 100450  ── triggers ──►  active-response "yara" (location=local)
                                          │  runs on fs-01
                                          ▼
                                    yara.sh  →  yara -r malware.yar <file>
                                          │  on match, writes:
                                          ▼
      "wazuh-yara: INFO - Scan result: <RULE> <file>"  →  active-responses.log
      │  shipped to the manager (localfile)
      ▼
decoder wazuh-yara / wazuh-yara-result  →  rule 100460 (level 12, T1204.002)
```

## Pieces (all IaC)

| File | Role | What |
|---|---|---|
| `roles/fileserver/files/yara.sh` | fileserver | AR script: parse alert JSON (jq), scan the changed file, log matches |
| `roles/fileserver/files/malware.yar` | fileserver | starter ruleset — EICAR, generic PHP webshell, ransom-note strings, Mimikatz |
| `roles/fileserver/tasks/main.yml` | fileserver | install yara+jq, deploy script/rules, ship active-responses.log |
| `roles/siem/tasks/main.yml` | siem | manager `<command>`/`<active-response>` for the `yara` command on rule 100450 |
| `roles/siem/files/local_decoder.xml` | siem | `wazuh-yara` decoders |
| `roles/siem/files/local_rules.xml` | siem | 100450 (FIM trigger), 100460 (match), 100461 (error) |

## Verify (when the lab is up)

```bash
# 1) converge fs-01 + siem-01
make converge   # or: ansible-playbook fileserver.yml siem.yml

# 2) drop the EICAR test file into the share (safe, non-malicious)
ssh fs-01 'printf %s "X5O!P%@AP[4\PZX54(P^)7CC)7}\$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!\$H+H*" \
  | sudo tee /srv/samba/public/eicar.com >/dev/null'

# 3) confirm the chain fired
ssh fs-01   "sudo grep wazuh-yara /var/ossec/logs/active-responses.log | tail"
ssh siem-01 "sudo grep -E '100450|100460' /var/ossec/logs/alerts/alerts.log | tail"
```

Rule 100460 firing on `EICAR_Test_File` proves the loop end to end. Then extend
`malware.yar` with a real feed (Florian Roth's `signature-base`, YARAify).

## Notes

- YARA + jq are arm64-native (Debian/Ubuntu packages) — no emulation.
- The scan runs only on the *changed* file (cheap), not the whole share.
- Deliberately **not** counted as new ATT&CK coverage beyond the T1204.002 tag on
  the alert — like Velociraptor, it's a capability, and the match's real technique
  depends on what was dropped (webshell = T1505.003, mimikatz = T1003, etc.).
