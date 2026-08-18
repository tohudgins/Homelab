# Homelab Runbook

How to actually *use* this lab — start it, run a simulation, hunt the results, add
new hosts, and reset. The lab is a platform, not a one-off build; this is the
operator's guide to driving it.

> Prereqs on the control node (macOS): VMware Fusion, Ansible (`pipx install
> --include-deps ansible`), the homelab SSH key at `~/.ssh/id_ed25519_homelab`,
> and the SSH aliases in `~/.ssh/config`. The encrypted ws-01 needs its passphrase
> in `scripts/.lab-secrets` (git-ignored) as `WS01_VMENC_PASS=...`.

## 1. Start / stop the lab (the `make` control surface)

Everything runs through `scripts/lab.sh`, wrapped by a `Makefile`:

```bash
make status                 # power state of every VM
make up PROFILE=soc         # start a run profile's VMs
make converge               # ansible-playbook site.yml (bring config to desired state)
make down                   # suspend everything running
make stop                   # clean poweroff of everything
make snapshot NAME=clean    # snapshot every running VM
make restore NAME=clean     # revert to a snapshot
make profiles               # list profiles
```

### Run profiles — never run everything (24 GB host ceiling)

| Profile | VMs | Use it for |
|---|---|---|
| `networking` | rtr-01 | firewall/segmentation work |
| `ad` | rtr-01 dc-01 ws-01 | Active Directory / GPO |
| `soc` | rtr-01 dc-01 ws-01 siem-01 | detection engineering (the daily driver) |
| `attack` | + fs-01 atk-01 | attack/detect pairing (suspend dmz first) |
| `vulnscan` | rtr-01 dc-01 siem-01 scan-01 | authenticated vuln scanning |
| `services` | rtr-01 dc-01 siem-01 fs-01 dmz-01 | file/web services + monitoring |

## 2. Run a simulation (the detection loop)

The lab exists to run this loop, over and over, on new techniques:

```bash
make up PROFILE=attack       # SOC + attacker box
make converge                # ensure everything is in its known-good state
```

1. **Attack** — from atk-01 (`ssh atk-01`): recon, BloodHound collection, execute a
   path (Kerberoasting, the fs-01 credential share, DCSync, etc. — see
   `phase-5-offense/`).
2. **Hunt** — in Wazuh (`https://<siem-01>` or `ssh siem-01`): find the telemetry,
   confirm the detection fired, or write a new rule (`phase-4-detection/`).
3. **Evade** — try to slip past your own rule; document what worked.
4. **Snapshot** before a destructive test, `make restore NAME=clean` after.

**On the target side (ws-01)**: Sysmon + PowerShell Script Block Logging + the
Wazuh agent are already feeding the SIEM. To fire arbitrary ATT&CK technique tests,
install Atomic Red Team on ws-01 (interactive PowerShell — the installer prompts):
`IEX (IWR https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1 -UseBasicParsing); Install-AtomicRedTeam -getAtomics` (a `C:\AtomicRedTeam` Defender exclusion is already set), then `Invoke-AtomicTest <Txxxx>` and hunt it.

**Realistic victim identities**: `asmith` (designated victim) and `bwilson` are
ordinary domain users (plus `jdoe`); run simulations as one of these, not
`localadmin`. All are (re)created idempotently by the `dc` role.

## 3. Add a new host (the scalability story)

The lab scales by the same pattern every existing host follows — this is why it's
built on Ansible roles, not hand config:

1. **Build the VM** — hand-built `.vmx` on the right vmnet (segment), or the
   headless autoinstall pattern in `phase-7-automation/provisioning/dmz-01/` for a
   from-blank Ubuntu box. Give it a static IP from `docs/00-ip-plan.md`.
2. **Register it** for control: add its `.vmx` path to `scripts/lab.sh` (`vmx_path`
   handles the default `<name>.vmwarevm/<name>.vmx` layout automatically) and add it
   to a run profile.
3. **Make it reachable**: add an SSH alias in `~/.ssh/config` (`ProxyJump rtr-01`
   for internal segments) and bootstrap passwordless sudo:
   `phase-7-automation/ansible/scripts/bootstrap-sudo.sh <host>`.
4. **Put it under config management**: add it to `inventory/hosts.yml` (under the
   segment group so it inherits the ProxyCommand jump + become), write a role under
   `roles/<role>/`, add a `<host>.yml` play, and wire it into `site.yml`.
5. **Converge + verify**: `make converge`, then re-run for `changed=0`.

New segments scale the same way: create the vmnet (DHCP off), add an nftables
stanza to the `router` role, converge rtr-01.

## 4. Where things live

| Need | Location |
|---|---|
| IP plan / segments | `docs/00-ip-plan.md` |
| Firewall / DHCP / DNS / NSM config | `phase-7-automation/ansible/roles/router/` |
| AD config + deliberate weaknesses | `roles/dc/` + `phase-2-identity/known-weaknesses.md` |
| Detection rules/decoders | `roles/siem/` + `phase-4-detection/` |
| Attack writeups + BloodHound | `phase-5-offense/` |
| NSM / PCAP analysis | `phase-6-nsm/` |
| **Credentials, per-VM config** | the second-brain `Virtual Machines` note (not in git) |

## 5. End a session

```bash
make down     # suspend all (fast resume, preserves state)   — or —
make stop     # clean poweroff (cold boot next time)
```

Always suspend before unplugging the external SSD. Cap snapshots at 2 per VM.
