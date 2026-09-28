# ws-01 — unattended provisioning (Windows 11 arm64, 25H2)

ws-01 is the domain-joined Windows victim workstation. Windows uses an
**autounattend.xml** answer file (not cloud-init/preseed). This reproduces the base
OS + a local admin + OpenSSH so the `windows` Ansible role can take over **over SSH**
(its transport). Sysmon, PowerShell Script-Block Logging and the Wazuh agent are all
applied by that role, not here.

> Authored 2026-09-28. **This is the least-verified file in the repo** and is marked
> so deliberately: a from-blank Windows-on-ARM install is ~30+ minutes and wasn't run
> here. The XML is well-formed and follows the standard Win11 unattend schema, but two
> things must be checked on a real build: (1) the **image edition name** — run
> `dism /Get-WimInfo /WimFile:<mount>\sources\install.wim` and set `/IMAGE/NAME` to
> match (defaults to "Windows 11 Pro"); (2) whether this ISO's Setup uses `install.wim`
> or `install.esd` and whether the ARM requirement-bypass is even needed (Fusion
> provides a vTPM). Treat it as a strong starting point, not a proven artifact.

## What's here
| File | Purpose |
|---|---|
| `autounattend.xml` | Windows Setup answer file: en-US, Win11 requirement bypass, GPT disk (EFI/MSR/Windows), skip OOBE + online account, create `localadmin`, and FirstLogonCommands that install/enable OpenSSH Server and drop the homelab key into `administrators_authorized_keys` |

## Build steps (host = macOS, VMware Fusion, ARM64)

```bash
# autounattend.xml is auto-detected at the root of removable media. Easiest: put it
# on a small second CD (any label) attached alongside the install ISO — no ISO
# remaster needed, unlike the Linux hosts.
mkdir seed && cp autounattend.xml seed/
xorriso -as mkisofs -output isos/ws-01-answer.iso -volid WSANSWER -joliet -rock seed

# Create the VM (4 vCPU / 8 GB / 64 GB, CORP NIC) with BOTH ISOs and boot it:
./scripts/create-vm.sh --name ws-01 --os arm-windows11-64 --cpus 4 --mem 8192 \
    --disk 64 --net vmnet3 \
    --iso isos/Win11_25H2_English_Arm64_v2.iso --seed isos/ws-01-answer.iso --start
# Setup finds autounattend.xml on the WSANSWER CD and installs unattended.
# NOTE: Windows Setup reboots several times and does NOT poweroff at the end — watch
# for the desktop, then detach both CDs.
```

## After first boot
`ansible-playbook windows.yml` (over SSH) installs Sysmon, PS Script-Block Logging
and the Wazuh agent. See `../ansible/roles/windows/`. Then domain-join per the AD docs.

Login: `localadmin`, password `WsLab2026!` (lab-only — see SECURITY.md); SSH key auth
is added by the FirstLogonCommands for the role's transport. **If you change the
password here, update `scripts/.lab-secrets` / the windows role to match.**
