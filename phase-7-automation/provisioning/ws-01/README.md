# ws-01 — unattended provisioning (Windows 11 arm64, 25H2)

ws-01 is the domain-joined Windows victim workstation. Windows uses an
**autounattend.xml** answer file (not cloud-init/preseed). This reproduces the base
OS + a local admin + OpenSSH so the `windows` Ansible role can take over **over SSH**
(its transport). Installing and configuring Sysmon, PowerShell Script-Block Logging
and the Wazuh agent, and joining the domain, are all done by that role, not here.

> **Build-verified from a blank disk, 2026-09-29.** A fresh `create-vm.sh` VM went blank →
> Setup → OOBE → AutoLogon → `firstlogon.ps1` (log ends `authorized key installed - DONE`)
> → `ssh localadmin@10.10.10.50` through rtr-01 answered (`ws-01\localadmin`,
> Windows 10.0.26200, default shell cmd as the `windows` role expects). Verified with
> the Fusion GUI console open and nobody touching it; it has **not** been re-run
> headless. The `windows` role then converged on that VM too — see "After first boot".
>
> Gotchas that cost time (each found from guest logs, not guesses — read them off the
> disk with `7zz x <vm>.vmdk '2.Basic data partition.ntfs'`, then
> `Windows/Panther/**/setuperr.log`):
> - **`RunSynchronous` is not a `Microsoft-Windows-Shell-Setup` setting.** It belongs in
>   `Microsoft-Windows-Deployment`. In the wrong component Windows rejects the *whole*
>   unattend (`0x80220001`) and OOBE dies with "unexpected error ... restart the
>   installation".
> - **No AutoLogon = FirstLogonCommands never run** (VM parks at the login screen).
> - **`firstlogon.ps1` must be pure ASCII.** Windows PowerShell 5.1 reads a BOM-less
>   file as ANSI; an em dash inside a double-quoted string ends with a curly `”`
>   quote, which terminates the string and the script silently fails to parse.
> - **The VM needs a USB xHCI controller *and* a `hid` device** or Setup has no
>   keyboard/mouse (`create-vm.sh` adds both for Windows guests).
> - **vmxnet3 has no inbox Windows driver**, so the VMware Tools CD is required for
>   any network at all; CORP has no DHCP, hence the static address.
> - The stock ISO stalls at "Press any key to boot from CD" (un-dismissable on a
>   headless VM). `build-media.sh` remasters it: UDF copy-out, `wimlib` split of
>   `install.wim` under 4 GB, `xorriso` with `efisys_noprompt.bin`.
> - **Edition name CONFIRMED**: `wiminfo` lists index 3 = **Windows 11 Pro**, matching
>   `/IMAGE/NAME`. (The ISO uses `install.wim`, not `.esd`.)

## What's here
| File | Purpose |
|---|---|
| `autounattend.xml` | Windows Setup answer file: en-US, Win11 requirement bypass, GPT disk (EFI/MSR/Windows), skip OOBE + online account (`BypassNRO`), create `localadmin`, AutoLogon it once, and run `firstlogon.ps1` from the answer CD |
| `firstlogon.ps1` | First-logon provisioning: VMware Tools, static IP, OpenSSH, authorized key. **Keep it pure ASCII** (see gotchas) |
| `build-media.sh` | Builds `isos/Win11_..._noprompt.iso` and `isos/ws-01-answer.iso` |

## Build steps (host = macOS, VMware Fusion, ARM64)

```bash
# 1. Build both ISOs: the no-prompt install ISO and the WSANSWER answer ISO
#    (autounattend.xml + firstlogon.ps1 + a pinned Win32-OpenSSH ARM64 MSI).
#    Needs brew: xorriso, wimlib. Idempotent; ~2 min the first time.
phase-7-automation/provisioning/ws-01/build-media.sh

# 2. Create the VM (4 vCPU / 8 GB / 64 GB, CORP NIC) with three CDs and boot it.
#    --extra-iso is the VMware Tools CD: firstlogon.ps1 installs it to get the
#    vmxnet3 driver. --gui because the console is how you watch/debug Setup.
./scripts/create-vm.sh --name ws-01 --os arm-windows11-64 --cpus 4 --mem 8192 \
    --disk 64 --net vmnet3 \
    --iso isos/Win11_25H2_English_Arm64_noprompt.iso --seed isos/ws-01-answer.iso \
    --extra-iso isos/vmware-arm64-drivers.iso --start --gui
# Setup finds autounattend.xml on the WSANSWER CD and installs unattended (~15 min,
# several reboots, no input needed). It does NOT power off at the end: when SSH
# answers on 10.10.10.50, detach the CDs.
```

## What happens after Setup
`autounattend.xml` AutoLogons `localadmin` once, which runs `firstlogon.ps1` from the
WSANSWER CD. It installs VMware Tools (vmxnet3 driver), sets the static CORP address
`10.10.10.50/24`, installs OpenSSH from the MSI on the CD (no internet needed) and
authorizes the homelab key. Progress is in `C:\firstlogon.log`. (It also writes to
COM1, but that did not show up in the serial log in testing — treat the log file as
the source of truth.)

## After first boot: converge the `windows` role
```bash
phase-7-automation/windows-config/fetch-installers.sh   # once: stage the Wazuh MSI + Sysmon
cd phase-7-automation/ansible && ansible-playbook windows.yml
```
Needs rtr-01, dc-01 and siem-01 up. The role installs Sysmon (ARM64) and the Wazuh
agent (enrolling with the manager), makes the agent collect the Sysmon and PowerShell
channels, sets the timezone, **joins `lab.internal`** (the VM reboots itself), then
points w32time at rtr-01 and applies the rest. A fresh host converges in one run and
re-runs at `changed=0`.

Verified 2026-09-29 on a from-blank rebuild, run as a test machine `ws-01t`
(`-e windows_hostname=ws-01t`, so the real ws-01's AD computer account and Wazuh agent
registration are never touched; `windows_hostname` is both the computer name and the
agent name). Manager side: agent Active, and Application/Security/System/Sysmon/
PowerShell events all arrived. The extra `-e` and a throwaway `known_hosts` are only
needed when testing next to a live ws-01 at the same address.

Things that bit during that run, now fixed in the role:
- **Sysmon names its service after the installer's file name.** Staging it under any
  name but `Sysmon64a.exe` registers a differently-named service.
- **A fresh Wazuh agent reads only Application/Security/System.** Without the Sysmon and
  PowerShell channels the machine looks healthy and sends none of the telemetry the
  detections use; the role now adds them.
- **Joining a domain resets w32time to `NT5DS`.** The time settings therefore run
  after the join, not before, or the next converge redoes them. The timezone still runs
  before it, because Kerberos rejects clock skew over 5 minutes.
- **`ansible.windows.win_domain_membership` no longer exists**; the role uses
  `microsoft.ad.membership`.
- **The vaulted `dc_domain_admin_password` did not match the live domain
  `Administrator`** (`kinit` said "Password incorrect"; that value was only ever used at
  provision time). The live account was reset to the vaulted value on 2026-09-29, so the
  repo is the source of truth again. Samba's default 42-day password age would have
  silently broken the next rebuild's join, so the `dc` role now marks the domain
  `Administrator` (only that account) as never-expiring.

Login: `localadmin`, password `WsLab2026!` (lab-only — see SECURITY.md); SSH key auth
is added by the FirstLogonCommands for the role's transport. **If you change the
password here, update `scripts/.lab-secrets` / the windows role to match.**
