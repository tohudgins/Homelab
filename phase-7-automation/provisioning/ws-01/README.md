# ws-01 — unattended provisioning (Windows 11 arm64, 25H2)

ws-01 is the domain-joined Windows victim workstation. Windows uses an
**autounattend.xml** answer file (not cloud-init/preseed). This reproduces the base
OS + a local admin + OpenSSH so the `windows` Ansible role can take over **over SSH**
(its transport). Sysmon, PowerShell Script-Block Logging and the Wazuh agent are all
applied by that role, not here.

> **Build-verified from a blank disk, 2026-09-29.** A fresh `create-vm.sh` VM went blank →
> Setup → OOBE → AutoLogon → `firstlogon.ps1` (log ends `authorized key installed - DONE`)
> → `ssh localadmin@10.10.10.50` through rtr-01 answered (`ws-01\localadmin`,
> Windows 10.0.26200, default shell cmd as the `windows` role expects). Verified with
> the Fusion GUI console open and nobody touching it; it has **not** been re-run
> headless. The `windows` role itself was not re-run against the rebuilt VM.
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

## After first boot
`ansible-playbook windows.yml` (over SSH) installs Sysmon, PS Script-Block Logging
and the Wazuh agent. See `../ansible/roles/windows/`. Then domain-join per the AD docs.

Login: `localadmin`, password `WsLab2026!` (lab-only — see SECURITY.md); SSH key auth
is added by the FirstLogonCommands for the role's transport. **If you change the
password here, update `scripts/.lab-secrets` / the windows role to match.**
