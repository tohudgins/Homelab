# ws-01 — unattended provisioning (Windows 11 arm64, 25H2)

ws-01 is the domain-joined Windows victim workstation. Windows uses an
**autounattend.xml** answer file (not cloud-init/preseed). This reproduces the base
OS + a local admin + OpenSSH so the `windows` Ansible role can take over **over SSH**
(its transport). Sysmon, PowerShell Script-Block Logging and the Wazuh agent are all
applied by that role, not here.

> Authored + **partially build-verified** 2026-09-28. Where it stands, precisely:
> - **XML**: well-formed, CI-validated, standard Win11 unattend schema.
> - **Edition name CONFIRMED**: `wiminfo` on this ISO's `sources/install.wim` lists
>   index 1 Home / 2 Home SL / **3 Windows 11 Pro** — so `/IMAGE/NAME = "Windows 11 Pro"`
>   matches exactly and Setup won't stall on edition selection. (The ISO uses
>   `install.wim`, not `.esd`.)
> - **create-vm.sh pipeline**: proven end-to-end on the two Linux hosts.
> - **Boots + applies the image headless — VERIFIED.** The default ISO stalls at
>   VMware UEFI's un-dismissable "Press any key to boot from CD" prompt (a from-blank
>   VM sat 39 min, vmdk still 8 MB). Fixed by rebuilding a **no-prompt ISO**: mount the
>   UDF ISO (`hdiutil`), copy the tree out, split `install.wim` under 4 GB with
>   `wimlib-imagex split ... install.swm 3800` (so plain ISO9660 works — this xorriso
>   has no `-udf`), then `xorriso -as mkisofs -iso-level 3 -J -joliet-long -e
>   efi/microsoft/boot/efisys_noprompt.bin -no-emul-boot`. With that ISO the VM booted
>   headless with **no keypress** and Windows Setup applied the full image (vmdk grew
>   8 MB → 13 GB) — confirmed live.
> - **OOBE completion NOT confirmed headlessly.** After the image applied, the VM ran
>   ~1 hr with continuous disk writes (not frozen) but never brought networking up, so
>   SSH never answered. Win11 25H2 OOBE likely needs a step the answer file doesn't
>   fully suppress, and it can't be seen/dismissed on a truly headless VM
>   (`captureScreen` needs guest tools that don't exist mid-Setup; Windows has no serial
>   console). **To confirm the last mile**: run it once in the Fusion GUI (attach the
>   headless VM in the Fusion library to watch OOBE), or iterate the OOBE section
>   (e.g. a `BypassNRO`/network-skip tweak) with the screen visible. SSH from the
>   FirstLogonCommands coming up is the success signal.

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
