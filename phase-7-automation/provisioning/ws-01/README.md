# ws-01 — unattended provisioning (Windows 11 arm64, 25H2)

ws-01 is the domain-joined Windows victim workstation. Windows uses an
**autounattend.xml** answer file (not cloud-init/preseed). This reproduces the base
OS + a local admin + OpenSSH so the `windows` Ansible role can take over **over SSH**
(its transport). Sysmon, PowerShell Script-Block Logging and the Wazuh agent are all
applied by that role, not here.

> Authored + **statically verified** 2026-09-28; one thing remains, and it's an
> environment limitation, not a defect in this file:
> - **XML**: well-formed, CI-validated, standard Win11 unattend schema.
> - **Edition name CONFIRMED**: `wiminfo` on this ISO's `sources/install.wim` lists
>   index 1 Home / 2 Home SL / **3 Windows 11 Pro** — so `/IMAGE/NAME = "Windows 11 Pro"`
>   matches exactly and Setup won't stall on edition selection. (The ISO uses
>   `install.wim`, not `.esd`.)
> - **create-vm.sh pipeline**: proven end-to-end on the two Linux hosts.
> - **NOT yet run to completion**, because a *headless* from-blank Windows install on
>   this setup is blocked before Setup even starts: VMware's UEFI shows the Windows
>   **"Press any key to boot from CD or DVD…"** prompt, which times out to no-boot with
>   no way to send that keystroke headlessly (confirmed 2026-09-28: a from-blank VM sat
>   39 min with the vmdk still at 8 MB — Setup never wrote a byte). The usual headless
>   fix — rebuilding the ISO with `efisys_noprompt.bin` — isn't doable with Mac tooling
>   here because this ISO's payload is **UDF**, which `xorriso` can't rewrite (it sees
>   only the ISO9660 stub). **To confirm the last mile**: open this VM once in the Fusion
>   GUI and press a key at that prompt (or rebuild the ISO with Windows `oscdimg
>   -bootdata:...efisys_noprompt.bin`); Setup then runs fully unattended off the answer
>   CD. SSH (from the FirstLogonCommands) coming up is the success signal.

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
