# dmz-01 — unattended provisioning (Ubuntu Server 26.04 ARM64)

dmz-01 is the DMZ segment's vulnerable-web-app host. Unlike dc-01/siem-01/fs-01
(built interactively), it was installed **fully headless** via Ubuntu autoinstall,
so the base VM is reproducible from these files — the from-scratch counterpart to
the Ansible roles that configure the already-running hosts.

## What's here
| File | Purpose |
|---|---|
| `user-data` | Ubuntu autoinstall config (cloud-init NoCloud): hostname, user + SSH key, **static DMZ IP `10.10.20.10/24`**, `poweroff` when done |
| `meta-data` | NoCloud instance metadata (instance-id / hostname) |
| `grub.cfg` | ISO grub with `autoinstall ds=nocloud` + serial console added, so the installer runs unattended instead of prompting |

## Build steps (host = macOS, VMware Fusion, ARM64)

```bash
ISO=isos/ubuntu-26.04-live-server-arm64.iso

# 1. Seed ISO — MUST be volume-label CIDATA for cloud-init's NoCloud datasource
mkdir seed && cp user-data meta-data seed/
xorriso -as mkisofs -output isos/dmz-01-seed.iso -volid CIDATA -joliet -rock seed

# 2. Remaster the Ubuntu ISO with the autoinstall grub.cfg (replay preserves EFI boot)
xorriso -indev "$ISO" -outdev isos/ubuntu-dmz01-auto.iso \
        -boot_image any replay -map grub.cfg /boot/grub/grub.cfg

# 3. Create the VM (1 vCPU / 2 GB / 20 GB nvme, vmxnet3 on vmnet4 = DMZ) with BOTH
#    ISOs attached (installer + CIDATA seed) and a file-backed serial console, then:
vmrun start dmz-01.vmx nogui
# autoinstall runs unattended and powers the VM off when finished.

# 4. Detach both CDs (set sata0:1/sata0:2 startConnected FALSE) and boot from disk.
```

## Gotchas (ARM64 / Fusion, same family as the atk-01 build)
- **The `autoinstall` kernel param is mandatory** — without it Subiquity stops at
  an interactive "Continue with autoinstall?" prompt, defeating headless install.
  It's added by remastering the ISO's `/boot/grub/grub.cfg`.
- **Seed volume label must be `CIDATA`** or cloud-init's NoCloud datasource never
  finds the config and the install falls back to interactive.
- **`shutdown: poweroff`** (not reboot) so the installer can't loop back into the
  still-attached CD — detach the CDs before the first real boot.
- **`match: {name: "en*"}`** in the netplan section — Ubuntu names the vmxnet3 NIC
  `enp2s0`, and matching by prefix keeps the config independent of the exact name.

## After first boot
Docker + the Juice Shop container and the Wazuh agent are layered on post-boot
(see `../ansible/roles/dmz/` once built) — the autoinstall deliberately keeps the
base image minimal.

Login: user `tohudgins`, key-based (homelab key) primary; password auth also on.
