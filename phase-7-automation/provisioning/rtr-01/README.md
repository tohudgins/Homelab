# rtr-01 — unattended provisioning (Debian 13 arm64, netinst preseed)

rtr-01 is the lab's hand-built router/firewall (nftables, dnsmasq, chrony, inline
Suricata + Zeek). Unlike the Ubuntu hosts it uses the **Debian installer + preseed**
(not cloud-init autoinstall). These files make the base OS reproducible from the
repo; the `router` role does all the actual router configuration afterwards.

> Authored 2026-09-28. **Build-verified from a genuinely blank VM the same day**:
> remastered ISO → `create-vm.sh` → fully unattended install → clean auto-poweroff →
> booted the installed disk → SSH in as root with the homelab key → confirmed hostname
> `rtr-01`, Debian 13, `PermitRootLogin prohibit-password`, sshd active. (The verify
> also caught the `finish-install/reboot_in_progress note` bug now fixed in the
> preseed.) The `router` role that configures this host is separately verified idempotent.

## What's here
| File | Purpose |
|---|---|
| `preseed.cfg` | Debian-installer answers: hostname, root-only key-based login, guided partitioning, minimal base + SSH, `poweroff` when done, late_command drops the SSH key + sets `PermitRootLogin prohibit-password` |
| `grub.cfg` | Installer grub: `auto=true priority=critical preseed/file=/cdrom/preseed.cfg` + serial console, using the ISO's real `/install.a64/` kernel paths |

## Networking note (5 NICs)
The preseed configures **only eth0 = WAN** (Fusion NAT, DHCP) so the installer has
connectivity to fetch packages. The four internal-segment NICs (CORP/DMZ/SOC/REDTEAM
on vmnet3/4/5/6) are created by `create-vm.sh --net nat,vmnet3,vmnet4,vmnet5,vmnet6`
and addressed by the `router` role — not here.

## Build steps (host = macOS, VMware Fusion, ARM64)

```bash
ISO=isos/debian-13.6.0-arm64-netinst.iso

# 1. Remaster the netinst ISO: inject preseed.cfg at the root and swap in the
#    autoinstall grub.cfg (replay preserves EFI boot).
xorriso -indev "$ISO" -outdev isos/debian-rtr01-auto.iso \
        -map preseed.cfg /preseed.cfg \
        -boot_image any replay -map grub.cfg /boot/grub/grub.cfg

# 2. Create the VM (2 vCPU / 4 GB / 40 GB, WAN + 4 segment NICs) and boot it:
./scripts/create-vm.sh --name rtr-01 --os arm-debian13-64 --cpus 2 --mem 4096 \
    --disk 40 --net nat,vmnet3,vmnet4,vmnet5,vmnet6 \
    --iso isos/debian-rtr01-auto.iso --start
# the preseed runs unattended and powers the VM off when finished.

# 3. Detach the CD (set the CD device startConnected FALSE) and boot from disk.
```

## After first boot
`ansible-playbook router.yml` builds the firewall, DHCP/DNS, NTP and NSM sensors.
See `../ansible/roles/router/`.

Login: `root`, key-based (homelab key) only; console password fallback `RtrLab2026!`
(lab-only, isolated host — see SECURITY.md).
