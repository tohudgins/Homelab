# fs-01 — unattended provisioning (Ubuntu Server 26.04 ARM64)

fs-01 is the CORP Samba file server (domain member, not a DC) with the deliberately
weak share/ACL config that gives BloodHound a real lateral-movement path. It was
originally **built interactively**; these files bring it up to the same
build-from-blank standard as dmz-01/scan-01/misp-01.

> Authored 2026-09-28 from the proven dmz-01 template (same ISO, Fusion, ARM64).
> Only host-specific data differs from that working template. **Pending a from-blank
> build-verify**; the `fileserver` role that configures the running host is exercised
> continuously by the purple-team credential-theft path.

## What's here
| File | Purpose |
|---|---|
| `user-data` | Ubuntu autoinstall (cloud-init NoCloud): hostname, user + SSH key, **static CORP IP `10.10.10.20/24`**, install-time DNS 1.1.1.1, `poweroff` when done |
| `meta-data` | NoCloud instance metadata (instance-id / hostname) |
| `grub.cfg` | ISO grub with `autoinstall ds=nocloud` + serial console |

## Build steps (host = macOS, VMware Fusion, ARM64)

```bash
ISO=isos/ubuntu-26.04-live-server-arm64.iso

# 1. Seed ISO — volume label MUST be CIDATA for cloud-init's NoCloud datasource
mkdir seed && cp user-data meta-data seed/
xorriso -as mkisofs -output isos/fs-01-seed.iso -volid CIDATA -joliet -rock seed

# 2. Remaster the Ubuntu ISO with the autoinstall grub.cfg (replay preserves EFI boot)
xorriso -indev "$ISO" -outdev isos/ubuntu-fs01-auto.iso \
        -boot_image any replay -map grub.cfg /boot/grub/grub.cfg

# 3. Create the VM shell + boot it (create-vm.sh writes the vmx/disk/NICs/serial):
./scripts/create-vm.sh --name fs-01 --os arm-ubuntu-64 --cpus 2 --mem 3072 \
    --disk 40 --net vmnet3 \
    --iso isos/ubuntu-fs01-auto.iso --seed isos/fs-01-seed.iso --start
# autoinstall runs unattended and powers the VM off when finished.

# 4. Detach both CDs (set the CD devices startConnected FALSE) and boot from disk.
```

## After first boot
`ansible-playbook fileserver.yml` domain-joins fs-01 and lays down the weak share.
See `../ansible/roles/fileserver/`.

Login: user `tohudgins`, key-based (homelab key) primary; console password fallback
`FsLab2026!` (lab-only, isolated host — see SECURITY.md).

## Gotchas
Same ARM64/Fusion family as dmz-01 — see `../dmz-01/README.md`.
