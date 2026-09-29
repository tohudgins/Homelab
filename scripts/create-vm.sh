#!/usr/bin/env bash
# ===========================================================================
# create-vm.sh — create a VMware Fusion (Apple Silicon / ARM64) VM from code.
#
# Codifies the manual "Create the VM (N vCPU / M GB / D GB, vmxnet3 on vmnetX)"
# step every provisioning/<host>/README.md used to describe by hand. Pair it with
# a host's provisioning seed to go blank-disk -> running from the repo:
#
#   ./create-vm.sh --name dc-01 --os arm-ubuntu-64 --cpus 2 --mem 4096 \
#       --disk 40 --net vmnet3 \
#       --iso isos/ubuntu-dc01-auto.iso --seed isos/dc-01-seed.iso --start
#
# --net takes a comma-separated list, one entry per NIC, in order:
#   "nat"     -> Fusion NAT (WAN uplink)
#   "vmnetN"  -> a custom host-only/segment network
# e.g. rtr-01 (WAN + 4 segments): --net nat,vmnet3,vmnet4,vmnet5,vmnet6
#
# --extra-iso attaches a third CD (e.g. isos/vmware-arm64-drivers.iso, which ws-01's
# first-logon script installs to get the vmxnet3 driver).
#
# Modelled field-for-field on the lab's existing hand-built ARM VMs (firmware=efi,
# nvme system disk, vmxnet3 NICs, file-backed serial console for headless
# autoinstall). It refuses to clobber an existing VM. Does NOT install an OS —
# that's the seed ISO's job; this builds the shell and (optionally) powers it on.
# ===========================================================================
set -euo pipefail

FUSION="/Applications/VMware Fusion.app/Contents"
VMRUN="$FUSION/Public/vmrun"
VDISK="$FUSION/Library/vmware-vdiskmanager"
VMROOT="${VMROOT:-$HOME/Virtual Machines.localized}"

name="" os="arm-ubuntu-64" cpus="2" mem="4096" disk="40" net="vmnet3"
iso="" seed="" extra="" start="no" ui="nogui"

usage() {
    sed -n '2,25p' "$0" | sed 's/^# \{0,1\}//'
    exit "${1:-0}"
}

while [ $# -gt 0 ]; do
    case "$1" in
        --name)  name="$2"; shift 2 ;;
        --os)    os="$2"; shift 2 ;;
        --cpus)  cpus="$2"; shift 2 ;;
        --mem)   mem="$2"; shift 2 ;;
        --disk)  disk="$2"; shift 2 ;;
        --net)   net="$2"; shift 2 ;;
        --iso)   iso="$2"; shift 2 ;;
        --seed)  seed="$2"; shift 2 ;;
        --extra-iso) extra="$2"; shift 2 ;;
        --start) start="yes"; shift ;;
        --gui)   ui="gui"; shift ;;
        -h|--help) usage 0 ;;
        *) echo "unknown arg: $1" >&2; usage 2 ;;
    esac
done

[ -n "$name" ] || { echo "! --name is required" >&2; usage 2; }
[ -x "$VMRUN" ]  || { echo "! vmrun not found at $VMRUN" >&2; exit 1; }
[ -x "$VDISK" ]  || { echo "! vmware-vdiskmanager not found at $VDISK" >&2; exit 1; }

# Resolve ISO paths relative to the repo root (this script lives in scripts/).
REPO="$(cd "$(dirname "$0")/.." && pwd)"
resolve() { case "$1" in /*) echo "$1" ;; "") echo "" ;; *) echo "$REPO/$1" ;; esac; }
iso="$(resolve "$iso")"; seed="$(resolve "$seed")"
[ -z "$iso" ]  || [ -f "$iso" ]  || { echo "! installer ISO not found: $iso" >&2; exit 1; }
[ -z "$seed" ] || [ -f "$seed" ] || { echo "! seed ISO not found: $seed" >&2; exit 1; }
extra="$(resolve "$extra")"
[ -z "$extra" ] || [ -f "$extra" ] || { echo "! extra ISO not found: $extra" >&2; exit 1; }

vmdir="$VMROOT/$name.vmwarevm"
vmx="$vmdir/$name.vmx"
vmdk="$vmdir/$name.vmdk"
[ -e "$vmdir" ] && { echo "! $vmdir already exists — refusing to clobber" >&2; exit 1; }

echo "Creating $name  ($os, ${cpus} vCPU / ${mem} MB / ${disk} GB, NICs: $net)"
mkdir -p "$vmdir"

# System disk. Growable single-file (-t 0); adapter hint in the descriptor is
# harmless — the vmx below attaches it via nvme0, matching the lab's real VMs.
"$VDISK" -c -s "${disk}GB" -a lsilogic -t 0 "$vmdk" >/dev/null

# --- write the vmx --------------------------------------------------------
{
cat <<VMX
.encoding = "UTF-8"
config.version = "8"
virtualHW.version = "22"
virtualHW.productCompatibility = "hosted"
displayName = "$name"
firmware = "efi"
guestOS = "$os"
numvcpus = "$cpus"
cpuid.coresPerSocket = "1"
memsize = "$mem"
powerType.powerOff = "soft"
powerType.powerOn = "soft"
powerType.suspend = "soft"
powerType.reset = "soft"
pciBridge0.present = "TRUE"
pciBridge4.present = "TRUE"
pciBridge4.virtualDev = "pcieRootPort"
pciBridge4.functions = "8"
pciBridge5.present = "TRUE"
pciBridge5.virtualDev = "pcieRootPort"
pciBridge5.functions = "8"
pciBridge6.present = "TRUE"
pciBridge6.virtualDev = "pcieRootPort"
pciBridge6.functions = "8"
pciBridge7.present = "TRUE"
pciBridge7.virtualDev = "pcieRootPort"
pciBridge7.functions = "8"
ehci.present = "TRUE"
nvme0.present = "TRUE"
nvme0:0.present = "TRUE"
nvme0:0.fileName = "$name.vmdk"
sata0.present = "TRUE"
serial0.present = "TRUE"
serial0.fileType = "file"
serial0.fileName = "$name-serial.log"
serial0.yieldOnMsrRead = "TRUE"
VMX

# Windows guests need a USB controller AND its virtual HID (keyboard/mouse) device:
# WinPE/Setup and OOBE have no other input path, so without these the console is
# unusable (Linux hosts install over serial). The hub/hid/video entries mirror what
# Fusion writes into a GUI-created Windows VM.
case "$os" in
    *windows*) cat <<VMX
usb.present = "TRUE"
usb_xhci.present = "TRUE"
vmci0.present = "TRUE"
usb_xhci:4.present = "TRUE"
usb_xhci:4.deviceType = "video"
usb_xhci:4.port = "4"
usb_xhci:4.parent = "-1"
usb_xhci:5.present = "TRUE"
usb_xhci:5.deviceType = "hid"
usb_xhci:5.port = "5"
usb_xhci:5.parent = "-1"
usb_xhci:6.present = "TRUE"
usb_xhci:6.deviceType = "hub"
usb_xhci:6.speed = "2"
usb_xhci:6.port = "6"
usb_xhci:6.parent = "-1"
usb_xhci:7.present = "TRUE"
usb_xhci:7.deviceType = "hub"
usb_xhci:7.speed = "4"
usb_xhci:7.port = "7"
usb_xhci:7.parent = "-1"
VMX
    ;;
esac

# CD drives: installer on sata0:0, optional seed on the next, optional extra after.
cd=0
if [ -n "$iso" ]; then
cat <<VMX
sata0:$cd.present = "TRUE"
sata0:$cd.deviceType = "cdrom-image"
sata0:$cd.fileName = "$iso"
sata0:$cd.startConnected = "TRUE"
VMX
cd=$((cd + 1))
fi
if [ -n "$seed" ]; then
cat <<VMX
sata0:$cd.present = "TRUE"
sata0:$cd.deviceType = "cdrom-image"
sata0:$cd.fileName = "$seed"
sata0:$cd.startConnected = "TRUE"
VMX
cd=$((cd + 1))
fi
if [ -n "$extra" ]; then
cat <<VMX
sata0:$cd.present = "TRUE"
sata0:$cd.deviceType = "cdrom-image"
sata0:$cd.fileName = "$extra"
sata0:$cd.startConnected = "TRUE"
VMX
fi

# NICs, in the order given to --net.
i=0
IFS=','
for n in $net; do
cat <<VMX
ethernet$i.present = "TRUE"
ethernet$i.virtualDev = "vmxnet3"
ethernet$i.linkStatePropagation.enable = "TRUE"
VMX
if [ "$n" = "nat" ]; then
    echo "ethernet$i.connectionType = \"nat\""
else
    echo "ethernet$i.connectionType = \"custom\""
    echo "ethernet$i.vnet = \"$n\""
fi
i=$((i + 1))
done
unset IFS
} > "$vmx"

echo "  wrote $vmx"
echo "  wrote $vmdk (${disk} GB, growable)"

if [ "$start" = "yes" ]; then
    echo "Starting $name ($ui) — autoinstall will run from the seed ISO."
    "$VMRUN" start "$vmx" "$ui"
else
    echo "Not started (pass --start to boot). Start later with:"
    echo "  '$VMRUN' start '$vmx' nogui"
fi
