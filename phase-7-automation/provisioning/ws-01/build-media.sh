#!/usr/bin/env bash
# ===========================================================================
# build-media.sh — build the two ISOs ws-01's headless Windows install needs.
#
#   isos/Win11_25H2_English_Arm64_noprompt.iso   the stock install ISO, remastered so
#       UEFI boots it with NO "Press any key to boot from CD" prompt (that prompt is
#       un-dismissable on a headless VM), and install.wim split under 4 GB so plain
#       ISO9660 can hold it (this xorriso has no -udf).
#   isos/ws-01-answer.iso                        label WSANSWER: autounattend.xml +
#       firstlogon.ps1 + the pinned Win32-OpenSSH ARM64 MSI. Hermetic on purpose —
#       the CORP segment has no DNS/DHCP of its own, so the guest must not need the
#       internet to become reachable.
#
# Host = macOS (hdiutil, xorriso, wimlib-imagex from Homebrew). Idempotent: an
# existing output is kept; delete it to rebuild. Needs ~20 GB scratch space.
# ===========================================================================
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../../.." && pwd)"
ISOS="$REPO/isos"
SRC="$ISOS/Win11_25H2_English_Arm64_v2.iso"
NOPROMPT="$ISOS/Win11_25H2_English_Arm64_noprompt.iso"
ANSWER="$ISOS/ws-01-answer.iso"

# Pinned Win32-OpenSSH release. Bump both together.
SSH_TAG="10.0.0.0p2-Preview"
SSH_MSI="OpenSSH-ARM64-v10.0.0.0.msi"
SSH_URL="https://github.com/PowerShell/Win32-OpenSSH/releases/download/$SSH_TAG/$SSH_MSI"

for t in hdiutil xorriso wimlib-imagex curl rsync; do
    command -v "$t" >/dev/null || { echo "! missing tool: $t" >&2; exit 1; }
done
[ -f "$SRC" ] || { echo "! source ISO not found: $SRC" >&2; exit 1; }

WORK="$(mktemp -d "${TMPDIR:-/tmp}/ws01-media.XXXXXX")"
MNT="$WORK/mnt"
mkdir -p "$MNT"
cleanup() {
    hdiutil detach "$MNT" >/dev/null 2>&1 || true
    chmod -R u+w "$WORK" 2>/dev/null || true
    rm -rf "$WORK"
}
trap cleanup EXIT

# --- 1. no-prompt install ISO ----------------------------------------------
if [ -f "$NOPROMPT" ]; then
    echo "= keep $NOPROMPT"
else
    echo "+ mounting $SRC"
    hdiutil attach -readonly -nobrowse -mountpoint "$MNT" "$SRC" >/dev/null
    TREE="$WORK/tree"
    echo "+ copying tree (~7 GB)"
    rsync -a "$MNT/" "$TREE/"
    hdiutil detach "$MNT" >/dev/null
    chmod -R u+w "$TREE"

    echo "+ splitting install.wim (<4 GB parts)"
    wimlib-imagex split "$TREE/sources/install.wim" "$TREE/sources/install.swm" 3800 >/dev/null
    rm -f "$TREE/sources/install.wim"

    [ -f "$TREE/efi/microsoft/boot/efisys_noprompt.bin" ] \
        || { echo "! efisys_noprompt.bin missing from the source ISO" >&2; exit 1; }

    echo "+ mastering $NOPROMPT"
    xorriso -as mkisofs -iso-level 3 -J -joliet-long -R -V WIN11_NOPROMPT \
        -e efi/microsoft/boot/efisys_noprompt.bin -no-emul-boot \
        -o "$NOPROMPT" "$TREE" >/dev/null 2>&1
    rm -rf "$TREE"
fi

# --- 2. answer ISO ---------------------------------------------------------
# Rebuilt every run: it is small and its inputs change.
SEED="$WORK/seed"
mkdir -p "$SEED"
cp "$HERE/autounattend.xml" "$HERE/firstlogon.ps1" "$SEED/"

MSI_CACHE="$ISOS/$SSH_MSI"
if [ ! -f "$MSI_CACHE" ]; then
    echo "+ fetching $SSH_MSI"
    curl -fsSL -o "$MSI_CACHE" "$SSH_URL"
fi
cp "$MSI_CACHE" "$SEED/openssh-arm64.msi"

echo "+ mastering $ANSWER"
rm -f "$ANSWER"
xorriso -as mkisofs -volid WSANSWER -joliet -rock -o "$ANSWER" "$SEED" >/dev/null 2>&1

echo "done:"
ls -lh "$NOPROMPT" "$ANSWER"
