#!/usr/bin/env bash
# ===========================================================================
# fetch-installers.sh — stage the Windows endpoint installers the `windows` Ansible
# role pushes to ws-01, so a rebuild needs no internet on the guest.
#
#   installers/wazuh-agent-<ver>.msi   Wazuh agent (x86 build; runs under ARM64
#                                      emulation — same as the original ws-01)
#   installers/Sysmon64a.exe           Sysinternals Sysmon, ARM64 build
#
# Same pattern as phase-4-detection/velociraptor/binaries/: fetched from the
# vendor, checksum-pinned, git-ignored, deployed by the role from the control node.
# Idempotent: existing files with a matching checksum are kept.
#
# Sysinternals only publishes an unversioned "latest" URL, so the Sysmon pin is on
# that zip's SHA-256. When Microsoft ships a new build this fails on purpose: review
# it, then update SYSMON_ZIP_SHA256 here.
# ===========================================================================
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
OUT="$HERE/installers"
mkdir -p "$OUT"

# Keep in step with wazuh_agent_version in the fileserver/dmz roles and the manager.
WAZUH_VER="4.14.7-1"
WAZUH_URL="https://packages.wazuh.com/4.x/windows/wazuh-agent-$WAZUH_VER.msi"
WAZUH_SHA256="e967f36b75589d6210244fd58239c7021fa53a77c38d92315c3b3bd115002ede"

SYSMON_URL="https://download.sysinternals.com/files/Sysmon.zip"
SYSMON_ZIP_SHA256="00ecf1b46aec99299d3ae0bca79dc621458bd014b20b509d7c5c8e8c8611aa54"

sha() { shasum -a 256 "$1" | cut -d' ' -f1; }

fetch() { # url dest sha256
    local url="$1" dest="$2" want="$3"
    if [ -f "$dest" ] && [ "$(sha "$dest")" = "$want" ]; then
        echo "= keep $(basename "$dest")"
        return 0
    fi
    echo "+ fetching $(basename "$dest")"
    curl -fsSL -o "$dest.part" "$url"
    local got; got="$(sha "$dest.part")"
    if [ "$got" != "$want" ]; then
        rm -f "$dest.part"
        echo "! checksum mismatch for $(basename "$dest")" >&2
        echo "  want $want" >&2
        echo "  got  $got" >&2
        exit 1
    fi
    mv "$dest.part" "$dest"
}

fetch "$WAZUH_URL" "$OUT/wazuh-agent-$WAZUH_VER.msi" "$WAZUH_SHA256"

if [ -f "$OUT/Sysmon64a.exe" ]; then
    echo "= keep Sysmon64a.exe"
else
    fetch "$SYSMON_URL" "$OUT/Sysmon.zip" "$SYSMON_ZIP_SHA256"
    unzip -o -q "$OUT/Sysmon.zip" Sysmon64a.exe -d "$OUT"
    rm -f "$OUT/Sysmon.zip"
    echo "+ extracted Sysmon64a.exe"
fi

ls -lh "$OUT"
