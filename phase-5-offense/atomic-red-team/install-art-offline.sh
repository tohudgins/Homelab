#!/usr/bin/env bash
# Offline install of Atomic Red Team onto ws-01 (Windows 11 ARM64, CORP segment).
#
# WHY OFFLINE: CORP has WAN egress (ping/TCP443 to the internet work), but ws-01's
# DNS is dc-01's Samba AD DNS, which has no external forwarder configured -- so
# `raw.githubusercontent.com` does not resolve on ws-01 and the upstream one-liner
#   IEX (IWR .../install-atomicredteam.ps1); Install-AtomicRedTeam -getAtomics
# fails at name resolution. We fetch the repos on the Mac (which has DNS) and push
# them over the existing SSH path (alias `ws-01`, ProxyJump rtr-01).
#
# ARM64 note: unlike SharpHound (x86-only native RPC assembly), ART is PowerShell +
# native OS commands, and its only binary dependency (powershell-yaml -> YamlDotNet)
# is architecture-neutral managed .NET, so it runs natively on Windows-on-ARM.
#
# Usage:  ./install-art-offline.sh [ssh_alias]      (default alias: ws-01)
set -euo pipefail

SSH_ALIAS="${1:-ws-01}"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
cd "$WORK"

echo "[*] Downloading repos..."
curl -sL -o invoke.tgz  "https://codeload.github.com/redcanaryco/invoke-atomicredteam/tar.gz/refs/heads/master"
curl -sL -o atomics.tgz "https://codeload.github.com/redcanaryco/atomic-red-team/tar.gz/refs/heads/master"
curl -sL -o psyaml.nupkg "https://www.powershellgallery.com/api/v2/package/powershell-yaml"

echo "[*] Extracting..."
tar xzf invoke.tgz
tar xzf atomics.tgz
mkdir -p psyaml && ( cd psyaml && unzip -oq ../psyaml.nupkg )

# CRITICAL: COPYFILE_DISABLE=1 stops macOS bsdtar from injecting AppleDouble "._*"
# resource-fork files. Without it, the module's psm1 dot-sources every Public\*.ps1
# INCLUDING the "._Foo.ps1" junk, and Import-Module dies with a parser error.
echo "[*] Building clean tarballs (no AppleDouble)..."
export COPYFILE_DISABLE=1
tar czf art-module.tgz  -C invoke-atomicredteam-master \
    Invoke-AtomicRedTeam.psd1 Invoke-AtomicRedTeam.psm1 Public Private LICENSE.txt README.md
tar czf atomics-only.tgz -C atomic-red-team-master atomics
( cd psyaml && tar czf ../psyaml.tgz powershell-yaml.psd1 powershell-yaml.psm1 lib LICENSE )

echo "[*] Transferring to ${SSH_ALIAS}..."
scp art-module.tgz atomics-only.tgz psyaml.tgz install-art-windows.ps1 \
    "${SSH_ALIAS}:C:/Users/localadmin/" 2>/dev/null || \
scp art-module.tgz atomics-only.tgz psyaml.tgz \
    "$(dirname "$0")/install-art-windows.ps1" "${SSH_ALIAS}:C:/Users/localadmin/"

echo "[*] Running Windows-side install/verify..."
ssh "${SSH_ALIAS}" 'powershell -NoProfile -ExecutionPolicy Bypass -File C:\Users\localadmin\install-art-windows.ps1'

echo "[*] Cleaning up transferred tarballs on ${SSH_ALIAS}..."
ssh "${SSH_ALIAS}" 'powershell -NoProfile -Command "Remove-Item C:\Users\localadmin\art-module.tgz,C:\Users\localadmin\atomics-only.tgz,C:\Users\localadmin\psyaml.tgz,C:\Users\localadmin\install-art-windows.ps1 -Force -ErrorAction SilentlyContinue"'

echo "[+] Done. Fire a test:  ssh ${SSH_ALIAS} 'powershell -c \"Invoke-AtomicTest T1033 -TestNumbers 1\"'"
