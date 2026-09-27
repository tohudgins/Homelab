#!/usr/bin/env bash
# ===========================================================================
# segmentation-test.sh — probe the firewall segmentation matrix live and diff
# each cell against the expected policy in segmentation-test-matrix.md (which is
# itself derived from the enforced nftables ruleset).
#
# Run from the operator host (uses the ~/.ssh/config aliases), lab up. Add the
# REDTEAM box for the RED rows:  make up PROFILE=services  + start atk-01.
#
# How a cell is judged: from the SOURCE host we probe a TARGET host:port with a
# 2s-timeout TCP connect. Three outcomes, and the firewall vs the service are
# told apart by WHICH one happens:
#   connected      -> ALLOW (and something is listening)
#   refused fast   -> ALLOW (packet reached the host; port just closed -> RST)
#   timed out (2s) -> DROP  (silently filtered by rtr-01's default-deny)
# So "refused" and "connected" both prove the path is permitted; only a timeout
# proves it's blocked. That filtered-vs-closed distinction is the whole test.
# ===========================================================================
set -u

TIMEOUT=2
pass=0
fail=0

# probe SRC_ALIAS TARGET_IP PORT  ->  echoes allow|drop|error
probe() {
    local src="$1" ip="$2" port="$3"
    # bash /dev/tcp on the remote host; time-box it so a filtered port returns
    # "drop" instead of hanging. Exit 124 = timeout(1) killed it = filtered.
    ssh -o ConnectTimeout=5 -o BatchMode=yes "$src" \
        "timeout $TIMEOUT bash -c 'exec 3<>/dev/tcp/$ip/$port' 2>/dev/null; echo \$?" \
        2>/dev/null | tail -1
}

# check DESC SRC TARGET PORT EXPECT(allow|drop)
check() {
    local desc="$1" src="$2" ip="$3" port="$4" expect="$5"
    local rc got
    rc="$(probe "$src" "$ip" "$port")"
    case "$rc" in
        0)   got="allow" ;;          # connected
        124) got="drop"  ;;          # timed out -> filtered
        "")  got="error" ;;          # ssh itself failed (host down?)
        *)   got="allow" ;;          # non-zero fast = RST = reached host, port closed
    esac
    if [ "$got" = "error" ]; then
        printf '  [ERR ] %-42s (source %s unreachable)\n' "$desc" "$src"
        fail=$((fail + 1))
    elif [ "$got" = "$expect" ]; then
        printf '  [PASS] %-42s %s\n' "$desc" "$got"
        pass=$((pass + 1))
    else
        printf '  [FAIL] %-42s expected %s, got %s\n' "$desc" "$expect" "$got"
        fail=$((fail + 1))
    fi
}

echo "== Segmentation matrix — live probe =="

# The headline control: the attacker box must not reach the SIEM.
check "REDTEAM->SOC 1514 (must be blocked)" atk-01  10.10.30.10 1514 drop
check "REDTEAM->SOC 55000 (must be blocked)" atk-01 10.10.30.10 55000 drop
# REDTEAM into the attack surface is permitted.
check "REDTEAM->CORP 445 (attack surface)"  atk-01  10.10.10.10 445  allow
check "REDTEAM->DMZ 3000 (Juice Shop)"      atk-01  10.10.20.10 3000 allow
# CORP->SOC only on the agent ports.
check "CORP->SOC 1514 (agent data)"         dc-01   10.10.30.10 1514 allow
check "CORP->SOC 22 (must be blocked)"      dc-01   10.10.30.10 22   drop
# DMZ must not pivot into the domain.
check "DMZ->CORP 445 (must be blocked)"     dmz-01  10.10.10.10 445  drop
check "DMZ->SOC 1514 (agent data)"          dmz-01  10.10.30.10 1514 allow
# SOC is the trusted plane; reaches agents.
check "SOC->CORP 22 (manager reach)"        siem-01 10.10.10.10 22   allow

echo ""
echo "== $pass passed, $fail failed/errored =="
[ "$fail" -eq 0 ]
