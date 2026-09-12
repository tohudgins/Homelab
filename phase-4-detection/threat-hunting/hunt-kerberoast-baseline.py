#!/usr/bin/env python3
# ===========================================================================
# hunt-kerberoast-baseline.py — hunt a TARGETED Kerberoast by RARITY, not volume.
#
# HYPOTHESIS: rule 100031 (detection-catalog.md #3) keys on VOLUME — 3+ TGS-REQs
# from one account in 60s. A patient attacker who has already done recon and
# knows exactly which SPN is worth cracking requests ONE ticket for ONE SPN and
# produces zero alerts (confirmed live, detection-catalog.md's evasion note: "a
# single targeted request is indistinguishable from a legitimate client
# requesting its one normal ticket"). But that framing undersells what's
# actually normal: an ordinary domain user has essentially NO reason to ever
# request a TGS for a *service* SPN directly (that happens transparently when
# they use the service, and even then it's the service's own client doing it,
# not an interactive `kinit`/`kvno`/impacket call) — so the (account, SPN) PAIR
# itself, not the request count, is the rare event worth ranking. Same "the
# least-frequent occurrence is the most interesting" idea as hunt-rare-process.py,
# applied to Kerberos ticket requests instead of process execution.
#
# METHOD: pull every "KDC Authorization" TGS-REQ event from the Wazuh full-event
# archive, stack-count by the (account, SPN) pair across the whole archive, and
# show the pairs seen exactly once — the same "singleton" signal hunt-rare-
# process.py uses, just on a different telemetry stream. A pair seen many times
# is an account's own routine service ticket; a pair seen once, especially for
# an account that doesn't otherwise touch that SPN, is what a targeted roast
# looks like from the wire's point of view.
#
# DATA SOURCE: same prerequisite as hunt-rare-process.py — Wazuh only alerts on
# rule-matched events, so a single quiet TGS-REQ that never crosses 100031's
# threshold is invisible in alerts.json. <logall_json>yes</logall_json> (already
# enabled for Hunt B) streams every event to archives.json, this hunt's input.
#
#   ./hunt-kerberoast-baseline.py                # fetch dc-01 KDC events live
#   ./hunt-kerberoast-baseline.py archives.json  # analyze a local copy
#   cat archives.json | ./hunt-kerberoast-baseline.py -
# ===========================================================================
import json
import subprocess
import sys

SIEM_SSH = "siem-01"
ARCHIVE = "/var/ossec/logs/archives/archives.json"


def load_events(source):
    """Return raw JSON-lines text of archive events, pre-filtered to KDC Authorization."""
    if source == "-":
        return sys.stdin.read()
    if source:
        return open(source).read()
    # live: pre-filter on the SIEM to the type this hunt needs (archives.json
    # holds every event from every agent — no point shipping all of it over SSH)
    remote = f"sudo grep -a '\"type\":\"KDC Authorization\"' {ARCHIVE} 2>/dev/null"
    r = subprocess.run(["ssh", "-o", "ConnectTimeout=15", SIEM_SSH, remote],
                       capture_output=True, text=True, timeout=120)
    if r.returncode not in (0, 1):  # grep rc=1 = no matches, not an error
        sys.exit(f"could not read {ARCHIVE} on {SIEM_SSH}: {r.stderr.strip()}")
    return r.stdout


def tgs_requests(text):
    """Yield (account, spn, timestamp) for each real TGS-REQ event."""
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            e = json.loads(line)
        except json.JSONDecodeError:
            continue
        kdc = e.get("data", {}).get("KDC Authorization")
        if not kdc or "TGS-REQ" not in (kdc.get("authType") or ""):
            continue
        account = kdc.get("account")
        spn = kdc.get("serviceDescription", "?")
        yield (account, spn, e.get("timestamp", "?"))


def main():
    source = sys.argv[1] if len(sys.argv) > 1 else None
    events = list(tgs_requests(load_events(source)))
    if not events:
        sys.exit("no KDC Authorization TGS-REQ events found — is <logall_json> on "
                 "and has any Kerberos ticket activity happened against dc-01?")

    # Unattributed requests (account: null) can't be baselined per-account, but
    # they're not nothing — Samba logs "null" precisely when a Kerberoast tool's
    # own TGS-REQ fails to resolve a requester (detection-catalog.md #3, the
    # rule-100031 off-by-one investigation found this exact behavior). Surface
    # them separately rather than silently dropping them from the count.
    attributed = [(a, s, t) for a, s, t in events if a and a != "null"]
    unattributed = [(a, s, t) for a, s, t in events if not a or a == "null"]

    pair_count, pair_first_seen = {}, {}
    for account, spn, ts in attributed:
        key = (account, spn)
        pair_count[key] = pair_count.get(key, 0) + 1
        if key not in pair_first_seen or ts < pair_first_seen[key]:
            pair_first_seen[key] = ts

    accounts = sorted({a for a, _, _ in attributed})
    spns = sorted({s for _, s, _ in attributed})
    print(f"\n== Kerberoast baseline hunt :: {len(attributed)} attributed TGS-REQs "
          f"({len(unattributed)} unattributed), {len(accounts)} accounts, "
          f"{len(spns)} distinct SPNs, {len(pair_count)} distinct (account, SPN) pairs ==")
    print("   ranked by request count per pair — singletons first, the same rarity")
    print("   signal hunt-rare-process.py uses, applied to ticket requests\n")

    print(f"  {'count':>5}  {'account':<16} {'spn':<42} first seen")
    print("  " + "-" * 100)
    for (account, spn), n in sorted(pair_count.items(), key=lambda x: (x[1], x[0])):
        print(f"  {n:>5}  {account:<16} {spn:<42} {pair_first_seen[(account, spn)]}")

    singles = [(a, s) for (a, s), n in pair_count.items() if n == 1]
    print(f"\n  {len(singles)} (account, SPN) pair(s) requested exactly once:")
    for a, s in sorted(singles):
        print(f"    {a} -> {s}")
    print("  -> a rule-100031 volume threshold never sees these (3+/60s from one\n"
          "     account); ranking by pair rarity does. Triage each: does this\n"
          "     account have any legitimate reason to hold this SPN's service\n"
          "     ticket? If not, treat it the same as a 100031 alert.")

    if unattributed:
        print(f"\n  {len(unattributed)} unattributed (account=null) TGS-REQ(s) — Samba logs "
              f"\"null\" when the requester\n  doesn't resolve (e.g. an impacket Kerberoast tool "
              f"hitting the KRB_AP_ERR_INAPP_CKSUM\n  interop wall documented elsewhere in this "
              f"catalog). Can't be baselined per-account, but a\n  burst of these against distinct "
              f"SPNs in a short window is itself worth a look — that's\n  exactly what rule 100031 "
              f"already keys on via same_field grouping on the literal \"null\".")


if __name__ == "__main__":
    main()
