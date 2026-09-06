#!/usr/bin/env python3
# ===========================================================================
# hunt-dns-tunnel.py — hunt for DNS tunneling / exfiltration in Zeek dns.log.
#
# HYPOTHESIS: an implant tunneling data over DNS (T1071.004 / T1048.003) encodes
# it into the subdomain labels of one attacker-controlled zone. It can't hide the
# shape of that traffic: the query names are abnormally LONG and HIGH-ENTROPY,
# nearly every one is UNIQUE (it's encoded data, not a reused hostname), and they
# arrive in HIGH VOLUME to that single zone. Normal DNS is the opposite — short,
# low-entropy, heavily repeated names spread across many domains.
#
# METHOD: group Zeek dns.log by registrable base domain (last two labels) and,
# per domain, compute query count, unique-name ratio, mean/max query-name length,
# mean Shannon entropy of the encoded portion, and the NXDOMAIN ratio. Rank by a
# composite tunnel score. The real tunnel separates from normal DNS by orders of
# magnitude on length + uniqueness, so it sorts straight to the top.
#
# The real-time companion is Suricata rule 9100010 (long qname to REDTEAM at
# volume); this is the analyst's quantitative view of the same behaviour, and it
# works on any destination, not just the scoped one. Reads dns.log as root from
# the sensor (rtr-01), or a local file / stdin.
#
#   ./hunt-dns-tunnel.py                 # fetch live from the sensor and rank
#   ./hunt-dns-tunnel.py dns.log         # analyze a local TSV
#   ssh rtr-01-root cat /opt/zeek/logs/current/dns.log | ./hunt-dns-tunnel.py -
# ===========================================================================
import math
import statistics
import subprocess
import sys

SENSOR_SSH = "rtr-01-root"
DNS_LOG = "/opt/zeek/logs/current/dns.log"
MIN_QUERIES = 10       # need volume for the stats to mean anything
LONG_NAME = 100        # a query name this long is already abnormal


def load(source):
    if source == "-":
        return sys.stdin.read()
    if source:
        return open(source).read()
    r = subprocess.run(["ssh", "-o", "ConnectTimeout=15", SENSOR_SSH, f"cat {DNS_LOG}"],
                       capture_output=True, text=True, timeout=60)
    if r.returncode != 0:
        sys.exit(f"could not read {DNS_LOG} on {SENSOR_SSH}: {r.stderr.strip()}")
    return r.stdout


def parse(text):
    fields = None
    for ln in text.splitlines():
        if ln.startswith("#fields"):
            fields = ln.split("\t")[1:]
            continue
        if ln.startswith("#") or not ln.strip() or fields is None:
            continue
        parts = ln.split("\t")
        if len(parts) >= len(fields):
            yield dict(zip(fields, parts))


def base_domain(q):
    labels = [lbl for lbl in q.strip(".").split(".") if lbl]
    return ".".join(labels[-2:]) if len(labels) >= 2 else q


def entropy(s):
    if not s:
        return 0.0
    freq = {c: s.count(c) for c in set(s)}
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


def main():
    source = sys.argv[1] if len(sys.argv) > 1 else None
    rows = [r for r in parse(load(source)) if r.get("query")]

    groups = {}
    for r in rows:
        groups.setdefault(base_domain(r["query"]), []).append(r)

    results = []
    for dom, qs in groups.items():
        names = [r["query"] for r in qs]
        if len(names) < MIN_QUERIES:
            continue
        lengths = [len(n) for n in names]
        # entropy of the encoded portion (query minus the base domain)
        subs = [n[: -len(dom) - 1] if n.endswith(dom) else n for n in names]
        ents = [entropy(s) for s in subs if s]
        uniq_ratio = len(set(names)) / len(names)
        nx = sum(1 for r in qs if r.get("rcode_name") == "NXDOMAIN") / len(qs)
        mean_len = statistics.mean(lengths)
        # composite tunnel score (0-100): length is the dominant term, reinforced
        # by uniqueness and entropy; volume is a floor, not the driver.
        score = round(min(100,
                          0.6 * min(mean_len, 120) / 120 * 100 +
                          0.25 * uniq_ratio * 100 +
                          0.15 * (statistics.mean(ents) if ents else 0) / 6 * 100))
        results.append({
            "dom": dom, "n": len(names), "uniq": uniq_ratio, "mean_len": mean_len,
            "max_len": max(lengths), "ent": statistics.mean(ents) if ents else 0,
            "nx": nx, "score": score,
        })

    results.sort(key=lambda x: -x["score"])
    print(f"\n== DNS-tunnel hunt :: {len(rows)} queries, {len(groups)} base domains, "
          f"{len(results)} with >={MIN_QUERIES} queries ==")
    print("   ranking by composite tunnel score (name length + uniqueness + entropy)\n")
    hdr = (f"  {'':1} {'score':>5} {'queries':>7} {'uniq%':>6} {'mean_len':>8} "
           f"{'max_len':>7} {'entropy':>7} {'nx%':>5}  domain")
    print(hdr)
    print("  " + "-" * (len(hdr) + 8))
    for r in results:
        flag = "!" if r["mean_len"] >= LONG_NAME else " "
        print(f"  {flag:1} {r['score']:>5} {r['n']:>7} {100*r['uniq']:>5.0f}% "
              f"{r['mean_len']:>7.0f}c {r['max_len']:>6}c {r['ent']:>7.2f} "
              f"{100*r['nx']:>4.0f}%  {r['dom']}")

    flagged = [r for r in results if r["mean_len"] >= LONG_NAME]
    print(f"\n  {len(flagged)} domain(s) with a mean query-name length >= {LONG_NAME} chars "
          f"(normal DNS is <40) — classic DNS-tunnel encoding:")
    for r in flagged:
        print(f"    {r['dom']}: {r['n']} queries, {100*r['uniq']:.0f}% unique, "
              f"mean {r['mean_len']:.0f}c / max {r['max_len']}c — treat as exfil until proven otherwise")
    print()


if __name__ == "__main__":
    main()
