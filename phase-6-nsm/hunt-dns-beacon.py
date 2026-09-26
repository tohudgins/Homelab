#!/usr/bin/env python3
# ===========================================================================
# hunt-dns-beacon.py — hunt for periodic C2 check-ins hiding in Zeek dns.log.
#
# HYPOTHESIS: a DNS-based (or DNS-fronted) C2 channel still calls home on a
# regular cadence (T1071.004) — same idea as hunt-beaconing.py's conn.log hunt,
# but conn.log can't see it here: every host's DNS queries — malicious and
# benign alike — go to the SAME recursive resolver IP:53, so grouping by
# (source, dest-ip, dest-port) the way hunt-beaconing.py does mixes one host's
# entire DNS history into a single "pair" and drowns the one C2 domain's
# rhythm in everything else it looked up. The signal only appears if you group
# by the QUERIED DOMAIN NAME instead of the resolver IP — which only dns.log,
# not conn.log, actually records.
#
# METHOD: group dns.log by (source host, base domain), and for any pair queried
# often enough to matter, compute the coefficient of variation (CV = stdev/mean)
# of the inter-query intervals. A metronome-like beacon has a near-zero CV;
# human/app-driven lookups are bursty and irregular (high CV). Composite score
# blends interval regularity with persistence (query count), the same two-signal
# idea hunt-beaconing.py uses and for the same reason: CV alone is a trap — a
# jittered beacon deliberately RAISES its CV to blend in, so a lone low-CV
# reading isn't proof and a moderate-CV high-count pair still deserves a look.
#
#   ./hunt-dns-beacon.py                 # fetch live from the sensor and rank
#   ./hunt-dns-beacon.py dns.log         # analyze a local TSV
#   ssh rtr-01-root cat /opt/zeek/logs/current/dns.log | ./hunt-dns-beacon.py -
# ===========================================================================
import statistics
import subprocess
import sys

SENSOR_SSH = "rtr-01-root"
DNS_LOG = "/opt/zeek/logs/current/dns.log"
MIN_QUERIES = 5          # need enough gaps for a CV to mean anything
EXPECTED_QUERIES = 15    # persistence term saturates here
BEACON_SCORE = 60        # composite score at/above this = worth investigating


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


def main():
    source = sys.argv[1] if len(sys.argv) > 1 else None
    rows = [r for r in parse(load(source)) if r.get("query") and r.get("ts")]

    groups = {}
    for r in rows:
        key = (r.get("id.orig_h", "?"), base_domain(r["query"]))
        try:
            ts = float(r["ts"])
        except ValueError:
            continue
        groups.setdefault(key, []).append(ts)

    results = []
    for (src, dom), stamps in groups.items():
        stamps.sort()
        if len(stamps) < MIN_QUERIES:
            continue
        deltas = [b - a for a, b in zip(stamps, stamps[1:]) if b > a]
        if len(deltas) < 2:
            continue
        mean_iv = statistics.mean(deltas)
        if mean_iv <= 0:
            continue
        cv = statistics.pstdev(deltas) / mean_iv
        regularity = max(0.0, 1 - min(cv, 1))       # 1 = metronome, 0 = chaotic
        persistence = min(len(stamps) / EXPECTED_QUERIES, 1.0)
        score = round(100 * (0.7 * regularity + 0.3 * persistence))
        results.append({
            "src": src, "dom": dom, "n": len(stamps), "mean_iv": mean_iv,
            "cv": cv, "score": score,
        })

    results.sort(key=lambda x: -x["score"])
    print(f"\n== DNS-beacon hunt :: {len(rows)} queries, {len(groups)} (source, domain) pairs, "
          f"{len(results)} with >={MIN_QUERIES} queries ==")
    print("   ranking by composite beacon score (interval regularity + persistence)\n")
    hdr = f"  {'':1} {'score':>5} {'queries':>7} {'mean_iv':>9} {'cv':>6}  source -> domain"
    print(hdr)
    print("  " + "-" * (len(hdr) + 8))
    for r in results[:15]:
        flag = "!" if r["score"] >= BEACON_SCORE else " "
        print(f"  {flag:1} {r['score']:>5} {r['n']:>7} {r['mean_iv']:>7.1f}s "
              f"{r['cv']:>6.2f}  {r['src']} -> {r['dom']}")

    flagged = [r for r in results if r["score"] >= BEACON_SCORE]
    print(f"\n  {len(flagged)} pair(s) scoring >= {BEACON_SCORE} — periodic-looking DNS lookups:")
    for r in flagged:
        print(f"    {r['src']} -> {r['dom']}: {r['n']} queries, mean interval "
              f"{r['mean_iv']:.1f}s, CV {r['cv']:.2f} (0 = perfectly regular)")
    print()


if __name__ == "__main__":
    main()
