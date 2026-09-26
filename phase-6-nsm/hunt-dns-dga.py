#!/usr/bin/env python3
# ===========================================================================
# hunt-dns-dga.py — hunt for Domain Generation Algorithm (DGA) C2 in Zeek dns.log.
#
# HYPOTHESIS: malware that can't hardcode its C2 domain (easy to sinkhole/blocklist)
# instead derives many CANDIDATE domains from a shared algorithm/seed and queries
# them until one resolves (T1568.002 — Dynamic Resolution: DGA). The shape this
# leaves in DNS is the opposite of a human or a real app: SHORT, RANDOM-LOOKING
# labels (not the long encoded blobs hunt-dns-tunnel.py hunts for), queried in
# BULK from one host, almost all NXDOMAIN (only the registered one(s) resolve).
#
# METHOD, two passes over the same grouped data:
#   1. Score every distinct (source host, base domain) pair on how "gibberish"
#      its label looks — a cheap, explainable heuristic (no ML, no external
#      corpus): character entropy normalized to a random-lowercase ceiling,
#      vowel scarcity, longest consonant run, and digit mixing. Real dictionary
#      words and brand names score low; `xqzplkw7f.net`-style strings score high.
#   2. Roll up by SOURCE HOST: a host that fires off many distinct gibberish-
#      scored domains that mostly NXDOMAIN is the DGA tell — any single such
#      domain could be a coincidence (a CDN/AV cache-buster subdomain, say), but
#      a burst of a dozen from one host in one session is not.
#
# HONEST LIMITATIONS (named, not hidden):
#   - The gibberish heuristic is English-letter-frequency-shaped; a DGA using a
#     dictionary-word wordlist (some newer families do, precisely to evade this
#     class of detector) would score low here. This catches the classic
#     random-character families, not every DGA design.
#   - No real newly-registered-domain / WHOIS-age signal — this lab is
#     deliberately internet-independent (see docs/design-decisions.md), and that
#     data requires an external, continuously-updated feed. NXDOMAIN volume is
#     used as the always-available proxy: the candidates that never resolve.
#
#   ./hunt-dns-dga.py                 # fetch live from the sensor and rank
#   ./hunt-dns-dga.py dns.log         # analyze a local TSV
#   ssh rtr-01-root cat /opt/zeek/logs/current/dns.log | ./hunt-dns-dga.py -
# ===========================================================================
import math
import subprocess
import sys

SENSOR_SSH = "rtr-01-root"
DNS_LOG = "/opt/zeek/logs/current/dns.log"
MIN_DISTINCT_DOMAINS = 5   # a host needs this many distinct gibberish+NX domains to flag
GIBBERISH_THRESHOLD = 55   # per-domain score (0-100) above which a label counts as gibberish


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


def sld_label(dom):
    """The second-level label a DGA actually generates — 'xqzplkw7f' out of
    'xqzplkw7f.net' — not the fixed TLD."""
    parts = dom.split(".")
    return parts[0] if parts else dom


def entropy(s):
    if not s:
        return 0.0
    freq = {c: s.count(c) for c in set(s)}
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


def gibberish_score(label):
    """0-100: how random/algorithmic a single label looks. Cheap and explainable
    on purpose — see the module header for what it does and doesn't catch."""
    label = label.lower()
    if len(label) < 4:
        return 0  # too short to say anything meaningful
    ent = entropy(label)
    vowels = sum(1 for c in label if c in "aeiou")
    vowel_ratio = vowels / len(label)
    max_consonant_run, run = 0, 0
    for c in label:
        if c.isalpha() and c not in "aeiou":
            run += 1
            max_consonant_run = max(max_consonant_run, run)
        else:
            run = 0
    digit_ratio = sum(c.isdigit() for c in label) / len(label)
    # ~4.7 bits/char is the ceiling for random lowercase-a-z; real words sit well
    # below it because letter frequency is skewed and short n-grams repeat.
    score = (
        (ent / 4.7) * 50
        + max(0, (0.28 - vowel_ratio)) * 140
        + min(max_consonant_run, 6) * 5
        + digit_ratio * 20
    )
    return round(min(100, score))


def main():
    source = sys.argv[1] if len(sys.argv) > 1 else None
    rows = [r for r in parse(load(source)) if r.get("query")]

    # Score every distinct (source, domain) pair once.
    per_source = {}
    for r in rows:
        src = r.get("id.orig_h", "?")
        dom = base_domain(r["query"])
        nx = r.get("rcode_name") == "NXDOMAIN"
        bucket = per_source.setdefault(src, {})
        entry = bucket.setdefault(dom, {"count": 0, "nx": 0, "score": gibberish_score(sld_label(dom))})
        entry["count"] += 1
        entry["nx"] += 1 if nx else 0

    host_results = []
    domain_hits = []
    for src, doms in per_source.items():
        gibberish_nx = [
            (dom, d) for dom, d in doms.items()
            if d["score"] >= GIBBERISH_THRESHOLD and d["nx"] / d["count"] >= 0.5
        ]
        for dom, d in gibberish_nx:
            domain_hits.append({"src": src, "dom": dom, **d})
        if len(gibberish_nx) >= MIN_DISTINCT_DOMAINS:
            host_results.append({
                "src": src,
                "distinct_gibberish_nx": len(gibberish_nx),
                "total_distinct_domains": len(doms),
                "sample": sorted((dom for dom, _ in gibberish_nx), key=len)[:5],
            })

    host_results.sort(key=lambda x: -x["distinct_gibberish_nx"])
    domain_hits.sort(key=lambda x: -x["score"])

    print(f"\n== DNS-DGA hunt :: {len(rows)} queries, {len(per_source)} source hosts ==")
    print(f"   flagging hosts with >= {MIN_DISTINCT_DOMAINS} distinct gibberish-scored "
          f"(>= {GIBBERISH_THRESHOLD}) domains that mostly NXDOMAIN\n")

    if not host_results:
        print("  no host crossed the DGA-burst threshold.\n")
    for h in host_results:
        print(f"  ! {h['src']}: {h['distinct_gibberish_nx']} distinct gibberish/NX domains "
              f"out of {h['total_distinct_domains']} total — sample: {', '.join(h['sample'])}")

    print("\n  top individual domain hits (score, source, nx-ratio):")
    for d in domain_hits[:10]:
        print(f"    {d['score']:>3}  {d['src']:<15} {d['dom']:<30} "
              f"{d['nx']}/{d['count']} NXDOMAIN")
    print()


if __name__ == "__main__":
    main()
