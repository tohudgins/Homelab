#!/usr/bin/env python3
# ===========================================================================
# hunt-beaconing.py — hunt for C2 beaconing in Zeek conn.log.
#
# HYPOTHESIS: a command-and-control implant calls home on a regular cadence.
# Even when the channel is TLS-encrypted (so a signature IDS is blind to the
# payload), the *timing* of the connections is not something encryption hides.
#
# METHOD: group Zeek conn.log by (id.orig_h, id.resp_h, id.resp_p) and score
# each pair with a composite BEACON SCORE (0-100), the mean of three signals a
# real beacon shows and human/app traffic does not (the same three RITA /
# AC-Hunter combine, done with the stdlib):
#   1. interval regularity  — 1 - CV(inter-arrival gaps).  A metronome scores 1.
#   2. request-size regularity — 1 - CV(orig_bytes).  Identical check-ins score 1;
#      a data-less SYN-only pattern (all orig_bytes == 0) scores 0 — it carries
#      no C2 tasking signal, which is exactly what separates a real implant from
#      a bare TCP keepalive/retry.
#   3. persistence — count / EXPECTED_CONNS, capped at 1.  A beacon keeps calling.
# WHY A COMPOSITE, NOT JUST CV: interval CV alone is a trap. A beacon with jitter
# (Sliver's `--jitter`) deliberately RAISES its interval CV to blend in, while a
# no-jitter benign keepalive is *more* regular than the malware. Ranking on CV
# alone therefore floats the keepalive above the C2 (see this lab's own run —
# the Wazuh agent's SOC:1514 keepalive out-regulars the Sliver beacon). Adding
# payload-consistency and persistence — and triaging by DESTINATION — is what
# recovers the beacon. The raw CV stays in the table so that trap is visible.
#
# DATA SOURCE: Zeek conn.log (TSV) from the inline NSM sensor on rtr-01. Those
# logs are root:zeek mode 0640, so by default we fetch them over SSH as root
# (the `rtr-01-root` alias). Pass a local file, or `-` for stdin, to analyze a
# copy instead — the parser is the same either way.
#
#   ./hunt-beaconing.py                  # fetch live from the sensor and rank
#   ./hunt-beaconing.py conn.log         # analyze a local TSV/JSON copy
#   ssh rtr-01-root cat /opt/zeek/logs/current/conn.log | ./hunt-beaconing.py -
#
# OUTPUT: a ranked table (most beacon-like first) with, per pair, the
# connection count, mean interval, interval CV, request-size CV, and the
# destination segment — so an analyst can triage by *where* the regular caller
# is phoning. The tool ranks on behaviour alone; the verdict is the analyst's.
# ===========================================================================
import json
import statistics
import subprocess
import sys

# --- where to pull the live logs from (root-readable Zeek spool on rtr-01) ---
SENSOR_SSH = "rtr-01-root"
CONN_LOG = "/opt/zeek/logs/current/conn.log"

# --- hunt thresholds -------------------------------------------------------
MIN_CONNS = 8        # need enough connections for a CV to mean anything
EXPECTED_CONNS = 20  # persistence saturates here (a beacon keeps calling)
BEACON_SCORE = 60    # composite score at/above this = worth investigating

# --- the lab's segments, so the output says WHERE a regular caller is going --
SEGMENTS = [
    ("10.10.10.", "CORP"),
    ("10.10.20.", "DMZ"),
    ("10.10.30.", "SOC/MGMT"),
    ("10.10.40.", "REDTEAM"),
]


def segment_of(ip):
    for prefix, name in SEGMENTS:
        if ip.startswith(prefix):
            return name
    return "external"


def load_conn(source):
    """Return raw text of the conn.log from a file, stdin, or the live sensor."""
    if source == "-":
        return sys.stdin.read()
    if source:
        with open(source) as f:
            return f.read()
    # default: fetch live from the sensor as root
    r = subprocess.run(["ssh", "-o", "ConnectTimeout=15", SENSOR_SSH, f"cat {CONN_LOG}"],
                       capture_output=True, text=True, timeout=60)
    if r.returncode != 0:
        sys.exit(f"could not read {CONN_LOG} on {SENSOR_SSH}: {r.stderr.strip()}")
    return r.stdout


def parse_conn(text):
    """Parse Zeek conn.log — handles both TSV (with the #fields header) and JSON
    Lines. Yields dicts with the fields we need."""
    lines = text.splitlines()
    # JSON-lines mode: first non-blank line is an object
    for ln in lines:
        if ln.strip():
            if ln.lstrip().startswith("{"):
                for j in lines:
                    j = j.strip()
                    if j:
                        yield json.loads(j)
                return
            break
    # TSV mode: pull column order from the #fields header
    fields = None
    for ln in lines:
        if ln.startswith("#fields"):
            fields = ln.split("\t")[1:]
            continue
        if ln.startswith("#") or not ln.strip():
            continue
        if fields is None:
            continue
        parts = ln.split("\t")
        if len(parts) < len(fields):
            continue
        yield dict(zip(fields, parts))


def num(v):
    """Zeek unset fields are '-' / '(empty)'."""
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


def main():
    source = sys.argv[1] if len(sys.argv) > 1 else None
    rows = list(parse_conn(load_conn(source)))

    # group by (src, dst, dst_port)
    groups = {}
    for r in rows:
        key = (r.get("id.orig_h"), r.get("id.resp_h"), r.get("id.resp_p"))
        if None in key:
            continue
        groups.setdefault(key, []).append(r)

    results = []
    for (src, dst, dport), conns in groups.items():
        ts = sorted(num(c.get("ts")) for c in conns if num(c.get("ts")) is not None)
        if len(ts) < MIN_CONNS:
            continue
        deltas = [b - a for a, b in zip(ts, ts[1:]) if b - a >= 0]
        if len(deltas) < 2:
            continue
        mean_iv = statistics.mean(deltas)
        if mean_iv <= 0:
            continue
        cv_iv = statistics.pstdev(deltas) / mean_iv

        # request-size consistency: a beacon check-in is near-identical each time
        obytes = [num(c.get("orig_bytes")) for c in conns]
        obytes = [b for b in obytes if b is not None]
        mean_ob = statistics.mean(obytes) if obytes else 0.0
        cv_ob = (statistics.pstdev(obytes) / mean_ob) if mean_ob > 0 else None

        # dominant connection state (SF=established w/ data, S0=SYN-only, ...)
        states = {}
        for c in conns:
            states[c.get("conn_state", "?")] = states.get(c.get("conn_state", "?"), 0) + 1
        state = max(states, key=states.get)

        # --- composite beacon score: mean of three 0-1 signals (see header) ---
        interval_score = max(0.0, 1 - cv_iv)
        size_score = max(0.0, 1 - cv_ob) if cv_ob is not None else 0.0
        persist_score = min(1.0, len(ts) / EXPECTED_CONNS)
        score = round(100 * (interval_score + size_score + persist_score) / 3)

        results.append({
            "src": src, "dst": dst, "dport": dport, "count": len(ts),
            "mean_iv": mean_iv, "cv_iv": cv_iv, "mean_ob": mean_ob, "cv_ob": cv_ob,
            "span": ts[-1] - ts[0], "score": score, "seg": segment_of(dst), "state": state,
        })

    # rank: highest composite beacon score first, ties broken by connection count
    results.sort(key=lambda x: (-x["score"], -x["count"]))

    print(f"\n== Beacon hunt :: {len(rows)} connections, {len(groups)} src/dst/port "
          f"pairs, {len(results)} with >={MIN_CONNS} conns ==")
    print(f"   ranking by composite beacon score (interval + size regularity + "
          f"persistence); flagged >= {BEACON_SCORE}\n")
    hdr = (f"  {'':1} {'score':>5} {'conns':>5} {'interval':>9} {'iv_cv':>6} "
           f"{'req_sz':>7} {'sz_cv':>6} {'st':>4}  {'source':<13} -> {'destination':<15} {'seg'}")
    print(hdr)
    print("  " + "-" * (len(hdr) - 2))
    for r in results:
        flag = "!" if r["score"] >= BEACON_SCORE else " "
        szcv = f"{r['cv_ob']:.2f}" if r["cv_ob"] is not None else "  -"
        print(f"  {flag:1} {r['score']:>5} {r['count']:>5} {r['mean_iv']:>7.1f}s "
              f"{r['cv_iv']:>6.2f} {r['mean_ob']:>6.0f}B {szcv:>6} {r['state']:>4}  "
              f"{r['src']:<13} -> {r['dst']:<15} {r['seg']}")

    flagged = [r for r in results if r["score"] >= BEACON_SCORE]
    print(f"\n  {len(flagged)} pair(s) scored >= {BEACON_SCORE} — triage by destination:")
    for r in flagged:
        if r["seg"] == "REDTEAM":
            note = "  <-- REDTEAM dest + payload: treat as C2 until proven otherwise"
        elif r["dport"] in ("1514", "1515"):
            note = "  (SOC:1514 = Wazuh agent channel — expected infrastructure)"
        else:
            note = ""
        print(f"    score {r['score']}: {r['src']} -> {r['dst']}:{r['dport']} "
              f"every ~{r['mean_iv']:.1f}s x{r['count']} [{r['state']}]{note}")
    print()


if __name__ == "__main__":
    main()
