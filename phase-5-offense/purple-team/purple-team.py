#!/usr/bin/env python3
# ===========================================================================
# purple-team.py — automated detection validation ("run the attack, prove the
# detection fired").
#
# For each ATT&CK technique in tests.json: run the Atomic Red Team test on the
# target (ws-01), wait, then query the Wazuh manager (siem-01) for the expected
# custom rule(s) firing from that agent since the run started. Prints a PASS/FAIL
# report with latency — a real detection-coverage / purple-team artifact.
#
#   PASS = the technique executed AND the intended detection fired.
#   FAIL = a coverage gap (rule didn't fire) or the atomic didn't run — both are
#          findings a detection engineer investigates, not errors to hide.
#
# Run from the operator host (has SSH to both, via the ~/.ssh/config aliases):
#   ./purple-team.py [tests.json]
# ===========================================================================
import json
import subprocess
import sys
import time

CFG = sys.argv[1] if len(sys.argv) > 1 else "tests.json"


def ssh(host, cmd, timeout=90):
    try:
        return subprocess.run(
            ["ssh", "-o", "ConnectTimeout=15", host, cmd],
            capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        # a hanging atomic (e.g. net view against a down DC) must not stall the run
        return subprocess.CompletedProcess(args=[], returncode=124, stdout="", stderr="timeout")


def run_atomic(target, technique, test):
    # -ExecutionPolicy Bypass is required (the default policy blocks the module's
    # scripts); import ART explicitly and point it at the offline atomics folder.
    ps = (f'Import-Module Invoke-AtomicRedTeam -Force -ErrorAction SilentlyContinue; '
          f'Invoke-AtomicTest {technique} -TestNumbers {test} '
          f'-PathToAtomicsFolder C:\\AtomicRedTeam\\atomics -TimeoutSeconds 60')
    return ssh(target, f'powershell -ExecutionPolicy Bypass -NoProfile -c "{ps}"')


def count_matching(siem, agent, rule_ids):
    # Count alerts for the expected rule(s) from this agent in the manager's alert
    # log — the source of truth. Called before + after each atomic; the delta is
    # what THIS test produced (robust against pre-existing alerts, no indexer /
    # timestamp-parsing dependency, which the first indexer-query version got wrong).
    ids = "|".join(rule_ids)
    remote = (f"sudo grep -aE '\"id\":\"({ids})\"' /var/ossec/logs/alerts/alerts.json 2>/dev/null "
              f"| grep -ac '\"name\":\"{agent}\"'")
    r = ssh(siem, remote, timeout=30)
    for line in reversed(r.stdout.strip().splitlines()):
        if line.strip().isdigit():
            return int(line.strip())
    return 0


def main():
    cfg = json.load(open(CFG))
    target, agent = cfg["target_ssh"], cfg["target_agent"]
    siem, settle = cfg["siem_ssh"], cfg.get("settle_seconds", 25)
    results = []
    print(f"\n== Purple-team validation :: target={target} agent={agent} "
          f"siem={siem} ==\n")
    for t in cfg["tests"]:
        tech, num = t["technique"], t["test"]
        before = count_matching(siem, agent, t["expect_rules"])
        t0 = time.time()
        run_atomic(target, tech, num)
        time.sleep(settle)
        n = count_matching(siem, agent, t["expect_rules"]) - before
        latency = round(time.time() - t0, 1)
        ok = n > 0
        results.append((tech, ok, n, latency, t["desc"], t["expect_rules"]))
        print(f"  [{'PASS' if ok else 'FAIL'}] {tech:11} "
              f"rules {','.join(t['expect_rules']):15} "
              f"hits={n} {latency}s  {t['desc']}")
    passed = sum(1 for r in results if r[1])
    print(f"\n== {passed}/{len(results)} techniques detected "
          f"({round(100*passed/len(results))}% coverage) ==\n")
    sys.exit(0 if passed == len(results) else 1)


if __name__ == "__main__":
    main()
