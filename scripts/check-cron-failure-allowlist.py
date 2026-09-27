#!/usr/bin/env python3
# Fails if a siem-01 cron job writes "CRON_JOB_FAILED: <script> exit=N" under a
# script name that rule 100563's regex doesn't accept. The rule is an explicit
# allowlist, so adding a new siem-01 cron with the idiom and forgetting the rule
# silently drops that job's failure alerts — which happened once already
# (velociraptor-hunt-escalate.py, 2026-09-27).
#
# misp-01 crons (misp/iris roles) are deliberately out of scope: misp-01 has no
# Wazuh agent, so those lines are local-visibility only and never reach the rule.
import pathlib
import re
import sys

REPO = pathlib.Path(__file__).resolve().parent.parent
ROLES = REPO / "phase-7-automation/ansible/roles"
SIEM01_SOURCES = [ROLES / "siem", ROLES / "velociraptor/tasks/server.yml"]
RULES = ROLES / "siem/files/local_rules.xml"

rules_text = RULES.read_text()
m = re.search(r'<rule id="100563".*?<regex type="pcre2">(.*?)</regex>', rules_text, re.S)
if not m:
    sys.exit("rule 100563 or its <regex> not found in local_rules.xml")
rule_re = re.compile(m.group(1))

writers = set()
for src in SIEM01_SOURCES:
    files = [src] if src.is_file() else [p for p in src.rglob("*") if p.is_file()]
    for f in files:
        for name in re.findall(r"CRON_JOB_FAILED: (\S+) exit=\$rc", f.read_text(errors="ignore")):
            writers.add(name)

if not writers:
    sys.exit("found no CRON_JOB_FAILED writers for siem-01 — the scan itself is broken")

missing = sorted(w for w in writers if not rule_re.search(f"CRON_JOB_FAILED: {w} exit=1"))
for w in sorted(writers):
    print(f"{'MISSING' if w in missing else 'ok':7} {w}")
if missing:
    sys.exit(f"rule 100563 would not alert on: {', '.join(missing)}")
