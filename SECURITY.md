# Security policy

This repository is a **cybersecurity training lab**, not production software.
Read this before running, forking, or reusing any of it.

## This lab contains intentional weaknesses — by design

The whole point of the lab is to attack it and then detect the attack, so parts
of it are *deliberately* insecure and documented as such:

- **Weak / deliberately misconfigured Active Directory** — Kerberoastable service
  accounts and SPNs, an over-permissioned path to Tier 0, and other documented
  flaws (`phase-2-identity/known-weaknesses.md`, the `dc` role).
- **A deliberately weak file share** on `fs-01` that leaks a service credential —
  the intended lateral-movement path (`fileserver` role).
- **An intentionally vulnerable web app** (OWASP Juice Shop) on `dmz-01`.
- **Offensive tooling and attack simulations** (Atomic Red Team, BloodHound,
  Sliver C2) under `phase-5-offense/`.

None of this should ever be deployed on a network you care about. It is meant to
run on an **isolated, non-internet-exposed set of VMs on RFC1918 addressing**
(`10.10.0.0/16`, segmented behind `rtr-01`).

## Committed credentials are lab-only

Some credentials and API keys are committed on purpose (e.g. the MISP and
DFIR-IRIS integration keys and bootstrap passwords in the `siem`/`iris` role
defaults). They exist so the lab is reproducible from the repository alone, they
protect nothing of value on an isolated lab network, and they are documented in
the role defaults as regenerable.

CI runs `gitleaks` on every push. `.gitleaks.toml` allowlists these specific,
known lab values **by value** — so any *new or different* secret committed by
mistake still fails the scan. If you fork this lab for real use, rotate every one
of these and move them into the existing `ansible-vault` setup
(`phase-7-automation/ansible/.vault_pass`).

## Accepted risk: TLS certificate validation disabled between siem-01 and misp-01

`custom-iris.py` and `custom-misp.py` (Wazuh's IRIS/MISP integration scripts,
`roles/siem/files/`) call `requests.*` with `verify=False`. Flagged by CI's
Semgrep SAST job, and left in place on purpose, inline-documented at each
occurrence: IRIS's and MISP's certs are self-signed (same posture as every
other lab credential above), and every one of these calls stays on the internal
SOC segment — siem-01 talking to misp-01, never a path that leaves the lab. The
real fix (distributing each service's cert, or a shared internal CA, to
siem-01 and pointing `verify=` at it) is legitimate future hardening, not
something this training lab needs to demonstrate.

## What CI does and doesn't check

Beyond linting and the secret scan above, CI runs a Semgrep SAST pass
(`p/python`) over the repo's own scripts, and a Trivy scan of the three images
`phase-5-offense/bloodhound-ce/docker-compose.yml` pins by exact tag
(`postgres:18`, `neo4j:4.4.42`, `specterops/bloodhound:latest`) — **not**
MISP/IRIS/Greenbone/Velociraptor, whose compose files are fetched from their
own upstream repos at deploy time rather than committed here, so there's no
fixed image list to check statically (see `docs/design-decisions.md`). The
Trivy job is deliberately informational, not gating: a base Debian or JVM image
routinely carries dozens of HIGH/CRITICAL CVEs in packages this repo doesn't
control the patch cadence of, and a real vuln-management program tracks and
triages that baseline on its own schedule rather than blocking every unrelated
merge on it. Juice Shop is excluded entirely — it's the deliberately vulnerable
app under test, not a finding.

## Reporting a problem

If you find a security issue in the *tooling or automation itself* (as opposed to
one of the intentional lab weaknesses above), please open a GitHub issue, or
contact the maintainer through the address on the GitHub profile. There is no
bug-bounty program — this is a personal learning project.
