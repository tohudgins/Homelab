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

## Reporting a problem

If you find a security issue in the *tooling or automation itself* (as opposed to
one of the intentional lab weaknesses above), please open a GitHub issue, or
contact the maintainer through the address on the GitHub profile. There is no
bug-bounty program — this is a personal learning project.
