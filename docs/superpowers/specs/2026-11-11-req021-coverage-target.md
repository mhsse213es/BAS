# REQ-021 coverage target (decision)

**Date:** 2026-11-11
**Decided by:** Claude, on Tausif's request to decide. Reversible by Tausif.

## Decision

The coverage target is the **Critical KEV population**: CISA KEV entries with a CVSS v3.1 (else v3.0) Primary base score of 9.0 to 10.0. Coverage is measured across:
- **Linux:** Ubuntu LTS releases focal, jammy, noble (Ubuntu OVAL).
- **Windows:** OS-scope Microsoft Critical KEVs (MSRC CVRF plus KB titles).

**High severity (CVSS 7.0 to 8.9) is out of scope** for this target. It is a separate decision after the Critical pipeline is validated on real hosts.

## Why

- It matches the scope already approved by the owner (Critical only).
- Changing the denominator now would make results hard to compare and would bring in curation work before mapping accuracy is established.
- The denominator is the full population, not the reviewed subset, so the claim cannot be inflated by reviewing only the easy rows.

## How coverage is reported

- **Denominator:** all Critical KEVs with a v3 Primary score. At the 2026-11-09 KEV snapshot this is 500.
- **Numerator:** Critical KEVs with an approved mapping for the relevant platform.
- **Every other CVE is reported as UNKNOWN**, with its reason (no Ubuntu OVAL match, no reviewed mapping, no Windows fixed build).
- Never report "no fix" for NO_UBUNTU_OVAL_MATCH.

## Limits to state with any number

- 456 KEVs have no v3 score. They are excluded from the denominator and must be listed separately, not treated as covered.
- The KEV and NVD snapshots are fixed at 2026-11-09 and 2026-11-10. Coverage changes with each new snapshot.
- Current numerator is small: 18 Ubuntu and 3 Windows approved rows. The covered share of the 500 is low, and that is the honest result.
- Coverage of a CVE means a reviewed fixed-version mapping exists. It does not mean any host is exposed or not exposed.

## Not decided here

- High severity scope.
- Whether a product or customer tier needs a different population.
- Level 2 exploitability (separate, lab-gated).
