# Remote Access Validation (PAN-OS / CVE-2026-0257): Open Items

Status as of 2026-10-20. Companion to `docs/remote-access-validation-plan.md`.
Each item says what is missing, what it blocks, and what closes it. Nothing here
is marked done until its evidence exists.

## Blocked on external input

| # | Item | Blocks | Closed by |
|---|------|--------|-----------|
| 1 | Sanitised PAN-OS configuration export | Config-import parser, exposure-condition mapping (Phase 2 steps 3 to 5) | A real export, sanitised by the user. Field names are mapped from it, not guessed. |
| 2 | Certificate-use field in the export | Shared versus dedicated override certificate. Stays unknown until the field is mapped. | Mapping from item 1 that matches the advisory's wording. |
| 3 | Staging PAN-OS appliance | End-to-end validation (Phases 4 and 5) | Staging access. Not yet available. |
| 4 | SIEM or DLP tenant with GlobalProtect logs | Phase 3 ingestion and correlation. B1 (action = block) and B2 (test-event timestamp) stay open. | A tenant export or live access. The connector's field coverage must be checked first. |
| 5 | Approved simulation scope | Any active test on the appliance (Phases 4 and 5) | Written scope from the user. |

## Open advisory issues

| # | Item | Effect | Closed by |
|---|------|--------|-----------|
| 6 | PAN-OS 10.2.18 base release conflicts in the advisory (product-status says affected, solution table says upgrade target) | Returns `unknown` with `RELEASE_UNRESOLVED` | Palo Alto clarification. Do not pick a side. |
| 7 | Advisory row for 11.2.8 to 11.2.10-h* is listed as "upgrade to 10.2.10-h7" in the solution table (apparent typo) | The code uses the "<11.2.10-h7" threshold from product status. This is a reading, not a verified fact. | Palo Alto clarification |
| 8 | Older unsupported releases are covered only by "All older unsupported PAN-OS versions" | Modelled as an affected range with no release-train detail | Advisory wording is sufficient for "affected". The supported fixed release is named by the advisory, not chosen by us. |

## Built, but unverified in a live environment

| # | Item | Gap |
|---|------|-----|
| 9 | Advisory registry (`ac93bfa0`) | Advisory data is verified against the vendor page on 2026-10-20 only. It has not been re-checked since. |
| 10 | Explainable verdicts (`92d47e81`) and advisory status (`da6be2a7`) | Tested with synthetic and registry fixtures only. No real asset has been assessed. |

## Explicitly out of scope (per decision, 2026-10-20)

- Prisma Access, Cloud NGFW, and Panorama. Panorama and Cloud NGFW are not affected per the advisory. A Panorama device must never be submitted as product `pan-os`.

## Rules for closing items

- A verdict may change only when its evidence changes. Keep the advisory revision that produced it.
- Missing or ambiguous facts stay unknown. They are never treated as safe.
- An unverified advisory is never the default. The API reports its status on each result.
