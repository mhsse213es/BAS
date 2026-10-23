# Aleef Benchmark Specification (Milestone 1)

Status: frozen 2026-10-23 (owner confirmed). Source: `docs/superpowers/specs/2026-10-23-aleef-milestone1-design.md`, section 10 and 11.

The target is a synthetic bank API, never a real banking system. Production testing is prohibited in this milestone. No UAT access exists; the lab is the only proof, and no statement about real-bank readiness is made until a design-partner UAT run exists.

## Held-out flaws (property level only)

The owner defines the benchmark specification and the hidden flaw cases. The generator's implementers do not receive the hidden cases or their exact trigger conditions until evaluation.

| ID | Flaw | Property |
|---|---|---|
| H1 | Cross-customer object access | Customer B cannot read A's account or transaction |
| H2 | Unauthorized object modification | A customer cannot modify another's beneficiary or payment |
| H3 | Approved payment tampering | Changing amount/beneficiary after approval invalidates the approval |
| H4 | Idempotency failure | Same idempotency key cannot create a second transaction |
| H5 | Invalid payment-state transition | Payment cannot reach settled without required authorization steps |
| H6 | Maker-checker bypass | Initiator cannot approve their own transaction when dual control is required |
| H7 | Cross-tenant document exposure | Customer cannot reach another's KYC document via an alternate endpoint |
| H8 | Inconsistent authorization across API versions | Older version enforces the same access rules as the current one |

Each has an independently seeded defect and a fixed counterpart. The cases stay out of the generator's catalogue and hard-coded rules (recognition test vs discovery test).

## Pass criteria for Milestone 1

At least 6 of 8 held-out flaws verified (75%); 0 verified false positives on fixed controls; 3 consecutive reproductions from fresh objects; legitimate-owner control and negative control pass for every verified finding; every verified finding has reproducible evidence and a saved regression test; all safety controls pass with no unauthorized money movement or production execution; all 8 flaws have documented ground truth and a fixed build.

Reporting: individual per-flaw results and exact test coverage, never recall alone. 6/8 is a prototype acceptance threshold, not proof of broad discovery capability.

## Sealed-defect rule

The seeded-defect code (trigger conditions for H1-H8) must be written by someone who is not the generator's implementer, and kept where the implementer does not read it (separate package path, built into the lab binary behind a defect-flag interface). The implementer builds the clean API skeleton, the fixed build, the OpenAPI document and the defect-flag hook, and nothing else.

Related constraints:

- The generator and its tests must not import the benchmark package, the sealed defects, or read hidden labels. A build-time check (import-graph test) enforces this.
- The evaluation harness reads labels only after the run. Labels live outside the generator's inputs.
- Generator properties stay general. They must not be tuned to the eight cases; any property added after seeing benchmark results must be recorded as post-hoc in the QA log.

## Resources the clean bank API must expose

- Accounts
- Transactions
- Beneficiaries
- Payments, with initiate, approve and settle operations
- KYC documents, with a primary endpoint and an alternate endpoint
- Two route sets: `/v1` and `/v2`

## Label file format

Ground-truth labels are held only by the owner and are never committed to this repository. File name `labels.json`:

```json
[{"id":"H1","operation":"...","note":"..."}]
```

## Implementer knowledge statement

The implementer has seen the property list above (it is in the visible spec) but has not seen the trigger conditions of any defect.
