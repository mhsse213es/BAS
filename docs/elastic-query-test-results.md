# Elastic query test against a real Elasticsearch

Tested 2026-11-04 on staging's Elasticsearch 8.15.3 (throwaway index, deleted afterwards). Tool:
`scripts/rulelib-gen/esvalidate.py`. Per-rule results: `docs/elastic-query-test-results.json`.

## Result

| | Rules |
|---|---:|
| Elastic queries considered (1,775 field-mapped + 26 keyword-only) | 1,801 |
| **Tested** (Elasticsearch evaluated them) | **1,761** |
| **PASS** | **1,761** |
| **FAIL** | **0** (after the two fixes below; 2 real defects were found first) |
| **UNTESTABLE** | **40** |

The 72 rules with no translation stay `PENDING_SAMPLE`: nothing here changes them, and no rule's `verification`
value was changed by this test (see "What PASS means").

## What a test is

For each rule the tool applies the same processing pipeline the generator used, builds events from the resulting
detection, and asks Elasticsearch to evaluate the shipped query against them:

- a **positive** event that satisfies the rule: the query must match it;
- a **benign** event (right fields, wrong values): the query must not match it;
- for the 309 passing rules with a `not filter` clause, a **filtered** event that satisfies the filter: the query
  must not match it.

Every event is checked against the rule by the tool's own evaluator before it is used. The query must also be
accepted by Elasticsearch's query validator.

**The harness can fail.** Negative controls on staging: corrupting a value in 60 passing queries was caught in 45
(the other 15 have another OR branch that still matches); deleting the `NOT` filter from 60 queries produced a
false positive in 57 (2 untestable, 1 unaffected).

## What PASS means, and what it does not

PASS means the query is valid and logically equivalent to the rule when Elasticsearch evaluates it, under the test
mapping (every string a `keyword`, `*.ip` an `ip`). It does **not** mean:

- a collector emits the field names the pipeline produced (that stays in the rule's `verification`:
  documented / assumed / none, and none was promoted to `validated`);
- the rule fires on real telemetry (events are built from the rule itself, not captured from an attack).

## Defects found and fixed

1. **Wildcard on an `ip` field** (AUDRULE-000743, AUDRULE-002046). Elasticsearch 8.15 answers HTTP 400 to
   `destination.ip:127.*` in strict mode and matches nothing in lenient mode. The generator now rewrites an IPv4
   prefix to a CIDR (`"127.0.0.0/8"`) and drops a branch that can never be an address (`source.ip:*-*`); a rule
   with nothing left is reported as a failure rather than guessed (`scripts/rulelib-gen/elastic_ip.py`, 5 tests).
   Rebuilding the whole bundle changed exactly these two rules and nothing else.

## Open finding: case sensitivity

**1,741 of the 1,761 passing queries do not match the same event with its text upper-cased.** Sigma matching is
case-insensitive; a Lucene query on a `keyword` field is not, and `query_string` has no case-insensitive option.
These queries therefore match only when the event's case equals the rule's. Whether that bites depends on how the
customer's index maps each field (a normalizer or an analyzed `text` field would match case-insensitively). This
is not fixed: it needs a decision (for example DSL `case_insensitive` queries, or EQL), and it is the largest gap
between "valid query" and "detects reliably".

## Why 40 rules were not testable

| Rules | Reason |
|---:|---|
| 23 | two conditions on the same field cannot be met by one value |
| 6 | regular-expression value: no event is generated from a regex |
| 4 | no event can be built that avoids one of the rule's filters |
| 3 | a text condition on the ip field `source.ip` cannot be met by an address |
| 2 | the event built does not satisfy the rule by the tool's own check |
| 2 | a CIDR filter on `id.orig_h` / `id.resp_h` (Zeek) only works if the collector types the field as `ip`; unknown |

Rules in each group are listed in the JSON with their reason. UNTESTABLE is not PASS and is not counted as tested.
