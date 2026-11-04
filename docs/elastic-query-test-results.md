# Elastic query test against a real Elasticsearch

Tested 2026-11-04 on staging's Elasticsearch 8.15.3 (throwaway indices, deleted afterwards). Tool:
`scripts/rulelib-gen/esvalidate.py`. Per-rule results for every run: `docs/elastic-query-test-results.json`.

## Correction to the earlier version of this document

The first version reported 1,761 of 1,801 Elastic queries tested and all passing. That was wrong in one way:
**40 Elastic queries shipped corrupt** (pySigma's `ecs_windows` pipeline turned a regular-expression value into the
text of a Python object, e.g. `SigmaRegularExpression(regexp=...)`; the generator's gate missed the form where the
Lucene backend escapes the parenthesis). Such a query can never match, and the test built its events from the same
rule, so it passed 35 of them and marked 5 untestable. The gate is fixed, the 40 Elastic translations are now
recorded as failures instead of shipped, and the test now rejects the pattern on the query text itself. The Go
bundle has a test for it that fails on the old bundle (40 hits) and passes on the new one.

## Result: Lucene `query_string` (unchanged text)

| | Rules |
|---|---:|
| Elastic queries shipped (1,735 field-mapped + 26 keyword-only) | 1,761 |
| **PASS** | **1,726** |
| **FAIL** | **0** |
| **UNTESTABLE** | **35** |

No query that passed before and is still shipped changed status. The 72 `PENDING_SAMPLE` rules are the identical
set and byte-identical in the bundle.

## Result: Elasticsearch DSL with `case_insensitive: true` (new, additive)

The Lucene query is kept as is. Where possible each field-mapped Elastic translation also carries a `dsl` query
(`term` / `prefix` / `wildcard` with `case_insensitive: true`, bool `filter` / `should` / `must_not` for AND / OR /
NOT). No EQL.

| Field mapping used in the test | PASS | FAIL | UNTESTABLE | No DSL |
|---|---:|---:|---:|---:|
| all strings `keyword` | 1,685 | 0 | 24 | 52 |
| all strings `wildcard` type | 1,685 | 0 | 24 | 52 |
| all strings analysed `text` | 157 | 1,528 | 24 | 52 |

- **Different-case events:** every PASS also matched the same event upper-cased and lower-cased, and still rejected
  the benign event, the filtered event and the filtered event differing only in case. Of the 1,726 passing Lucene
  queries, 1,706 were case-sensitive; the DSL of those matches case variants.
- **Mutation check:** removing `case_insensitive` failed 80 of 80 queries on a case miss; corrupting a value failed
  60 of 60; deleting a `must_not` failed 57 of 60 (2 untestable, 1 unaffected).
- **52 rules have no DSL:** 26 keyword-only and 26 free-text search conditions. The 9 rules that use a regular
  expression now have one (next section).
- **Text mapping fails by design.** `term`/`prefix`/`wildcard` act on analysed tokens, so a DSL query does not
  work on an analysed `text` field. The DSL is for `keyword` and `wildcard`-typed fields (what ECS uses). Where a
  customer's fields are analysed `text`, the analyser already gives case-insensitivity and the Lucene query applies;
  that was not measured here.
- **Not claimed:** equivalence under any other mapping (a custom normalizer, `constant_keyword`, runtime fields,
  other analysers) was not tested.

Behaviour of Elasticsearch 8.15.3 the translator works around (each tested):

1. `case_insensitive` folds ASCII only (`Ä` does not match `ä`). For the 7 rules with cased non-ASCII letters the
   upper-case and lower-case spellings of those letters are both added. A mixed-case spelling of them is not covered.
2. `term ""` never matches, with or without `case_insensitive`. An empty string is written as "field exists and has
   no character". The `wildcard` field type cannot express this; 2 rules' filtered-empty events are skipped on that
   type (20 rules contain an empty-string condition).
3. A wildcard on an `ip` field is an error or matches nothing, so IPv4 prefixes become CIDR terms (see below).

## Regular expressions in the DSL

Sigma's `re` is a PCRE-style search; Elasticsearch's `regexp` is Lucene syntax and must match the whole value. So the
regex is rewritten (`scripts/rulelib-gen/elastic_regex.py`): wrapped in `.*( ... ).*` unless anchored with `^` / `$`,
`\s \d \w` (and negations) turned into classes, `(?:` into `(`, Lucene operator characters (`@ & ~ < > # "`) escaped,
`.` made `[^\n]` as in PCRE, and a leading `(?i)` or the rule's `i` flag turned into `case_insensitive: true` (also
applied inside `[a-z]`, which Elasticsearch does not do on its own). Sigma regexes are case-sensitive unless flagged,
and these stay so. Lookaround, `\b`, back-references, `\x..`, inline flags, `^` / `$` mid-pattern and the `m` flag are
refused: that rule gets no regex DSL rather than a wrong one.

- **Differential test:** `scripts/rulelib-gen/esregex_diff.py` compares the translated query with Python's `re.search`
  on 582 strings (hand-written plus mutations: a character removed, inserted, case-swapped) for the 9 shipped regexes
  and 24 other constructs. **33 of 33 agree exactly on `keyword` and on `wildcard` fields**
  (`docs/elastic-regex-dsl-test-results.json`). The first run caught one real error (`[a-z]` under `(?i)`), now fixed.
- **Rule level:** 3 of the 9 rules (AUDRULE-001572, -001934, -000429) were run end to end with hand-built events (match,
  upper-case match where `(?i)` or the field allows it, a benign event, a filtered event): all pass on both field
  types. The other 6 are UNTESTABLE for the rule harness (it cannot build an event from a regex) and are covered only
  by the differential test and the structural tests.
- **Found on the way:** AUDRULE-000429 compares `source.ip` to the text `AWS Internal`, which Elasticsearch rejects on
  an `ip` field (HTTP 400). The DSL now writes such a condition as `match_none`; this also corrected AUDRULE-000321 and
  AUDRULE-000973.

### Open finding: the shipped Lucene queries for these 9 rules are anchored

A Lucene `query_string` regex must match the whole field value. On Elasticsearch 8.15.3 `c:/-D/` returns nothing for
the value `auditctl -D`, while `c:/.*-D.*/` matches it. The Lucene text of the 9 regex rules was not changed (the DSL
work keeps Lucene as is), so those 9 Lucene queries almost never match; use the DSL for them. The rule harness had
marked them UNTESTABLE, which hid this. The fix would be to pad the Lucene regex with `.*`.

## What a test is

For each rule the tool applies the generator's pipeline, builds events from the resulting detection and asks
Elasticsearch to evaluate the shipped query: a **positive** that must match, a **benign** that must not, and for
rules with a `not` filter a **filtered** event that must not. Every event is checked against the rule by the tool's
own evaluator first. Negative controls on the Lucene side: corrupting a value in 60 passing queries was caught in 45
(the rest have another OR branch); deleting the `NOT` filter from 60 produced a false positive in 57.

## What PASS means, and what it does not

PASS means the query is valid and logically equivalent to the rule when Elasticsearch evaluates it under the test
mapping. It does **not** mean the collector emits those field names (that stays in the rule's `verification`:
documented / assumed / none; none was promoted to `validated`), or that the rule fires on real telemetry (events are
built from the rule, not captured from an attack). No rule's `verification` value changed.

## Defects found and fixed

1. **Wildcard on an `ip` field** (AUDRULE-000743, AUDRULE-002046): HTTP 400 in strict mode, no match in lenient mode.
   IPv4 prefixes are now CIDR terms; a branch that can never be an address is dropped
   (`scripts/rulelib-gen/elastic_ip.py`).
2. **40 corrupt shipped queries** (above).
3. **DSL translator:** empty-string and non-ASCII handling (above), found by 5 failures in the first DSL run; regex
   class case and `ip` fields compared to non-address text, found by the regex tests.

## Why 35 Lucene rules (18 DSL) were not testable

| Lucene | DSL | Reason |
|---:|---:|---|
| 18 | 7 | two conditions on the same field cannot be met by one value |
| 6 | 6 | regular-expression value: no event is generated from a regex (the DSL is covered by the differential test) |
| 4 | 4 | no event can be built that avoids one of the rule's filters |
| 3 | 3 | a text condition on the ip field `source.ip` cannot be met by an address |
| 2 | 2 | the event built does not satisfy the rule by the tool's own check |
| 2 | 2 | a CIDR filter on Zeek `id.orig_h` / `id.resp_h` only works if the field is typed `ip`; unknown |

UNTESTABLE is not PASS and is not counted as tested. Coverage counts: Elastic now 2,053 translated, 51 not available
(`docs/detection-rules-coverage.md`).
