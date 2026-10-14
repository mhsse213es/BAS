# rwscore Scoring Engine — Design

## Why

Sub-project #1 wired `rwevidence` into real scenario dispatch: every modeled
ransomware technique attempt across the 8 real scenarios now produces 5
independently-verified `rw_capability_results` rows (one per capability
dimension), persisted and queryable via `db.RWCapabilityCoverage`. Nothing
rolls those rows up into a single score yet. The product's only existing
ransomware score (`orchestrator/web/src/features/ransomware.js:60-62`) is
still the naive `pass/(pass+fail)%` the roadmap explicitly calls too weak —
a customer could score highly despite zero tested backup recovery, simply
because many easier tests passed.

This is sub-project #2 of the ransomware-mastery master roadmap (see
`project_ransomware_mastery_master_roadmap.md`; the other sub-projects are
out of scope here), depending only on #1 (done, pushed `43c249d7`).

## Scope

- **In scope**: a pure Go computation package (`internal/rwscore`) that
  turns a run's capability-result coverage counts into a 5-dimension
  weighted score, a qualitative rating, and the risk-gate override the
  roadmap names by name. One thin read-only API endpoint so the engine is
  actually reachable, matching sub-project #1's own precedent of never
  leaving a library function uncalled.
- **Out of scope**: the UI (sub-project #3 — explicitly next after this).
  Persisted/cached scores (stateless computation is sufficient for now —
  YAGNI). "Evidence freshness" and "platform coverage" qualifiers the
  roadmap lists for the UI display (§4) — freshness has no policy defined
  anywhere yet, platform coverage needs sub-project #9 (cross-platform
  adapters), which doesn't exist. A second risk gate beyond the one the
  roadmap names (see Risk gates below) — not invented here.
- `rw_capability_results`, `db.RWCapabilityCoverage`/`RWCoverageRow` (both
  sub-project #1): read, never modified.

## A. Package boundary and input shape

New package `internal/rwscore`, mirroring how AD mastery keeps
`admatrix`/`adcoverage` (rollup/scoring) separate from `adprimitive`/
`controlval` (evidence production) — scoring is a distinct concern over
many `CapabilityResult`s across a run, not an evidence-producing capability
itself.

`rwscore` defines its own `CoverageRow`, mirroring `db.RWCoverageRow`'s
shape field-for-field, rather than importing `internal/db` directly — the
same discipline `rwevidence.StepInput` already uses to stay independent of
`scenario`/`models`. The caller (the API handler) translates one struct to
the other; `rwscore` never touches Postgres.

```go
type CoverageRow struct {
    TechniqueID    string
    Capability     string // one of the 5 Dimension values below
    Verdict        string // PASS / FAIL / ERROR / SKIPPED
    SkipReason     string // insufficient_evidence / not_applicable / not_tested / ""
    SpecificReason string
    Count          int
}
```

## B. Dimension pass-rate math

For each of the 5 dimensions, bucket every row by `Verdict`/`SkipReason`:

- **Pass** = count where `Verdict == "PASS"`.
- **Fail** = count where `Verdict == "FAIL"`.
- **Error** = count where `Verdict == "ERROR"` — an evaluator that ran and
  failed operationally. Distinct from Unknown: this is sub-project #1's own
  acceptance criterion 7 (ERROR must be provably distinct from "never
  invoked"), carried forward rather than re-collapsed here.
- **Unknown** = count where `SkipReason == "insufficient_evidence"` (the
  roadmap's UNKNOWN). **Stays in the pass-rate denominator** — this is the
  roadmap's explicit anti-pattern guard: "Never silently remove UNKNOWN
  results from the denominator and then present the result as
  comprehensive protection." It is never a Pass.
- **NotApplicable** = count where `SkipReason == "not_applicable"` —
  excluded from both numerator and denominator (neutral), per the rule
  sub-project #1 already wrote into `rwevidence/types.go`'s own doc
  comment: never inflating, never penalizing.
- **NotTested** = count where `SkipReason == "not_tested"` (covers both the
  roadmap's NOT TESTED and the technique-not-mapped/not-an-attempt/gate/
  applicability-undecided sub-reasons sub-project #1 introduced) — excluded
  from the pass-rate denominator (there is nothing to average when no valid
  test ran), surfaced instead as a coverage gap.

```
PassRate = Pass / (Pass + Fail + Error + Unknown)   -- 0 if denominator is 0
```

Every one of these 6 counts (Pass/Fail/Error/Unknown/NotApplicable/
NotTested) is carried on the output `DimensionScore`, not just the ratio —
so nothing a caller might want to surface is hidden behind a single opaque
percentage, the same transparency principle driving every decision above.

## C. Overall score and dimension-weight redistribution

Overall is the weighted average of the 5 `PassRate`s, using the roadmap's
own illustrative starting weights (`ransomware.txt` lines 194-221) —
Prevention 25%, Detection 20%, Containment 20%, Recovery 25%, Data
protection 10%. Explicitly **not** an industry standard; calibrate later
against real validation data, same caveat the roadmap itself gives.

**Judgment call (deciding, not asking — flagging because it's non-obvious):**
when a dimension has zero evaluated rows for this run (`Pass+Fail+Error+
Unknown == 0` — e.g. a run covering only techniques where that dimension
is `not_applicable` or `not_tested` end to end), that dimension is
**excluded from the weighted average and its weight redistributed
proportionally** across the dimensions that do have evaluated rows, rather
than either (a) counting it as a hard 0 — double-penalizing something
never attempted, on top of the NotTested count already surfacing the gap
separately — or (b) silently vanishing it without redistributing, which
would cap the maximum achievable score below 100 with no visible reason.
If every dimension is empty (nothing evaluated at all), Overall is `0.0`
and Rating is `Vulnerable` — absence of evidence must never read as safety,
the same fail-closed principle roadmap item 1 states for individual tests
("UNKNOWN when evidence is insufficient, never an automatic PASS").

Explicit formula (removing any ambiguity in "redistributed proportionally"):
for the set `N` of dimensions with at least one evaluated row,

```
Overall = 100 * Σ_{d in N} (weight[d] / Σ_{e in N} weight[e]) * PassRate[d]
```

i.e. each non-empty dimension's original weight is rescaled so the
non-empty dimensions' weights alone sum to 1.0, then the weighted average
runs over only those. A fully-non-empty run (`N` = all 5) reduces to the
plain weighted average in section C's intro, unchanged.

## D. Risk gate

The roadmap names exactly one gate by example: "a failed critical recovery
test must prevent an organization from receiving an overall 'Protected'
rating, even if its other controls perform well." Built as a checkable
predicate (so a second gate doesn't need a redesign later) but **only one
gate ships now** — a second one is not invented since the roadmap names
only this one.

**Gate**: `Recovery.Fail > 0` → ceiling `Rating` at `AtRisk` (never
`Protected`), regardless of the numeric Overall. A gate is a ceiling, never
an upgrade: if the numeric math already put the run at `Vulnerable`, the
gate changes nothing.

`CriticalFailures []string` is populated only when a gate triggers, with
one message per affected technique (the `CoverageRow`'s own `TechniqueID`
grouping gives this for free) — e.g. `"Recovery FAILED for T1490 (2
attempts)"`. Never per-action detail: the input is already technique-level
aggregate counts, so the message never claims finer granularity than the
data actually has.

## E. Rating scale

Three tiers, same illustrative-not-authoritative caveat as the weights:

```
Overall >= 80  -> Protected
Overall >= 50  -> AtRisk
Overall <  50  -> Vulnerable
```

then the risk gate (D) applies as a ceiling on top.

## F. Output shape

```go
type DimensionScore struct {
    Dimension                                      Dimension
    Pass, Fail, Error, Unknown, NotApplicable, NotTested int
    PassRate                                        float64
}

type RunScore struct {
    Overall           float64 // 0..100
    Rating            Rating  // protected / at_risk / vulnerable
    Dimensions        []DimensionScore // always all 5, in a fixed order
    CriticalFailures  []string
    GateTriggered     bool
}

func ScoreRun(rows []CoverageRow) RunScore
```

`ScoreRun` is a pure function: no I/O, no randomness, same input always
gives the same output — the whole engine is table-driven unit tests, no
container-backed test needed for the package itself.

## G. API surface

One new read-only endpoint, reusing the plain-`Get` precedent the codebase
already has for run-scoped reports (`routes.go:240-252`, e.g.
`/api/scenarios/runs/{runId}/variant-coverage`) — no new permission
middleware invented, matching those neighbors exactly:

```
GET /api/scenarios/runs/{runId}/rw-score
```

Handler (`internal/api/rwscore_handlers.go`, new file):
1. `runID := chi.URLParam(r, "runId")`.
2. Verify the run exists (`SELECT 1 FROM scenario_runs WHERE id = $1`,
   same idiom as `GetVariantCoverageReport`) — 404 on no match, so an
   unknown runID never silently returns a complete-looking "Vulnerable"
   score indistinguishable from a real, terrible assessment.
3. `db.RWCapabilityCoverage(ctx, h.db, runID)` (sub-project #1, unchanged).
4. Translate each `db.RWCoverageRow` to `rwscore.CoverageRow` (field-for-
   field, see section A).
5. `rwscore.ScoreRun(rows)`, JSON-encode the result.

## Acceptance criteria

1. A dimension with only PASS rows scores `PassRate == 1.0`.
2. A dimension with only FAIL rows scores `PassRate == 0.0`.
3. `insufficient_evidence` rows lower a dimension's `PassRate` below what
   it would be if silently excluded (the UNKNOWN anti-pattern guard, proven
   by a test that would pass wrongly if Unknown were dropped from the
   denominator).
4. `not_applicable` rows change neither a dimension's `PassRate` nor the
   Overall weighted average versus the same input with those rows removed.
5. A dimension with zero evaluated rows is excluded from the weighted
   average, with its weight redistributed — proven by comparing Overall
   against a hand-computed redistributed-weight expectation, not just "it
   runs without error."
6. Every dimension empty across the board → `Overall == 0`, `Rating ==
   Vulnerable`.
7. `Recovery.Fail > 0` with an otherwise-high Overall still yields `Rating
   == AtRisk`, never `Protected`, and `GateTriggered == true`.
8. The gate never upgrades a rating: `Recovery.Fail > 0` with a low Overall
   stays `Vulnerable`, not bumped to `AtRisk`.
9. `CriticalFailures` names the exact technique(s) and count(s) behind a
   triggered gate, matching the input `CoverageRow`s' own `TechniqueID`s.
10. `GetRunRWScore` 404s for a nonexistent `runId` without calling
    `RWCapabilityCoverage` at all.
11. `GetRunRWScore` against a real run seeded via sub-project #1's own
    dispatch path (not a synthetic `rwscore`-only fixture) returns a score
    whose `Dimensions` reflect that run's actual persisted
    `rw_capability_results` rows.

## Review Focus (for the implementation plan to pin with tests)

- The weight-redistribution math (C) is the one place a small arithmetic
  mistake produces a plausible-looking but wrong number silently — needs a
  hand-computed expected value, not just "non-zero."
- The UNKNOWN-stays-in-denominator rule (B) is the one place a simpler-
  looking "just use Pass/(Pass+Fail)" implementation would pass every
  other test while reintroducing the exact anti-pattern the roadmap calls
  out by name.
- The gate's ceiling-never-upgrade direction (D) — a one-line `<` vs `<=`
  or swapped comparison would quietly let a failed Recovery test still
  reach "Protected" under some input, undermining the entire sub-project's
  reason for existing.
