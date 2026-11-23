# XSS sink re-sweep, 2026-11-23

Group G (frontend XSS surface) was halted on 2026-10-08 against the old single-file console. The console is now split into
`orchestrator/web/src` modules, so this re-runs the existing G1 pipeline (`scripts/g1-run-local.sh`) on today's `main`
(`96a78985`) and triages what it reports.

## What the pipeline says

- The committed G1 artifacts in `security/g1/` are **stale**: regenerating changes five of them. CI's "G1 audit artifacts are
  stale" step (`.github/workflows/test.yml`) would fail on the next push or PR for that reason alone. Last refresh: `f7d675f5`.
- `g1-check-no-regression.py` reports **17 slots whose severity tier rose** against the committed baseline, and a
  **canonical escaper check failure** (`esc` line 20299 and `x` lines 4317 and 4401 are "not a pure delegate", plus a possible
  duplicate escaper at 20300). The escaper findings are a result of the module inlining (several modules define `x`/`esc`);
  not investigated further.

## Triage of the 17 slots (by reading the code, not by the classifier)

| Slots | Finding |
|---|---|
| Sinks whose content is `empty(...)`, `card('', empty(...))`, `hbars(...)`, `pill`, `chip` (loadVariantCoverage, renderList, renderRemList, vfLoadQueue, vfRenderQueue, loadRemediations, renderDisclaimer, loadAgtOverview error path) | Safe. `empty()`, `card()` title/sub, `hbars()`, `pill()`, `chip()` escape their text with `x()` (`web/src/core/kit.js`). The classifier cannot see into them because they moved out of the old monolith, so it rates them `unclear`/`partial_escaped`. |
| `fetchAuditPage` rows (audit-logs.js) | Safe. Every field, including the free-text detail, goes through `x()`. |
| `vfLoadEvidence` (detection-verification.js) | Safe. Uploaded file name, hash and uploader are escaped; the id uses `encodeURIComponent`; size is a number. |
| `renderRemList` (findings.js) | Safe. Text escaped; `missed` and `detectedOnly` are coerced with `Number(v) \|\| 0` in `rem-model.js`. |
| `renderIOCRegistryTable` (iocs.js) | Safe in practice. One unescaped value, `row.sightingCount`, is a count from the server; it would only be exploitable if the API returned a non-number. Cheap hardening: wrap it in `Number()`. |
| `loadVariantCoverage` (variants.js) | Safe. All cells are escaped. |
| `loadAgtOverview` (agent-drawer.js `overviewHtml`) and `renderLegacyMigrationPanel` (agents-insights.js) | Safe. Server strings are escaped; remaining interpolations are constants or model tones. |

**No exploitable injection was found in the 17 flagged slots.** This is a manual read of those sinks only. It is not a new
inventory of every sink in the console, and it says nothing about sinks the classifier did not flag.

## What this means for CI

The guard cannot be satisfied by committing regenerated artifacts: the 17 regressions would still fail the comparison against
the committed baseline, and the guard has no reviewed-exception mechanism. The real fix is to teach the classifier the
`kit.js` helpers as escaping (so the slots return to their previous tiers) or to add a reviewed-waiver file. Either changes the
security tool itself, so it was left for an explicit decision. (Option 1 was then chosen and built; see the update below.)

## Not done

- A reviewed-waiver mechanism for the guard, and regenerating and committing the `security/g1/` artifacts (see the update below).
- A full re-inventory of all sinks; the style-policy (`.style.<prop>`) work that depends on it.

## Update: classifier taught the kit.js helpers (option 1)

Done on this branch:

- `scripts/g1-assemble-classifier-view.py` now reads each module's imports from `core/kit.js` and presents calls to the
  helpers that escape every argument (`empty`, `pill`, `chip`, `hbars`, `kv`, `bar`, `icon`) as `g1safe(...)`, and
  `card(...)` as `g1card(...)`. Only names the module actually imports from `core/kit.js` are rewritten: a module that defines
  its own `pill()` (agent-drawer.js does, and its version interpolates the tone unescaped) or imports from elsewhere keeps the
  name and stays unproven. `grid`, `kpi` and `seg` take raw HTML and are never trusted.
- `scripts/g1-innerhtml-sink-classifier.py` treats `g1safe` as an escaper, and `g1card(title, body, options)` as exactly as
  safe as its body. It refuses (falls back to "indirect builder") when the options contain `actions` or `cls` (both reach the
  markup unescaped), when the argument count is wrong, or when the call has template literals, regex literals or unbalanced
  text. Tests: `scripts/test_g1_kit_helpers.py` (16 cases); the other 61 G1 tests still pass.
- Canonical escaper check now passes. Two real defects behind it were fixed: `core/charts.js` had two local numeric functions
  named `x` (renamed `px`, 8 lines), and `features/execution-coverage.js` carried a second full escaper `esc()` (replaced by the
  shared `x()`; all three uses are HTML text, where the extra `'` escape did nothing). Web suite 952/952.

Result: the guard's regressions went from **17 to 10**. The ones that remain are a different kind and teaching the helpers
cannot clear them:

| Slots | What it is |
|---|---|
| 8 slots, tier 0 to 1: `fetchAuditPage`, `loadVariantCoverage` (2), `renderIOCRegistryTable`, `renderList`, `renderRemList`, `vfLoadEvidence`, `vfLoadQueue` | Code that was fully static in the October baseline now puts server data into markup, escaped. The guard counts that as "more dangerous", which is its design. Each was read by hand above and is escaped. |
| 2 slots, tier 3 to 4: `loadAgtOverview`, `renderLegacyMigrationPanel` | Builder functions that assemble their result from local variables and local helpers (`dl`, `note`, `actBtn`); the classifier cannot prove them without a deeper trace. Read by hand: every server value passes through `x()`, `on()` or a validated tone. |

These ten cannot be accepted by regenerating and committing the artifacts: the guard has no way to record a reviewed
exception, so the next PR would fail against `main`'s baseline. That needs a small reviewed-waiver file, which is the part of
option 2 that remains a separate decision. The regenerated `security/g1/` artifacts were deliberately not committed.

## Update: reviewed-waiver file

`security/g1/G1_REVIEWED_REGRESSIONS.json` records a regression a reviewer has read and accepted. `g1-check-no-regression.py`
reads it (override with `--waivers`; a missing file means none) and prints every waived regression so a PR reviewer still sees it.

A regression is waived only when a waiver names the **same slot and the same tier change** and **every current sink in that slot
at the new tier is one of the waiver's `sink_ids`**. Sink ids are content hashes of the sink's own source, so editing a waived
sink, or adding another sink at that tier, makes the guard fail again. A malformed file is an error, never ignored. Each entry
needs a reason, a reviewer, a `YYYY-MM-DD` date, and `to_tier` above `from_tier`. A waiver that excused nothing in a run is
reported as stale (not failed) so it gets removed.

Limits, stated plainly:
- **Builder sinks.** For `el.innerHTML = overviewHtml(a)` the id covers the call, not the builder's body, so an edit inside
  `overviewHtml` or `migrationPanelHtml` does not re-flag. The two waivers for those say so.
- **The reviewer is not a person.** The 9 entries were written from a manual read by Claude Sonnet 5.5. The guard enforces that a
  reason, a reviewer name and a date exist; it cannot check that a human agreed. Merging the PR is that sign-off.
- **Not new coverage.** This clears the ten flagged slots. Two other sinks at the highest tier changed their source since the
  baseline and are listed by the guard as "REVIEW, not failed" (`renderScheduledAssessmentsList`, `renderTemplateGrid`); they
  were not read as part of this work.

The regenerated `security/g1/` artifacts are committed with it, so CI's "artifacts are stale" step passes. With the waivers,
the guard passes locally against the committed baseline (`G1 regression guard: PASS`), and all 88 G1 Python tests pass.
