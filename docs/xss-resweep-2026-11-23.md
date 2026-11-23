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
security tool itself, so it is left for an explicit decision. Nothing in `security/g1/` or `scripts/` was changed here.

## Not done

- Classifier or guard changes; regenerating and committing the artifacts.
- A full re-inventory of all sinks; the style-policy (`.style.<prop>`) work that depends on it.
