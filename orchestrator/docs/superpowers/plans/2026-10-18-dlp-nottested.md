# DLP Mastery Priority 4: capability-aware NOT_TESTED resolver (narrow scope)

## Locked scope (user decision, verbatim intent)

1. Add `StatusNotTested` to `internal/reporting/dlp.go`'s domain, without removing or renaming any existing status.
2. When `dlpVerifier` encounters an explicit, recognized `skip:` marker (reused exactly as-is — `isSkipMarker`, no changes to its matching rule), return `StatusNotTested` with the available reason, instead of today's `StatusUnknown`.
3. Keep `StatusUnknown` / `MissingEvidence` for genuinely ambiguous outcomes: execution occurred but no recognizable evidence was found (no marker, or an unrecognized marker token).
4. Never classify arbitrary output merely containing the word "skip" as a skipped test — satisfied by construction: `isSkipMarker` already requires the literal first line (after trimming) to start with `skip:`, case-insensitive. Not touched in this change.
5. Preserve serialization/compatibility for existing stored results and consumers.
6. Do **not** map DLP results onto `internal/controlval`'s four-verdict (PASS/FAIL/ERROR/SKIPPED) taxonomy in this change — that is a separately scoped, cross-domain compatibility decision for later, not bundled here.
7. Log scenario-level capability declarations (pre-dispatch precondition gating) as a future, separate cross-domain design initiative — not built now.

## What does NOT change

- `dlpComparator.Compare`'s truth table — byte-for-byte unchanged. `ComparisonResult` stays `MissingEvidence` for the skip path (unchanged) — only the legacy `Status` field gains a new, more specific value for that one case.
- `collapseToStatus` (shared by every verifier in this package) — untouched. The `StatusNotTested` override happens locally inside `dlpVerifier.Verify`, after the shared `collapseToStatus` call, only on the skip-marker path.
- `isSkipMarker` — untouched.
- No scenario metadata, no pre-dispatch gating, no `internal/controlval` import.

## Design

### `detection_validation.go`

Add one constant to the existing `Status` block:
```go
StatusNotTested = "NotTested" // required capability/precondition was confirmed absent; never attempted
```

### `dlp.go`

`dlpVerifier.Verify`'s skip-marker switch case already sets `observed = ObservationUnknown` and leaves `collectionMethod = ""`. After the shared epilogue computes `r.Comparison`/`r.Status` via `collapseToStatus` (which resolves `MissingEvidence` → `StatusUnknown`, unchanged), override specifically for this one case:

```go
wasSkip := isSkipMarker(ev.RawOutput)
...
if wasSkip {
    r.Status = StatusNotTested
}
```

**Builder's call:** `limitationsFor`'s existing `MissingEvidence`+`ObservationUnknown` text ("it may have been skipped, or produced no recognizable completion marker") is now imprecise once `Status` distinguishes the two cases — a reader seeing `StatusNotTested` with text that hedges "may have been skipped" is misleading. Split the text: pass `wasSkip` into `limitationsFor` (or branch before calling it) so the skip case states plainly "this step did not run -- a recognized precondition/capability was confirmed absent," while the no-marker case keeps today's inconclusive phrasing unchanged. This is a direct, minimal consistency fix for the "confidence and limitations" dimension Priority 3 already built, not scope creep — flagged here since it wasn't explicitly in the locked requirement list.

## Tests (TDD, `dlp_test.go`)

Per the user's regression table, plus the builder's-call addition:
1. Required client tool absent + skip marker → `StatusNotTested`, `Comparison` stays `MissingEvidence`.
2. Technique explicitly inapplicable + skip marker → `StatusNotTested` (same code path, different skip-reason text in `RawOutput` — proves the marker-convention match, not the reason text, drives the branch).
3. Step executes, no recognizable marker at all → unchanged `StatusUnknown`/`MissingEvidence` (regression; existing `TestDLPVerifier` subtest already covers this, must stay green unmodified).
4. Enforcement failure positively observed (sink-confirmed delivery despite expected Block) → unchanged existing classification (regression; existing `TestDLPVerifier_SinkPrimary_TokenReceived` must stay green unmodified).
5. A stored result predating this change (`Status:"Unknown"`, no new field) still deserializes and behaves identically — light JSON round-trip check.
6. `limitationsFor`'s skip-case text names the precondition as confirmed absent, never hedges "may have been skipped."
7. A garbage/unrecognized marker (not a skip) still resolves `StatusUnknown`, never `StatusNotTested` — proves the override is gated on the real skip check, not on "any non-Match/Mismatch outcome."

## Review focus for final review

- Confirm `collapseToStatus` itself is untouched (diff) — the override lives only in `dlpVerifier.Verify`.
- Confirm no other verifier (`automaticVerifier`/`apiVerifier`/`manualVerifier`) or any `internal/controlval` import was touched.
- Confirm the full pre-existing `dlp_test.go`/`detection_validation_test.go` suite stays green unmodified.
- Confirm `isSkipMarker`'s exact-prefix-match behavior (not a loose "contains skip") is unchanged and still governs the new branch.
