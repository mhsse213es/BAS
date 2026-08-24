# Environment Restoration Accuracy — Design

**Status:** Approved (sections reviewed and confirmed with user, 2026-08-24)
**Spec type:** Architectural

## Problem

The "Environment Restoration" panel on a run report shows a headline
cleanup stat (`0.0% Clean`, `47 leaked • 0 cleaned`) directly above an
"Agent-Confirmed Rollbacks" list that shows real, successful cleanups for
that same run. Both numbers are technically correct in isolation; shown
together they read as a contradiction, and a customer-facing security
report cannot show that.

## Root cause

Two independent, currently-disconnected mechanisms both claim to describe
"was this run's environment restored?":

1. **Per-step `CleanupVerdict`** (`reverted | partial | leaked`,
   `internal/models/schema.go`) — set once, immediately, from the exit
   code of that step's own `cleanup:` PowerShell/shell script
   (`agent/executor.go:105,280` → `runCleanup`, `agent/executor_windows.go`).
   All-or-nothing per step: any single failing line anywhere in a
   multi-action cleanup script marks the *whole* step `partial` or
   `leaked`, regardless of what it actually left behind.

2. **The whole-run safety-net sweep** (`agent/snapshot_windows.go`,
   `agent/snapshot_posix.go`) — `captureSnapshot()` runs once before any
   step starts (`agent/agent.go:533`), `revertFromSnapshot()` runs once
   after every step has finished (`agent/agent.go:724`). It diffs the
   pre-run baseline against post-run state across scheduled tasks,
   services, registry Run/RunOnce keys, temp dirs, hosts file, and
   startup folders, and actively removes anything new — logging each
   success into `reverted []string`. This diff is **anonymous by
   design**: a flat before/after comparison with no link back to which
   step created any given artifact.

`buildEnvRestoration` (`internal/reporting/engine.go:3210`) receives both
the per-step matrix and `reverted[]`, but only uses `reverted[]` to
populate an unused `RevertedCount` field. The headline `StepsCleaned` /
`StepsLeaked` / `CleanupRate` come *exclusively* from the frozen
per-step `CleanupVerdict` — never reconciled against what the later
sweep actually achieved.

Critically, this is not simply an aggregation bug: even a perfectly
accurate per-step verdict, computed the moment that step's own cleanup
script exits, is *correctly* "leaked" at that point in time if the
script failed — the safety net's rescue happens strictly *later*, after
every other step has also run. The two numbers describe different
moments and different mechanisms. Closing the gap requires both a more
accurate per-step verdict *and* an explicit reconciliation step, not a
one-line aggregation fix.

## Constraint that shapes the design: concurrency

Scenario steps run through a resource-lock scheduler
(`agent/sched/scheduler.go`, `orchestrator/internal/scenario/resource.go`).
Only a small, curated set of read-only **observation**-risk discovery
techniques (T1012, T1057, T1082, T1033, …) ever get a non-nil
`ResourceProfile`; every other step — including every step that could
possibly declare a `cleanup:` script, since cleanup implies mutation —
stays unlabeled and takes the scheduler's **exclusive global barrier**,
i.e. runs fully serial today. This means a cleanup-bearing step never
overlaps any other step in time, on either OS. That removes the hardest
version of the attribution problem (concurrent steps racing to claim
credit for the same artifact) without adding any new locking.

## Design

### 1. Per-step evidence-based verdict

For every step with a non-empty `cleanup:` script (already the sole
existing trigger for computing `CleanupVerdict` at all —
`agent/executor.go:105`, `:280`):

1. Take a **lightweight** snapshot immediately before the step's action
   runs (`captureSnapshotLite`) — the same categories as today's
   `captureSnapshot`, minus the netsh firewall dump and hosts-file read
   on Windows (the slowest calls, and essentially never what a
   `cleanup:` script targets). POSIX has no comparably expensive calls
   today, so its lite variant is identical to the full one.
2. Run the step's action, then its `cleanup:` script exactly as today —
   the raw exit-code verdict is still computed, unchanged.
3. Take a second lightweight snapshot immediately after.
4. Diff (1) against (3) via a new shared `diffSnapshots(before, after)`
   helper (extracted from the inline diff logic already duplicated
   across `revertFromSnapshot`'s six sections) — the result is
   `CleanupResidual []string`, using a normalized key format shared
   with the whole-run sweep: `"tmp:<path>"`, `"registry:<key>\<value>"`,
   `"schtask:<name>"`, `"service:<name>"`, `"startup:<path>"` (POSIX:
   `"cron:<path>"`, `"service:<name>"`, `"tmp:<path>"`, plus whole-file
   keys for crontab/iptables/sensitive files, unchanged from today's
   `s.Files` keys).
5. Reconcile: diff evidence overrides the raw exit code when they
   disagree — exit-0-but-residual-present downgrades to `partial`;
   timeout-but-empty-residual upgrades to `reverted`. If either snapshot
   failed to capture (any subprocess error — already handled
   per-category with `err == nil` guards, so a partial/empty snapshot is
   normal, not exceptional), `CleanupResidual` stays nil and
   `CleanupVerdict` falls back to today's exit-code-only behavior —
   never blocks or fails the step.

### 2. Server-side reconciliation — the missing third state

In `buildEnvRestoration` (or a small helper it calls), cross-reference
each step's `CleanupResidual` keys against the run's final `reverted[]`
list (same key format, so this is a plain set intersection). A match
means: the step's own script failed to remove it, but the whole-run
safety net confirmed its removal afterward. This step's status becomes
a new explicit third state, **`rescued`** — counted toward the
headline cleaned rate (it *is* clean by the end of the run) but
rendered with a distinct badge/caption ("cleaned by safety net, not by
its own script") so the report stays honest about *how* it got clean.
`leaked` now means residue that nothing, at any point, confirmed
removing.

Historical rows recorded before this change have no `CleanupResidual`
(nil) — treated as "no evidence available," falling back to today's
exit-code-only classification. Existing reports are not reinterpreted
incorrectly.

## Data model changes

- `agent/types.go` (`ExecResult`): add
  `CleanupResidual []string \`json:"cleanupResidual,omitempty"\`` —
  populated only for cleanup-bearing steps.
- `agent/snapshot.go` / `snapshot_windows.go` / `snapshot_posix.go`:
  extract `diffSnapshots(before, after *SystemSnapshot) []string` from
  the logic already inline in `revertFromSnapshot`; add
  `captureSnapshotLite(runID string) *SystemSnapshot`.
- `agent/executor.go`: wrap both `if step.Cleanup != ""` sites (~105,
  ~280) with the pre/post lite-snapshot bracket and the override logic.
- `internal/models/schema.go`: mirror `CleanupResidual []string` on the
  server-side result struct; extend the `CleanupVerdict` doc comment
  with the new `"rescued"` value.
- `internal/reporting/engine.go`: `buildEnvRestoration` gains the
  residual-vs-`reverted[]` reconciliation. Signature is unchanged —
  `(matrix []TechniqueRow, reverted []string)` — residual data travels
  via the matrix rows. All three call sites (~1510, ~1800, ~2002)
  benefit automatically.
- `orchestrator/wwwroot/index.html`: Environment Restoration panel gets
  one new badge/state for `rescued` (distinct color, e.g. amber, with a
  short caption); everything else in that panel is unchanged.
- No new API endpoint. Persistence: whatever column/type
  `CleanupVerdict` already uses on the technique-result table gains a
  sibling nullable column for the residual list (exact type confirmed
  during planning against the live schema).

## Error handling

- Snapshot capture failure at any category: fails soft exactly as
  today's `captureSnapshot` (independent `err == nil` guards per
  category) — degrades to exit-code-only verdict for that step, never
  blocks the run.
- Residual found with no match in `reverted[]`: stays `leaked`. This is
  the honest default — no match means nothing ever confirmed removing
  it.
- Pre-change historical data (nil `CleanupResidual`): reconciliation
  step is skipped, `buildEnvRestoration` falls back to legacy
  `CleanupVerdict`-only math for that row.

## Cost

Each cleanup-bearing step now pays two lightweight snapshots
(roughly 1-3s each with firewall/hosts excluded) instead of zero. Since
these steps are already fully serial under the scheduler, this is pure
addition to total run wall-clock time, not a concurrency regression.
Hand-authored scenario YAMLs today show roughly half of steps declare a
`cleanup:` block (198 `cleanup:` lines across ~387 `technique_id:`
occurrences, sampled across `scenarios/*.yaml`); dynamically-expanded
ART/Caldera sweeps will vary. This should be measured against a real
sweep during implementation and reported, not assumed away.

## Testing

- **Agent unit tests**: `diffSnapshots` against synthetic
  before/after `SystemSnapshot` fixtures — no new items (empty diff),
  one new temp file (present in residual), pre-existing items never
  flagged. Override logic tested directly: exit-0 + residual →
  `partial`; timeout + empty residual → `reverted`; nil snapshots →
  falls back to raw exit code unchanged.
- **`captureSnapshotLite` vs `captureSnapshot`**: assert the lite
  variant's key set is a strict subset with no firewall/hosts keys —
  guards against the expensive calls creeping back into the per-step
  path later.
- **Server-side (`internal/reporting`)**: table-driven test on the
  `buildEnvRestoration` reconciliation covering matched-residual →
  `rescued`/counted-clean, unmatched-residual → `leaked`, nil-residual
  (legacy row) → unchanged legacy math.
- **End-to-end**: extend the existing `seedReportableRun` test-DB
  fixture pattern (already used in `run_report_api_test.go`) with a
  leaked-but-later-rescued step and a genuinely-leaked step; assert the
  report JSON's `envRestoration` no longer produces a
  zero-percent-clean-with-nonempty-rollback-list contradiction for that
  fixture.
- Real hardware verification (a live Windows agent run against a
  scenario with `cleanup:` scripts) is out of scope for this session —
  flagged honestly as unverified rather than claimed complete.

## Out of scope

- Per-step attribution for steps *without* a `cleanup:` script. Their
  artifacts remain in the anonymous whole-run `reverted[]` bucket with
  no per-step identity, exactly as today. Extending snapshot-diffing to
  every state-mutating step (not just cleanup-bearing ones) would be a
  materially larger scope change and was not requested.
- Any change to the scheduler's locking/concurrency model — none is
  needed; cleanup-bearing steps are already fully serial.
- Linux/macOS get the same design (their snapshot categories are
  already cheap enough that no "lite" trimming is needed) — no
  Windows-only scoping decision required here.
