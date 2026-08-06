# Custom-Step Privilege Field Design

**Goal:** Let scenario authors set `requires_priv` on hand-authored custom steps directly in the Scenario Builder UI, so those steps participate in privilege-tier coverage tracking and Run Wizard "Max privilege" dispatch filtering the same way ART- and Caldera-sourced steps already do.

## Background

`Step.RequiresPriv` (`orchestrator/internal/scenario/types.go:159-163`) is a `PrivSpec` — a struct with `Minimum` and `Preferred` string tiers (`"user" | "admin" | "system"`), accepting either a scalar YAML/JSON value (`requires_priv: admin`) or a mapping form (`{minimum: user, preferred: admin}`). Today it's populated automatically for the two generated modes:

- **ART mode** — `mapARTElevation()` (`orchestrator/internal/scenario/art.go:63-68`) sets `Minimum` from Atomic Red Team's `elevation_required` flag.
- **Caldera mode** — `mapCalderaElevation()` (`orchestrator/internal/scenario/builder.go:392-397`) sets `Minimum` from the ability's `Privilege` field.

Neither ever sets `Preferred` — nothing in the codebase reads or writes it today.

**Custom steps mode** (the Scenario Builder's `addStep()` UI, `orchestrator/wwwroot/index.html:10356`) has no privilege source at all — no UI field, no metadata to derive from. Every hand-authored custom step is therefore permanently "unannotated," which means:

- It always renders as `inherited` in the Privilege Tier Breakdown (`index.html:10814`).
- It can never be filtered by the Run Wizard's "Max privilege" ceiling (`modal-max-privilege`, `index.html:3673-3681`), since that filter relies on `RequiresPriv` being set (`SkipReasonPolicyPrivilege` in `handlers.go`).

## Backend: no changes needed

`CreateScenario` and `UpdateScenario` (`orchestrator/internal/api/handlers.go:1625,1646`) decode the POST/PUT body directly into `scenario.Scenario`. `PrivSpec.UnmarshalJSON` already accepts a bare JSON string scalar (`"requiresPriv": "admin"`) as well as the object form. The wire format this feature needs is already fully supported server-side — this is a pure frontend change.

## Frontend changes

All changes are in `orchestrator/wwwroot/index.html`.

### 1. `addStep(st)` (`:10356-10382`)

Add a `<select class="st-priv">` as a 5th field in the step's existing `.bld-grid` (alongside Name / Technique ID / Executor / Timeout — not a new full-width row):

```html
<div class="bld-field">
  <label>Requires privilege</label>
  <select class="st-priv">
    <option value="">No requirement</option>
    <option value="user">User</option>
    <option value="admin">Admin</option>
    <option value="system">System</option>
  </select>
</div>
```

Selected value comes from `st.requiresPriv` when editing an existing step (the raw scalar string the API returned, or `undefined` for legacy/unannotated steps — both map to `""` / "No requirement").

Add a hint line beneath the grid (matching the Run Wizard's existing copy at `:3680` for consistency):

> "Steps requiring higher privilege than a run's Max Privilege ceiling are skipped, not dispatched."

### 2. `collectBuilder()` (`:10437-10445`)

When building each step object, read `.st-priv`'s value. Only set the key when non-empty:

```js
var priv = r.querySelector('.st-priv').value;
var step = {
  name: r.querySelector('.st-name').value.trim() || ('Step ' + (i + 1)),
  techniqueId: tech,
  framework: 'custom',
  executor: r.querySelector('.st-exec').value,
  command: r.querySelector('.st-cmd').value,
  timeoutSec: parseInt(r.querySelector('.st-timeout').value, 10) || 60,
  cleanup: r.querySelector('.st-cleanup').value.trim()
};
if (priv) step.requiresPriv = priv;
sc.steps.push(step);
```

"No requirement" **omits `requiresPriv` from the JSON payload entirely** — it must not send a literal `"none"` string. This matters because `PrivSpec.IsZero()` (which drives the "inherited" badge and the empty/unannotated semantics documented in `types.go:23-24`) only returns `true` when the field is completely absent. A literal `"none"` value would make `IsZero()` return `false` (treating the step as "annotated with tier none") and `"none"` isn't a key in `privilegeTierRank`, so it would be silently ranked as `0` — a confusing, unrecognized-value state rather than the clean "inherited" path that already exists.

### 3. `scenarioToYaml()` (`:10538-10546`)

Emit a scalar `requires_priv:` line per step, only when the step has a non-empty `requiresPriv`:

```js
if (st.requiresPriv) out += '    requires_priv: ' + q(st.requiresPriv) + '\n';
```

This keeps the "Download YAML" export consistent with what gets POSTed to the API, and produces the same scalar form documented in `types.go:12` (`requires_priv: admin`).

## Non-goals

- **No `Preferred` tier exposure.** Nothing in the product reads or writes `Preferred` today (see Background). Adding UI for it now would surface a schema capability with no consumer and no way to explain its effect. Revisit only if/when the execution engine gains a use for it (e.g. auto-elevation across tiers).
- **No changes to ART or Caldera modes.** They keep auto-deriving privilege exactly as today.
- **No new display surfaces** beyond the builder form itself (e.g. scenario detail cards, the ART/Caldera picker). Existing privilege-aware displays (Privilege Tier Breakdown, Privilege Tier Coverage panel) are already data-driven off `RequiresPriv` — this change just makes custom steps a real data source for them, with no new rendering code needed elsewhere.
- **No backend or schema changes.** Purely additive UI writing into an already-supported field.

## Testing

No automated frontend test framework exists for `wwwroot/index.html` (established pattern in this codebase — verified manually via browser). Verification plan:

1. Open the Scenario Builder, switch to Custom steps mode, add a step, set "Requires privilege" to Admin, save.
2. Confirm via `GET /api/scenarios/{id}` (or re-opening the builder for edit) that the step's `requiresPriv` round-trips as `"admin"`.
3. Run the scenario with the Run Wizard's Max Privilege set to "User" — confirm the admin-tier step is skipped with `SkipReasonPolicyPrivilege`, and a lower-tier step (or one left at "No requirement") still dispatches.
4. Confirm the run's Privilege Tier Breakdown shows the step under its real tier, not "inherited."
5. Click "Download YAML" and confirm the exported file contains `requires_priv: "admin"` for that step and omits the line entirely for a step left at "No requirement."
6. Edit an existing custom scenario with no `requires_priv` on any step — confirm the dropdown defaults to "No requirement" for all of them (no forced/incorrect default).
