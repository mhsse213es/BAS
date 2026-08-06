# Custom-Step Privilege Field Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a "Requires privilege" dropdown to the Scenario Builder's custom-step editor so hand-authored steps can carry `requires_priv`, the same way ART- and Caldera-derived steps already do.

**Architecture:** Pure frontend change in `orchestrator/wwwroot/index.html`. The backend (`scenario.PrivSpec.UnmarshalJSON`, `CreateScenario`/`UpdateScenario`) already accepts a bare scalar string for `requiresPriv` on write — no backend or schema changes. Three functions change: `addStep()` renders and populates the field, `collectBuilder()` serializes it into the outbound scenario object, `scenarioToYaml()` mirrors it into the YAML export.

**Tech Stack:** Vanilla JS, no build step — `index.html` is edited directly and served as-is.

## Global Constraints

- No backend/Go changes — verified `PrivSpec.UnmarshalJSON` (`orchestrator/internal/scenario/types.go:31-44`) already accepts a scalar string, and `CreateScenario`/`UpdateScenario` decode the request body straight into `scenario.Scenario`.
- "No requirement" must omit `requiresPriv` from the outbound JSON entirely — never send the literal string `"none"`. `PrivSpec.IsZero()` (`types.go:81`) only returns `true` when the field is completely absent, and `"none"` isn't a key in `privilegeTierRank` (`types.go:87-91`), so sending it would silently misclassify the step instead of triggering the existing "inherited" path.
- Only expose `Minimum` (the scalar tier). Do not add a `Preferred` field — nothing in the codebase reads or writes it today (confirmed: `mapARTElevation` and `mapCalderaElevation` both only ever set `Minimum`).
- **Read-path correction vs. the spec:** `PrivSpec.MarshalJSON` (`types.go:47-53`) always emits the **object** form on the way out (`{"minimum":"admin"}` or JSON `null` — never a bare scalar), even though the scalar form is accepted on the way in. This means when `GET /api/scenarios/{id}` returns an existing scenario (used by `fillBuilder()` to populate the edit form), each step's `requiresPriv` is either `null` or `{minimum: "...", preferred?: "..."}` — **not** a plain string. `addStep(st)` must read `st.requiresPriv && st.requiresPriv.minimum`, not `st.requiresPriv` directly. The outbound side (`collectBuilder()`) is unaffected — it can and should send a plain scalar string, since that's valid input and simpler to construct.

---

### Task 1: Add the privilege dropdown to the custom-step editor, wire it through save/load/export, and verify end-to-end

This is one task, not split further — the three edits are small, share no independent test boundary from each other (a dropdown with nothing reading/writing it isn't independently useful), and the whole feature is verified together in one manual pass per the spec's testing plan.

**Files:**
- Modify: `orchestrator/wwwroot/index.html:10356-10382` (`addStep`)
- Modify: `orchestrator/wwwroot/index.html:10437-10446` (`collectBuilder`, the custom-steps branch)
- Modify: `orchestrator/wwwroot/index.html:10538-10546` (`scenarioToYaml`, the steps loop)

**Interfaces:**
- Consumes: existing `x()` HTML-escape helper (`index.html:12867-12870`), existing `q()` YAML-quote helper (local to `scenarioToYaml`, `index.html:10523`), existing `.bld-grid` / `.bld-field` CSS classes already used by the other step fields.
- Produces: each step object built by `collectBuilder()` gains an optional `requiresPriv: "user"|"admin"|"system"` string key (omitted when not set). No other task or function consumes this yet beyond the existing backend/report code that already reads `Step.RequiresPriv` generically.

- [ ] **Step 1: Add the dropdown markup to `addStep()`**

Open `orchestrator/wwwroot/index.html` and find the `.bld-grid` block inside `addStep()` (currently lines 10372-10379):

```js
    '<div class="bld-grid">' +
      '<div class="bld-field"><label>Name</label><input class="st-name" type="text" value="' + x(st.name || '') + '" placeholder="e.g. Dump LSASS"></div>' +
      '<div class="bld-field"><label>Technique ID</label><input class="st-tech" list="att-techniques" type="text" value="' + x(st.techniqueId || '') + '" placeholder="T1003.001"></div>' +
      '<div class="bld-field"><label>Executor</label><select class="st-exec">' + execOpts + '</select></div>' +
      '<div class="bld-field"><label>Timeout (sec)</label><input class="st-timeout" type="number" min="0" value="' + (st.timeoutSec || 60) + '"></div>' +
      '<div class="bld-field full"><label>Command</label><textarea class="st-cmd" rows="2" placeholder="command to run on the endpoint">' + x(st.command || '') + '</textarea></div>' +
      '<div class="bld-field full"><label>Cleanup (optional)</label><textarea class="st-cleanup" rows="1" placeholder="command run after the step">' + x(st.cleanup || '') + '</textarea></div>' +
    '</div>';
```

Replace it with (adds the privilege `<select>` as a 5th grid cell, plus a hint line below the grid — note the read-path correction: `st.requiresPriv` is an object or `null`, so the current tier is `st.requiresPriv && st.requiresPriv.minimum`):

```js
    '<div class="bld-grid">' +
      '<div class="bld-field"><label>Name</label><input class="st-name" type="text" value="' + x(st.name || '') + '" placeholder="e.g. Dump LSASS"></div>' +
      '<div class="bld-field"><label>Technique ID</label><input class="st-tech" list="att-techniques" type="text" value="' + x(st.techniqueId || '') + '" placeholder="T1003.001"></div>' +
      '<div class="bld-field"><label>Executor</label><select class="st-exec">' + execOpts + '</select></div>' +
      '<div class="bld-field"><label>Timeout (sec)</label><input class="st-timeout" type="number" min="0" value="' + (st.timeoutSec || 60) + '"></div>' +
      '<div class="bld-field"><label>Requires privilege</label><select class="st-priv">' + privOpts + '</select></div>' +
      '<div class="bld-field full"><label>Command</label><textarea class="st-cmd" rows="2" placeholder="command to run on the endpoint">' + x(st.command || '') + '</textarea></div>' +
      '<div class="bld-field full"><label>Cleanup (optional)</label><textarea class="st-cleanup" rows="1" placeholder="command run after the step">' + x(st.cleanup || '') + '</textarea></div>' +
    '</div>' +
    '<div class="bld-mode-help">Steps requiring higher privilege than a run\'s Max Privilege ceiling are skipped, not dispatched.</div>';
```

Now add the `privOpts` variable that builds the dropdown's options. Insert it right after the existing `execOpts` block (currently lines 10358-10362):

```js
  var execs = ['powershell','cmd','bash','sh','wmi','mshta','rundll32','cscript','wscript','regsvr32','schtasks'];
  var cur = st.executor || 'powershell';
  var execOpts = execs.map(function(e) {
    return '<option value="' + e + '"' + (e === cur ? ' selected' : '') + '>' + e + '</option>';
  }).join('');
  var privTiers = [['', 'No requirement'], ['user', 'User'], ['admin', 'Admin'], ['system', 'System']];
  var curPriv = (st.requiresPriv && st.requiresPriv.minimum) || '';
  var privOpts = privTiers.map(function(t) {
    return '<option value="' + t[0] + '"' + (t[0] === curPriv ? ' selected' : '') + '>' + t[1] + '</option>';
  }).join('');
```

The full function should now read:

```js
function addStep(st) {
  st = st || {};
  var execs = ['powershell','cmd','bash','sh','wmi','mshta','rundll32','cscript','wscript','regsvr32','schtasks'];
  var cur = st.executor || 'powershell';
  var execOpts = execs.map(function(e) {
    return '<option value="' + e + '"' + (e === cur ? ' selected' : '') + '>' + e + '</option>';
  }).join('');
  var privTiers = [['', 'No requirement'], ['user', 'User'], ['admin', 'Admin'], ['system', 'System']];
  var curPriv = (st.requiresPriv && st.requiresPriv.minimum) || '';
  var privOpts = privTiers.map(function(t) {
    return '<option value="' + t[0] + '"' + (t[0] === curPriv ? ' selected' : '') + '>' + t[1] + '</option>';
  }).join('');
  var div = document.createElement('div');
  div.className = 'bld-step';
  div.innerHTML =
    '<div class="bld-step-hdr"><span class="bld-step-num">Step</span>' +
      '<span class="bld-actions">' +
        '<button type="button" onclick="moveStep(this,-1)" title="Move up">&#9650;</button>' +
        '<button type="button" onclick="moveStep(this,1)" title="Move down">&#9660;</button>' +
        '<button type="button" onclick="removeStep(this)" title="Remove">&#10005;</button>' +
      '</span></div>' +
    '<div class="bld-grid">' +
      '<div class="bld-field"><label>Name</label><input class="st-name" type="text" value="' + x(st.name || '') + '" placeholder="e.g. Dump LSASS"></div>' +
      '<div class="bld-field"><label>Technique ID</label><input class="st-tech" list="att-techniques" type="text" value="' + x(st.techniqueId || '') + '" placeholder="T1003.001"></div>' +
      '<div class="bld-field"><label>Executor</label><select class="st-exec">' + execOpts + '</select></div>' +
      '<div class="bld-field"><label>Timeout (sec)</label><input class="st-timeout" type="number" min="0" value="' + (st.timeoutSec || 60) + '"></div>' +
      '<div class="bld-field"><label>Requires privilege</label><select class="st-priv">' + privOpts + '</select></div>' +
      '<div class="bld-field full"><label>Command</label><textarea class="st-cmd" rows="2" placeholder="command to run on the endpoint">' + x(st.command || '') + '</textarea></div>' +
      '<div class="bld-field full"><label>Cleanup (optional)</label><textarea class="st-cleanup" rows="1" placeholder="command run after the step">' + x(st.cleanup || '') + '</textarea></div>' +
    '</div>' +
    '<div class="bld-mode-help">Steps requiring higher privilege than a run\'s Max Privilege ceiling are skipped, not dispatched.</div>';
  document.getElementById('bld-steps').appendChild(div);
  renumberSteps();
}
```

- [ ] **Step 2: Read the dropdown in `collectBuilder()`**

Find the step-building block inside `collectBuilder()` (currently lines 10437-10445):

```js
      sc.steps.push({
        name: r.querySelector('.st-name').value.trim() || ('Step ' + (i + 1)),
        techniqueId: tech,
        framework: 'custom',
        executor: r.querySelector('.st-exec').value,
        command: r.querySelector('.st-cmd').value,
        timeoutSec: parseInt(r.querySelector('.st-timeout').value, 10) || 60,
        cleanup: r.querySelector('.st-cleanup').value.trim()
      });
```

Replace it with (builds the step object first, then conditionally adds `requiresPriv` so "No requirement" omits the key entirely rather than sending an empty string):

```js
      var newStep = {
        name: r.querySelector('.st-name').value.trim() || ('Step ' + (i + 1)),
        techniqueId: tech,
        framework: 'custom',
        executor: r.querySelector('.st-exec').value,
        command: r.querySelector('.st-cmd').value,
        timeoutSec: parseInt(r.querySelector('.st-timeout').value, 10) || 60,
        cleanup: r.querySelector('.st-cleanup').value.trim()
      };
      var privVal = r.querySelector('.st-priv').value;
      if (privVal) newStep.requiresPriv = privVal;
      sc.steps.push(newStep);
```

- [ ] **Step 3: Emit `requires_priv` in `scenarioToYaml()`**

Find the steps loop inside `scenarioToYaml()` (currently lines 10538-10546):

```js
  if (sc.steps.length) {
    out += 'steps:\n';
    sc.steps.forEach(function(st) {
      out += '  - name: ' + q(st.name) + '\n';
      out += '    technique_id: ' + q(st.techniqueId) + '\n';
      out += '    framework: ' + q(st.framework || 'custom') + '\n';
      out += '    executor: ' + q(st.executor) + '\n';
      out += '    timeout_sec: ' + (st.timeoutSec || 60) + '\n';
      if (st.command) out += '    command: ' + block(st.command, 6) + '\n';
      if (st.cleanup) out += '    cleanup: ' + block(st.cleanup, 6) + '\n';
    });
  }
```

Replace it with (adds one conditional line — `st.requiresPriv` here is the plain scalar string `collectBuilder()` just produced, e.g. `"admin"`, since `scenarioToYaml()` is always called on `collectBuilder()`'s output, never on API response data):

```js
  if (sc.steps.length) {
    out += 'steps:\n';
    sc.steps.forEach(function(st) {
      out += '  - name: ' + q(st.name) + '\n';
      out += '    technique_id: ' + q(st.techniqueId) + '\n';
      out += '    framework: ' + q(st.framework || 'custom') + '\n';
      out += '    executor: ' + q(st.executor) + '\n';
      out += '    timeout_sec: ' + (st.timeoutSec || 60) + '\n';
      if (st.requiresPriv) out += '    requires_priv: ' + q(st.requiresPriv) + '\n';
      if (st.command) out += '    command: ' + block(st.command, 6) + '\n';
      if (st.cleanup) out += '    cleanup: ' + block(st.cleanup, 6) + '\n';
    });
  }
```

- [ ] **Step 4: Confirm the file still parses cleanly**

Run:

```bash
node --check orchestrator/wwwroot/index.html 2>&1 | head -5
```

This will report a syntax error pointing at the `<!DOCTYPE...` line — that's expected and fine (it's an HTML file, not raw JS); the point of this step is only to catch a mismatched brace/quote introduced by the edits. If the error message is anything other than a complaint about the leading HTML (e.g. `Unexpected token`/`Unexpected end of input` deep inside the file, past line 10300), stop and fix the syntax before continuing. As a second check, extract just the `<script>` block and check that instead:

```bash
node -e "
  const fs = require('fs');
  const html = fs.readFileSync('orchestrator/wwwroot/index.html', 'utf8');
  const m = html.match(/<script>([\s\S]*)<\/script>/);
  new Function(m[1]);
  console.log('script block parses OK');
"
```

Expected: `script block parses OK`. If it throws, the error message will include a line number relative to the script block's start — fix before continuing.

- [ ] **Step 5: Manual browser verification**

No automated frontend test framework exists for this file (established pattern in this codebase). Start the dashboard locally (however this project is normally run — e.g. `docker compose up` or the existing dev server) and in a browser:

1. Open the Scenario Builder ("+ New Scenario"), switch Execution mode to "Custom steps — define each command yourself", click "+ Add step". Confirm the new "Requires privilege" dropdown appears as a 5th field next to Timeout, defaulted to "No requirement", with the hint line ("Steps requiring higher privilege...") visible below the grid.
2. Set the step's Requires privilege to "Admin", fill in a Technique ID (required) and Name, click "Save". Confirm no error and the drawer closes.
3. Reopen the same scenario for edit ("Edit Scenario"). Confirm the step's "Requires privilege" dropdown shows "Admin" (proves the round-trip through `GET /api/scenarios/{id}`'s object-form `requiresPriv` and `addStep()`'s `st.requiresPriv.minimum` read works).
4. Add a second step to the same scenario, leave its Requires privilege at "No requirement", save. Reopen for edit — confirm the second step's dropdown still shows "No requirement" (proves omission round-trips correctly, not defaulting to some other value).
5. Open the Run Wizard for this scenario, pick a target agent, on the Options step set "Max privilege" to "User", run it. Confirm the Admin-tier step is skipped (check the run results for a skip reason mentioning privilege) while the "No requirement" step still dispatches.
6. In the run's results, check the Privilege Tier Breakdown — confirm the Admin step is shown under the "Admin" tier, not tagged "inherited".
7. Reopen the scenario builder for this scenario and click "Download YAML". Open the downloaded file and confirm it contains a `requires_priv: "admin"` line under the first step, and no `requires_priv` line at all under the second step.

If any of these fail, stop and report — do not proceed to commit with a known-broken round-trip.

- [ ] **Step 6: Commit**

```bash
git add orchestrator/wwwroot/index.html
git commit -m "$(cat <<'EOF'
feat(scenario-builder): add privilege field to custom steps

Custom steps had no way to declare requires_priv, unlike ART/Caldera
steps which get it auto-derived from technique metadata. Adds a
"Requires privilege" dropdown to the step editor; the backend already
accepts the scalar wire format so no server-side changes are needed.
EOF
)"
git push
```

(Per this repo's convention, push immediately after committing.)

---

## Self-Review Notes

- **Spec coverage:** all three spec-listed function changes (`addStep`, `collectBuilder`, `scenarioToYaml`) are covered in Steps 1-3; the "omit, don't send `none`" requirement is implemented in Step 2 via the `if (privVal)` guard; the "No `Preferred` exposure" non-goal is respected — only `.minimum` is read/written; the spec's 6-point testing plan is covered by Step 5's 7 checks (split #3/#4 of the spec's plan into two explicit checks for clarity, one per privilege state).
- **Placeholder scan:** none — all steps contain literal, complete code.
- **Type consistency:** `st.requiresPriv` (inbound, object-or-null) vs `newStep.requiresPriv` (outbound, scalar string) are documented as intentionally different shapes in the Global Constraints' read-path correction, and both usages within the plan match that documented asymmetry.
