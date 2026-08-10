# Group Picker Modal Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the two raw numeric-ID `prompt()` dialogs used to move an agent into a group or reparent a group with one shared dropdown modal populated from the already-loaded group tree.

**Architecture:** One new modal (`#group-picker-overlay`) and one small cluster of JS functions (`openGroupPicker`, `closeGroupPicker`, `submitGroupPicker`, `gpFlattenGroups`). `moveAgentToGroupPrompt`/`moveAgentGroupPrompt` keep their exact names and signatures — only their bodies change, from a `prompt()` to a one-line call into the new picker — so every existing call site needs zero changes.

**Tech Stack:** Vanilla JS (ES5-style syntax matching this file's convention, ES6 built-ins like `.repeat()`/`Object.keys` are already used elsewhere and fine to use here), inline CSS reuse, no build step.

## Global Constraints

- Frontend-only. No `.go` file touched by this plan.
- `openAgentGroupMenu`'s "type: rename/new/move/delete" meta-prompt,
  `createAgentGroupPrompt`, `renameAgentGroupPrompt`, and
  `deleteAgentGroupConfirm` are explicitly out of scope — do not modify them.
- No new backend endpoint. Both PATCH endpoints
  (`/api/agents/{agentId}/group`, `/api/agent-groups/{id}`) and the
  backend's existing parent-cycle check are already correct and unchanged.
- The group-picker's dropdown excludes only the group being moved itself
  (for the reparent flow) — it does not pre-filter descendant groups.
  Deeper cycles are caught by the existing backend check and surfaced via
  the standard `showToast(res.error, 'err')` error path, with the modal
  staying open so the user can pick again.
- No automated frontend test suite exists (established project
  convention). Verification is a Node.js syntax-check of the file's single
  inline `<script>` block, plus reading back edited regions for
  well-formedness.

---

## Verification helper

```bash
cd orchestrator/wwwroot
awk '/^<script>$/{flag=1;next}/^<\/script>$/{flag=0}flag' index.html > /tmp/group-picker-check.js
node --check /tmp/group-picker-check.js
```

Expected on success: no output, exit code 0.

---

### Task 1: Group Picker modal

**Files:**
- Modify: `orchestrator/wwwroot/index.html:3989-3991` (insert modal markup)
- Modify: `orchestrator/wwwroot/index.html:6630-6657` (insert new JS block, swap two function bodies)

**Interfaces:**
- Consumes: `agentGroupTree` (existing global, nested `{id, name, totalAgentCount, children}` tree), `x()`/`showToast()`/`apicall()` (existing), `loadAgents()`/`loadAgentGroupTree()` (existing refresh functions).
- Produces: `openGroupPicker(mode, contextId)` (`mode` is `'agent'` or `'group'`), `closeGroupPicker()`, `submitGroupPicker()`, `gpFlattenGroups(nodes, depth, excludeId, out)`. Nothing later consumes these — this is the only task.

This is one task: the modal markup, the picker functions, and the two call-site swaps only make sense verified together — a modal with no way to open it, or an `openGroupPicker` with no modal to populate, are equally useless in isolation.

- [ ] **Step 1: Add the modal markup**

Find this exact block (the end of `#remove-agent-overlay`, immediately followed by the Technique/Ability Picker comment):

```html
    <div class="modal-actions">
      <button class="btn btn-outline btn-sm" onclick="closeRemoveAgentModal()">Cancel</button>
      <span style="flex:1"></span>
      <button id="remove-agent-submit-btn" class="btn btn-sm" style="color:#fff;background:var(--danger)" onclick="submitRemoveAgent()">&#128465; Force Remove</button>
    </div>
  </div>
</div>

<!-- Technique / Ability Picker -->
```

Replace it with:

```html
    <div class="modal-actions">
      <button class="btn btn-outline btn-sm" onclick="closeRemoveAgentModal()">Cancel</button>
      <span style="flex:1"></span>
      <button id="remove-agent-submit-btn" class="btn btn-sm" style="color:#fff;background:var(--danger)" onclick="submitRemoveAgent()">&#128465; Force Remove</button>
    </div>
  </div>
</div>

<!-- Group Picker (Move Agent to Group / Move Group to New Parent) -->
<div id="group-picker-overlay" class="overlay">
  <div class="modal" style="width:400px">
    <h3 id="gp-title">Move to Group</h3>
    <label class="modal-lbl">Group</label>
    <select id="gp-select" style="width:100%"></select>
    <div class="modal-actions">
      <button class="btn btn-outline btn-sm" onclick="closeGroupPicker()">Cancel</button>
      <span style="flex:1"></span>
      <button class="btn btn-primary btn-sm" onclick="submitGroupPicker()">Move</button>
    </div>
  </div>
</div>

<!-- Technique / Ability Picker -->
```

- [ ] **Step 2: Add the picker JS and swap the two function bodies**

Find this exact block (`renameAgentGroupPrompt`'s end through `moveAgentGroupPrompt`'s full body):

```js
function renameAgentGroupPrompt(groupId) {
  var name = prompt('New name:');
  if (!name) return;
  apicall('/api/agent-groups/' + groupId, { method: 'PATCH', body: JSON.stringify({ name: name }) })
    .then(function(res) { if (res && res.error) { showToast(res.error, 'err'); return; } loadAgentGroupTree(); })
    .catch(function(e) { showToast(e.message, 'err'); });
}

function moveAgentGroupPrompt(groupId) {
  var newParent = prompt('Move to parent group ID (blank for root):');
  if (newParent === null) return;
  var parentId = newParent.trim() === '' ? null : parseInt(newParent, 10);
  apicall('/api/agent-groups/' + groupId, { method: 'PATCH', body: JSON.stringify({ parentId: parentId }) })
    .then(function(res) { if (res && res.error) { showToast(res.error, 'err'); return; } loadAgentGroupTree(); })
    .catch(function(e) { showToast(e.message, 'err'); });
}
```

Replace it with:

```js
function renameAgentGroupPrompt(groupId) {
  var name = prompt('New name:');
  if (!name) return;
  apicall('/api/agent-groups/' + groupId, { method: 'PATCH', body: JSON.stringify({ name: name }) })
    .then(function(res) { if (res && res.error) { showToast(res.error, 'err'); return; } loadAgentGroupTree(); })
    .catch(function(e) { showToast(e.message, 'err'); });
}

// gpFlattenGroups walks the nested group tree depth-first into a flat list
// of {id, label} entries for the picker's <select>, indenting each label by
// its depth so the hierarchy stays legible in a flat list. excludeId (used
// only for the group-reparent flow) skips that one node's own entry -- its
// children are still included, since the backend's existing cycle check
// (agent_groups_handlers.go's UpdateAgentGroup) is the real guard against
// picking a deeper invalid target, not this client-side list.
function gpFlattenGroups(nodes, depth, excludeId, out) {
  (nodes || []).forEach(function(n) {
    if (n.id !== excludeId) {
      out.push({ id: n.id, label: (depth > 0 ? '— '.repeat(depth) : '') + n.name });
    }
    if (n.children && n.children.length) gpFlattenGroups(n.children, depth + 1, excludeId, out);
  });
  return out;
}

var _gpMode = null, _gpContextId = null;

function openGroupPicker(mode, contextId) {
  _gpMode = mode;
  _gpContextId = contextId;
  document.getElementById('gp-title').textContent = mode === 'agent' ? 'Move Agent to Group' : 'Move Group to New Parent';
  var excludeId = mode === 'group' ? contextId : null;
  var options = gpFlattenGroups(agentGroupTree, 0, excludeId, []);
  var topLabel = mode === 'agent' ? '— Ungrouped —' : '— Root (no parent) —';
  document.getElementById('gp-select').innerHTML = '<option value="">' + topLabel + '</option>' +
    options.map(function(o) { return '<option value="' + x(o.id) + '">' + x(o.label) + '</option>'; }).join('');
  document.getElementById('group-picker-overlay').classList.add('open');
}

function closeGroupPicker() {
  document.getElementById('group-picker-overlay').classList.remove('open');
  _gpMode = null;
  _gpContextId = null;
}

function submitGroupPicker() {
  var selected = document.getElementById('gp-select').value;
  var groupId = selected === '' ? null : parseInt(selected, 10);
  var mode = _gpMode, contextId = _gpContextId;
  var url, body, onSuccess;
  if (mode === 'agent') {
    url = '/api/agents/' + encodeURIComponent(contextId) + '/group';
    body = { groupId: groupId };
    onSuccess = function() { loadAgents(); };
  } else {
    url = '/api/agent-groups/' + contextId;
    body = { parentId: groupId };
    onSuccess = function() { loadAgentGroupTree(); };
  }
  apicall(url, { method: 'PATCH', body: JSON.stringify(body) }).then(function(res) {
    if (res && res.error) { showToast(res.error, 'err'); return; }
    closeGroupPicker();
    showToast('Moved', 'ok');
    onSuccess();
  }).catch(function(e) { showToast(e.message, 'err'); });
}

function moveAgentGroupPrompt(groupId) {
  openGroupPicker('group', groupId);
}
```

- [ ] **Step 3: Swap `moveAgentToGroupPrompt`'s body**

Find this exact block:

```js
function moveAgentToGroupPrompt(agentId) {
  var newGroup = prompt('Move to group ID (blank for Ungrouped):');
  if (newGroup === null) return;
  var groupId = newGroup.trim() === '' ? null : parseInt(newGroup, 10);
  apicall('/api/agents/' + encodeURIComponent(agentId) + '/group', { method: 'PATCH', body: JSON.stringify({ groupId: groupId }) })
    .then(function(res) { if (res && res.error) { showToast(res.error, 'err'); return; } loadAgents(); })
    .catch(function(e) { showToast(e.message, 'err'); });
}
```

Replace it with:

```js
function moveAgentToGroupPrompt(agentId) {
  openGroupPicker('agent', agentId);
}
```

- [ ] **Step 4: Syntax-check**

```bash
cd orchestrator/wwwroot
awk '/^<script>$/{flag=1;next}/^<\/script>$/{flag=0}flag' index.html > /tmp/group-picker-check.js
node --check /tmp/group-picker-check.js
```

Expected: no output, exit code 0.

- [ ] **Step 5: Read back both edited regions to confirm well-formedness**

Use the `Read` tool on `orchestrator/wwwroot/index.html` around `id="group-picker-overlay"` and around `function gpFlattenGroups` (search to find current line numbers) and confirm: the modal's tags are balanced; `moveAgentGroupPrompt`/`moveAgentToGroupPrompt` no longer contain any `prompt(` calls; `openAgentGroupMenu`'s dispatch line (`else if (action === 'move') moveAgentGroupPrompt(groupId);`) and the Agents-tab row-menu's `onclick="closeAllRowMenus();moveAgentToGroupPrompt(...)"` are both unchanged (confirm via `grep -n "moveAgentToGroupPrompt\|moveAgentGroupPrompt"` — each function name should appear exactly once as a `function` declaration and at its one pre-existing call site, plus `moveAgentGroupPrompt`'s new call from inside `openGroupPicker`... no, `openGroupPicker` doesn't call `moveAgentGroupPrompt` — confirm the call-site count simply hasn't grown beyond the two pre-existing sites for each name).

- [ ] **Step 6: Commit**

```bash
git add orchestrator/wwwroot/index.html
git commit -m "feat(ui): Group Picker modal replaces raw group-ID prompts"
```

---

## Self-Review

**1. Spec coverage:**
- One shared modal for both flows, dynamic title — Step 1.
- `gpFlattenGroups` indents by depth, excludes only the group itself (not descendants) for reparent mode — Step 2.
- Backend cycle-check reuse (no client-side descendant filtering), error surfaced via existing `showToast` pattern, modal stays open on error (the `.then` handler returns without calling `closeGroupPicker()` when `res.error` is set) — Step 2's `submitGroupPicker`.
- Both PATCH endpoints and request shapes identical to the prompts they replace (`{groupId}` / `{parentId}`) — Step 2/3.
- `moveAgentToGroupPrompt`/`moveAgentGroupPrompt` keep exact names/signatures, zero other call sites touched — Steps 2-3, verified in Step 5.
- `openAgentGroupMenu`, `createAgentGroupPrompt`, `renameAgentGroupPrompt`, `deleteAgentGroupConfirm` untouched — none of these appear in any old_string/new_string block in this plan.
- No backend changes — no `.go` file appears anywhere in this plan.

**2. Placeholder scan:** no TBD/TODO; every step has literal exact-match old/new code; single task, no "similar to Task N" risk.

**3. Type consistency:** `mode` is used identically as the string `'agent'`/`'group'` everywhere it appears (`openGroupPicker`'s parameter, `submitGroupPicker`'s branch, the two call sites in the swapped function bodies). `gpFlattenGroups`'s `{id, label}` output shape matches exactly what `openGroupPicker`'s `.map()` call reads (`o.id`, `o.label`).
