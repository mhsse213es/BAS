# Group Picker Modal — Design

## Why

The Agents tab's group-management UI is entirely built on native `prompt()`/
`confirm()` dialogs. Two of those prompts ask the user to type a raw numeric
`agent_groups.id` — but that ID is never displayed anywhere in the UI (the
group tree shows only name + agent count), so there is no way to actually use
them. Confirmed via direct user testing this session: a user created a group
by typing its name, then had no way to discover the ID needed to move an
agent into it.

This is scoped to the two ID-entry prompts specifically — not a rebuild of
the whole group-management interaction (the "type: rename/new/move/delete"
kebab meta-prompt and the name-only create/rename prompts stay as-is for
now, a deliberate V1 scope decision).

## What's broken

- `moveAgentToGroupPrompt(agentId)` (`wwwroot/index.html:6650`) — the Agents
  table row-menu's "Move to group…" action (Admin-only). Prompts: *"Move to
  group ID (blank for Ungrouped):"*. No ID is visible anywhere.
- `moveAgentGroupPrompt(groupId)` (`wwwroot/index.html:6632`) — reached via
  the group tree's kebab menu → typing `"move"` into the meta-prompt.
  Prompts: *"Move to parent group ID (blank for root):"*. Same problem.

Both call already-correct, unchanged backend endpoints
(`PATCH /api/agents/{agentId}/group`, `PATCH /api/agent-groups/{id}`) — the
bug is purely in how the target group is selected client-side.

## Design

One new shared modal handles both flows — they're the same interaction
("pick a group from a list") with a different target and endpoint:

```
#group-picker-overlay (new)
  <h3> — dynamic title: "Move Agent to Group" / "Move Group to New Parent"
  <select id="gp-select"> — flattened group tree, indented by depth,
                             plus a top "— Ungrouped —" / "— Root (no parent) —" option
  <div class="modal-actions">
    [Cancel] [Move]
```

Reuses the existing `.overlay` / `.modal` / `.modal-lbl` / `.modal-actions` /
`.btn` classes already used by every other small modal in this file (e.g.
`#respond-overlay`) — no new visual language.

**`openGroupPicker(mode, contextId)`** — `mode` is `'agent'` or `'group'`.
Populates `#gp-select` from `agentGroupTree` (the Agents tab's already-loaded
nested tree — this modal is only ever opened from that tab, so no new fetch
is needed), flattened depth-first with indentation prefixed onto each
option's label (e.g. `"— Servers"` for a child of "Production") so the
hierarchy stays legible in a flat `<select>`. For `'group'` mode, the group
being moved (`contextId`) is excluded from its own option list — a cheap
client-side guard against the obvious "move a group under itself" mistake.
Deeper cycles (moving a group under one of its own descendants) are not
filtered client-side; the backend's existing cycle check
(`internal/api/agent_groups_handlers.go:136-159`, already correct and
unchanged by this spec) rejects those with a clear 400 error, surfaced via
the existing `showToast(res.error, 'err')` pattern — the modal stays open
on that error so the user can pick a different option, rather than closing
and forcing a retry from scratch.

**On confirm:**
- `mode === 'agent'`: `PATCH /api/agents/{contextId}/group` with
  `{groupId: selected || null}` — identical request shape
  `moveAgentToGroupPrompt` already sends today.
- `mode === 'group'`: `PATCH /api/agent-groups/{contextId}` with
  `{parentId: selected || null}` — identical request shape
  `moveAgentGroupPrompt` already sends today.

On success: close the modal, `showToast('Moved', 'ok')`, refresh
(`loadAgents()` for agent mode, `loadAgentGroupTree()` for group mode —
exactly the refresh calls each prompt's success handler already makes today).

**`moveAgentToGroupPrompt(agentId)` and `moveAgentGroupPrompt(groupId)` keep
their exact names and signatures.** Their bodies become one-line calls into
`openGroupPicker('agent', agentId)` / `openGroupPicker('group', groupId)`.
Every existing call site — the agent row-menu's `onclick`, and
`openAgentGroupMenu`'s `else if (action === 'move')` dispatch — needs zero
changes.

## Non-goals

- No change to `openAgentGroupMenu`'s "type: rename/new/move/delete"
  meta-prompt, or to `createAgentGroupPrompt`/`renameAgentGroupPrompt`
  (name-only prompts, no ID problem — explicitly out of scope per this
  session's scope decision).
- No new backend endpoint or backend change of any kind — both PATCH
  endpoints and the existing cycle-check are already correct and untouched.
- No descendant-cycle pre-filtering client-side — the server's existing
  check is the correctness boundary; the client only guards the trivial
  self-parent case for a slightly better first-try experience.

## Testing plan

No automated frontend test suite exists for this file (established project
convention). Verification is the same Node.js syntax-check pattern used
throughout this session's frontend work
(`awk '/^<script>$/{...}/^<\/script>$/{...}flag' index.html | node --check`)
plus reading back the edited regions for well-formedness. Manual browser QA
(opening the picker from both entry points, confirming the option list and
both success/error paths) is deferred to the project's existing Pending
Manual QA Backlog pattern, not blocking implementation.
