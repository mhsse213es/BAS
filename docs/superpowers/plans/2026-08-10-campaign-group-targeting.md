# Campaign Group Targeting Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add Agent Group (single group, live-resolved server-side at launch) and Admin-only All Agents as Campaign targeting modes, alongside the existing explicit Agents mode, with a matching frontend redesign of the "New Campaign" modal and small additions to the campaign list/detail views.

**Architecture:** `CreateCampaign` gains a `targetType` request field (`agents | group | all`). For `group`, it resolves live membership server-side by reusing the already-shipped, already-tested `internal/jobs.Store.ResolveGroupAgentIDs`. For `all`, it resolves every non-retired agent, gated Admin-only by a new `CanTargetAllAgents` permission. The resolved set (minus any `excludeAgentIds`) becomes the frozen `campaigns.targets` snapshot exactly as it already does today — no change to how a campaign executes once targets are known. Two new nullable-by-default columns (`target_type`, `target_group_id`) record how the snapshot was produced, for display and audit. The Run Scenario wizard is untouched.

**Tech Stack:** Go (`internal/api`, `internal/auth`, `internal/campaign`, `internal/db`), PostgreSQL, vanilla JS in `orchestrator/wwwroot/index.html` (no build step, no framework).

## Global Constraints

- No new database table. `campaigns` gains exactly two columns:
  `target_type text NOT NULL DEFAULT 'agents'`, `target_group_id bigint`
  (nullable). Every existing campaign row reads as `target_type='agents'`
  with zero backfill needed.
- No new backend package and no refactor of `GET /api/agents`'s existing
  inline recursive-CTE query. `CreateCampaign` reuses the already-shipped
  `internal/jobs.Store.ResolveGroupAgentIDs(ctx, groupIDs []int64) ([]string, error)`
  directly (single-element slice for the single-group case). `internal/jobs`
  itself is not modified by this plan.
- A Campaign targets exactly one thing: a single group, an explicit agent
  list, or the entire eligible fleet — never a combination. No multi-group
  selection.
- `target_type == "all"` is Admin-only, enforced server-side via a new
  `CanTargetAllAgents` permission (not client-trust, not a reused
  unrelated permission). The frontend hiding the option for non-Admins is
  a UX simplification, not the security boundary.
- No new HTTP endpoint for the live preview. The frontend reuses the
  already-existing `GET /api/agents?groupId=X`, which already performs
  the identical recursive-descendant resolution.
- The Run Scenario wizard (`run-overlay`, `wizardSet`, `data-pane`/`data-pip`)
  is not touched by this plan.
- No automated frontend test suite exists for `wwwroot/index.html`
  (established project convention). Frontend task verification is a
  Node.js syntax-check of the file's single inline `<script>` block plus
  reading back edited regions — do not invent a JS test framework.

---

## Verification helper (frontend tasks)

```bash
cd orchestrator/wwwroot
awk '/^<script>$/{flag=1;next}/^<\/script>$/{flag=0}flag' index.html > /tmp/campaign-ui-check.js
node --check /tmp/campaign-ui-check.js
```

Expected on success: no output, exit code 0.

---

### Task 1: Backend — CreateCampaign group/all/exclusions targeting

**Files:**
- Modify: `orchestrator/internal/db/postgres.go:249` (schema)
- Modify: `orchestrator/internal/auth/permissions.go:44-45` (new `CanTargetAllAgents` const), `:215` (RoleAdmin map — grant it), `:299` (`Permissions()` enumeration). **Not** added to the RoleAnalyst map (Admin-only).
- Modify: `orchestrator/internal/auth/permissions_test.go:38-42` (`TestHasPermission_FullMatrix`), `:76` (`TestHasPermission_MatrixIsComplete`'s `tested` map), `:128` (`TestPermissions_Ordering`'s `want` slice)
- Modify: `orchestrator/internal/api/campaign_handlers.go:23-131` (`CreateCampaign`)
- Modify: `orchestrator/internal/api/campaign_crud_test.go` (new tests + new `seedAgentGroup` helper)

**Interfaces:**
- Consumes: `internal/jobs.Store.ResolveGroupAgentIDs(ctx, groupIDs []int64) ([]string, error)` (existing, unchanged), `h.jobsStore *jobs.Store` (existing `Handler` field, already unconditionally wired in production via `cmd/server/main.go:454`), `auth.ClaimsFrom(ctx)` / `auth.HasPermission(role, perm)` (existing).
- Produces: `auth.CanTargetAllAgents` (new permission constant). `campaigns.target_type`/`campaigns.target_group_id` columns. `CreateCampaign` now accepts `targetType`/`groupId`/`excludeAgentIds` in its request body — Task 2 reads the stored `target_type`/`target_group_id` back out in `GetCampaign`/`ListCampaigns`.

- [ ] **Step 1: Write the failing tests**

In `orchestrator/internal/api/campaign_crud_test.go`, add this helper near the top of the file (after the existing `createCampaignReq` function):

```go
// seedAgentGroup inserts a group and returns its id. If agentIDs is non-empty,
// each of those agents is assigned to the group (they must already exist —
// call seedActiveAgent first).
func seedAgentGroup(t *testing.T, pool *pgxpool.Pool, name string, agentIDs ...string) int64 {
	t.Helper()
	var groupID int64
	if err := pool.QueryRow(context.Background(),
		`INSERT INTO agent_groups (name) VALUES ($1) RETURNING id`, name,
	).Scan(&groupID); err != nil {
		t.Fatalf("seed agent group: %v", err)
	}
	for _, agentID := range agentIDs {
		if _, err := pool.Exec(context.Background(),
			`UPDATE agents SET group_id = $1 WHERE agent_id = $2`, groupID, agentID); err != nil {
			t.Fatalf("assign agent %s to group: %v", agentID, err)
		}
	}
	return groupID
}
```

Then add these tests to the same file:

```go
func TestCreateCampaign_GroupTargeting_ResolvesLiveMembership(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		sc, engine := minimalPostureScenario(t, "cc-group-sc")
		seedActiveAgent(t, pool, "cc-group-a1", "Windows")
		seedActiveAgent(t, pool, "cc-group-a2", "Windows")
		seedActiveAgent(t, pool, "cc-group-outside", "Windows")
		groupID := seedAgentGroup(t, pool, "cc-group-finance", "cc-group-a1", "cc-group-a2")

		jobsStore := jobs.NewStore(pool)
		h := New(pool, ws.NewHub(), engine, "").WithJobsDispatcher(jobsStore, jobs.NewDispatcher(jobsStore))
		rec := httptest.NewRecorder()
		h.CreateCampaign(rec, createCampaignReq(map[string]any{
			"name": "x", "scenarioId": sc.ID, "targetType": "group", "groupId": groupID,
		}))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}
		var resp struct {
			Dispatched int `json:"dispatched"`
		}
		json.Unmarshal(rec.Body.Bytes(), &resp)
		if resp.Dispatched != 2 {
			t.Errorf("dispatched = %d, want 2 (cc-group-a1, cc-group-a2 — not cc-group-outside)", resp.Dispatched)
		}
	})
}

func TestCreateCampaign_GroupTargeting_MissingGroupID_BadRequest(t *testing.T) {
	sc, engine := minimalPostureScenario(t, "cc-group-missing-sc")
	h := New(nil, ws.NewHub(), engine, "")
	rec := httptest.NewRecorder()
	h.CreateCampaign(rec, createCampaignReq(map[string]any{
		"name": "x", "scenarioId": sc.ID, "targetType": "group",
	}))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 (groupId required for group targeting)", rec.Code)
	}
}

func TestCreateCampaign_AllAgents_AnalystForbidden(t *testing.T) {
	sc, engine := minimalPostureScenario(t, "cc-all-forbidden-sc")
	h := New(nil, ws.NewHub(), engine, "")
	req := createCampaignReq(map[string]any{
		"name": "x", "scenarioId": sc.ID, "targetType": "all",
	})
	req = req.WithContext(auth.ContextWithClaims(req.Context(), &auth.Claims{UserID: "analyst-1", Role: auth.RoleAnalyst}))
	rec := httptest.NewRecorder()
	h.CreateCampaign(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 (all-agents targeting is Admin-only), body = %s", rec.Code, rec.Body.String())
	}
}

func TestCreateCampaign_AllAgents_AdminSucceeds_ExcludesRetired(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		sc, engine := minimalPostureScenario(t, "cc-all-sc")
		seedActiveAgent(t, pool, "cc-all-a1", "Windows")
		seedActiveAgent(t, pool, "cc-all-a2", "Windows")
		if _, err := pool.Exec(context.Background(),
			`INSERT INTO agents (agent_id, hostname, os_version, state) VALUES ('cc-all-retired','h','Windows','retired')`); err != nil {
			t.Fatalf("seed retired agent: %v", err)
		}
		h := New(pool, ws.NewHub(), engine, "")
		req := createCampaignReq(map[string]any{
			"name": "x", "scenarioId": sc.ID, "targetType": "all",
		})
		req = req.WithContext(auth.ContextWithClaims(req.Context(), &auth.Claims{UserID: "admin-1", Role: auth.RoleAdmin}))
		rec := httptest.NewRecorder()
		h.CreateCampaign(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}
		var resp struct {
			Dispatched int `json:"dispatched"`
		}
		json.Unmarshal(rec.Body.Bytes(), &resp)
		if resp.Dispatched != 2 {
			t.Errorf("dispatched = %d, want 2 (cc-all-a1, cc-all-a2 — cc-all-retired excluded)", resp.Dispatched)
		}
	})
}

func TestCreateCampaign_Exclusions_SubtractedFromResolvedSet(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		sc, engine := minimalPostureScenario(t, "cc-excl-sc")
		seedActiveAgent(t, pool, "cc-excl-a1", "Windows")
		seedActiveAgent(t, pool, "cc-excl-a2", "Windows")
		groupID := seedAgentGroup(t, pool, "cc-excl-group", "cc-excl-a1", "cc-excl-a2")

		jobsStore := jobs.NewStore(pool)
		h := New(pool, ws.NewHub(), engine, "").WithJobsDispatcher(jobsStore, jobs.NewDispatcher(jobsStore))
		rec := httptest.NewRecorder()
		h.CreateCampaign(rec, createCampaignReq(map[string]any{
			"name": "x", "scenarioId": sc.ID, "targetType": "group", "groupId": groupID,
			"excludeAgentIds": []string{"cc-excl-a2"},
		}))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}
		var resp struct {
			Dispatched int `json:"dispatched"`
		}
		json.Unmarshal(rec.Body.Bytes(), &resp)
		if resp.Dispatched != 1 {
			t.Errorf("dispatched = %d, want 1 (cc-excl-a1 only — cc-excl-a2 excluded)", resp.Dispatched)
		}
	})
}

func TestCreateCampaign_LegacyRequest_DefaultsToAgentsMode(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		sc, engine := minimalPostureScenario(t, "cc-legacy-sc")
		seedActiveAgent(t, pool, "cc-legacy-a1", "Windows")
		h := New(pool, ws.NewHub(), engine, "")
		rec := httptest.NewRecorder()
		// No targetType field at all — must behave exactly as before this change.
		h.CreateCampaign(rec, createCampaignReq(map[string]any{
			"name": "x", "scenarioId": sc.ID, "agentIds": []string{"cc-legacy-a1"},
		}))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}
	})
}
```

Add the new imports this test file needs — find the existing `import (...)` block in `campaign_crud_test.go` and add `"github.com/audspect/bas/internal/jobs"` to it (alongside the existing `"github.com/audspect/bas/internal/auth"`, `"github.com/audspect/bas/internal/models"`, etc.).

- [ ] **Step 2: Run the tests to verify they fail**

```bash
cd orchestrator
go vet ./internal/api/... ./internal/auth/...
```

Expected: compile errors — `req.TargetType`/`req.GroupID`/`req.ExcludeAgentIDs` undefined on the request struct, and `undefined: auth.CanTargetAllAgents`. (`go build` won't show these since they're test-only references — use `go vet`, which compiles test files too, exactly as established earlier this session.)

- [ ] **Step 3: Add the schema migration**

In `orchestrator/internal/db/postgres.go`, find this exact block:

```go
		`ALTER TABLE scenario_runs ADD COLUMN IF NOT EXISTS campaign_id text`,
		`CREATE INDEX IF NOT EXISTS idx_scenario_runs_campaign ON scenario_runs (campaign_id)`,
```

Replace it with:

```go
		`ALTER TABLE scenario_runs ADD COLUMN IF NOT EXISTS campaign_id text`,
		`CREATE INDEX IF NOT EXISTS idx_scenario_runs_campaign ON scenario_runs (campaign_id)`,
		// target_type/target_group_id record how a campaign's frozen `targets`
		// snapshot was produced (explicit list / a resolved group / the whole
		// fleet) -- for display and audit, not re-resolution. Every existing
		// campaign row reads as target_type='agents', which is simply true:
		// every campaign created before this column existed was an explicit
		// agent list.
		`ALTER TABLE campaigns ADD COLUMN IF NOT EXISTS target_type text NOT NULL DEFAULT 'agents'`,
		`ALTER TABLE campaigns ADD COLUMN IF NOT EXISTS target_group_id bigint`,
```

- [ ] **Step 4: Add the `CanTargetAllAgents` permission**

In `orchestrator/internal/auth/permissions.go`, find this exact block:

```go
	CanCreateCampaign   Permission = "campaigns:create"
	CanStopCampaign     Permission = "campaigns:stop"
```

Replace it with:

```go
	CanCreateCampaign   Permission = "campaigns:create"
	CanStopCampaign     Permission = "campaigns:stop"
	// CanTargetAllAgents is Admin-only, unlike every other campaign
	// permission in this block -- targeting the entire fleet in one launch
	// is a materially bigger blast radius than targeting a group or an
	// explicit list, so it gets its own stricter gate rather than riding
	// on CanCreateCampaign.
	CanTargetAllAgents Permission = "campaigns:target-all-agents"
```

Next, in the same file, find this exact line (inside `rolePermissions[RoleAdmin]`):

```go
		CanRunDetectionVerification: true, CanCreateCampaign: true, CanStopCampaign: true,
```

This line appears twice in the file — once inside `RoleAdmin`'s map (~line 215) and once inside `RoleAnalyst`'s map (~line 264). Replace **only the first occurrence** (`RoleAdmin`'s — confirm by checking you are editing the block that starts with `RoleAdmin: {` above it, not `RoleAnalyst: {`) with:

```go
		CanRunDetectionVerification: true, CanCreateCampaign: true, CanStopCampaign: true, CanTargetAllAgents: true,
```

Do **not** touch the `RoleAnalyst` occurrence of this line — Analyst does not get `CanTargetAllAgents`.

Next, in the same file, find this exact line (inside `Permissions()`'s enumeration):

```go
		CanRunDetectionVerification, CanCreateCampaign, CanStopCampaign, CanSetFindingStatus,
```

Replace it with:

```go
		CanRunDetectionVerification, CanCreateCampaign, CanStopCampaign, CanTargetAllAgents, CanSetFindingStatus,
```

- [ ] **Step 5: Update the three permission test guards**

In `orchestrator/internal/auth/permissions_test.go`, find this exact block (inside `TestHasPermission_FullMatrix`):

```go
		{RoleAdmin, CanViewAgentGroups, true},
		{RoleAnalyst, CanViewAgentGroups, true},
		{RoleViewer, CanViewAgentGroups, false},
	}
```

Replace it with:

```go
		{RoleAdmin, CanViewAgentGroups, true},
		{RoleAnalyst, CanViewAgentGroups, true},
		{RoleViewer, CanViewAgentGroups, false},

		{RoleAdmin, CanTargetAllAgents, true},
		{RoleAnalyst, CanTargetAllAgents, false},
		{RoleViewer, CanTargetAllAgents, false},
	}
```

Next, in the same file, find this exact line (inside `TestHasPermission_MatrixIsComplete`'s `tested` map):

```go
		CanRunDetectionVerification: true, CanCreateCampaign: true, CanStopCampaign: true,
```

Replace it with:

```go
		CanRunDetectionVerification: true, CanCreateCampaign: true, CanStopCampaign: true, CanTargetAllAgents: true,
```

Next, in the same file, find this exact line (inside `TestPermissions_Ordering`'s `want` slice):

```go
		CanRunDetectionVerification, CanCreateCampaign, CanStopCampaign, CanSetFindingStatus,
```

Replace it with:

```go
		CanRunDetectionVerification, CanCreateCampaign, CanStopCampaign, CanTargetAllAgents, CanSetFindingStatus,
```

- [ ] **Step 6: Update `CreateCampaign`'s request struct and validation**

In `orchestrator/internal/api/campaign_handlers.go`, find this exact block:

```go
	var req struct {
		Name            string                   `json:"name"`
		ScenarioID      string                   `json:"scenarioId"`
		AgentIDs        []string                 `json:"agentIds"`
		Mode            string                   `json:"mode"`
		ConfirmLive     bool                     `json:"confirmLive"`
		ConfirmLab      bool                     `json:"confirmLab"`
		Reason          string                   `json:"reason"`
		Techniques      []string                 `json:"techniques"`
		Abilities       []string                 `json:"abilities"`
		Steps           []int                    `json:"steps"`
		Checks          []string                 `json:"checks"`
		Notes           string                   `json:"notes"`
		Tags            []string                 `json:"tags"`
		ExecutionPolicy scenario.ExecutionPolicy `json:"executionPolicy,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Name == "" || req.ScenarioID == "" || len(req.AgentIDs) == 0 {
		jsonError(w, "name, scenarioId and at least one agentId are required", http.StatusBadRequest)
		return
	}
```

Replace it with:

```go
	var req struct {
		Name            string                   `json:"name"`
		ScenarioID      string                   `json:"scenarioId"`
		AgentIDs        []string                 `json:"agentIds"`
		Mode            string                   `json:"mode"`
		ConfirmLive     bool                     `json:"confirmLive"`
		ConfirmLab      bool                     `json:"confirmLab"`
		Reason          string                   `json:"reason"`
		Techniques      []string                 `json:"techniques"`
		Abilities       []string                 `json:"abilities"`
		Steps           []int                    `json:"steps"`
		Checks          []string                 `json:"checks"`
		Notes           string                   `json:"notes"`
		Tags            []string                 `json:"tags"`
		ExecutionPolicy scenario.ExecutionPolicy `json:"executionPolicy,omitempty"`
		TargetType      string                   `json:"targetType"`
		GroupID         *int64                   `json:"groupId"`
		ExcludeAgentIDs []string                 `json:"excludeAgentIds"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Name == "" || req.ScenarioID == "" {
		jsonError(w, "name and scenarioId are required", http.StatusBadRequest)
		return
	}
	// targetType defaults to "agents" -- every campaign created before this
	// field existed was, in fact, an explicit agent list, so an absent
	// targetType must behave exactly as it always has.
	targetType := req.TargetType
	if targetType == "" {
		targetType = "agents"
	}
	switch targetType {
	case "agents":
		if len(req.AgentIDs) == 0 {
			jsonError(w, "at least one agentId is required for agents targeting", http.StatusBadRequest)
			return
		}
	case "group":
		if req.GroupID == nil {
			jsonError(w, "groupId is required for group targeting", http.StatusBadRequest)
			return
		}
	case "all":
		// Admin-only: targeting the entire fleet is a materially bigger blast
		// radius than a group or an explicit list. The frontend hides this
		// option for non-Admins as a UX simplification -- this check is the
		// actual security boundary.
		claims, ok := auth.ClaimsFrom(r.Context())
		if !ok || !auth.HasPermission(claims.Role, auth.CanTargetAllAgents) {
			jsonError(w, "targeting all agents requires Administrator access", http.StatusForbidden)
			return
		}
	default:
		jsonError(w, "targetType must be agents, group, or all", http.StatusBadRequest)
		return
	}
```

- [ ] **Step 7: Add resolution logic and use the resolved set everywhere `req.AgentIDs` was used**

Find this exact block (immediately following the live-execution guardrails, before `var initiatedBy *string`):

```go
	var initiatedBy *string
	if c, ok := auth.ClaimsFrom(r.Context()); ok && c != nil {
		initiatedBy = &c.UserID
	}

	id := newID()
	subset, _ := json.Marshal(map[string]any{
		"techniques": req.Techniques, "abilities": req.Abilities, "steps": req.Steps, "checks": req.Checks,
		"executionPolicy": req.ExecutionPolicy,
	})
	targets, _ := json.Marshal(req.AgentIDs)
	tags, _ := json.Marshal(req.Tags)
	if _, err := h.db.Exec(r.Context(),
		`INSERT INTO campaigns (id, name, scenario_id, scenario_name, mode, subset, reason, targets, notes, tags, created_by)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
		id, req.Name, sc.ID, sc.Name, mode, subset, req.Reason, targets, req.Notes, tags, initiatedBy); err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	opts := dispatchOpts{
		Mode: mode, ConfirmLive: req.ConfirmLive, ConfirmLab: req.ConfirmLab, Reason: req.Reason,
		Techniques: req.Techniques, Abilities: req.Abilities, Steps: req.Steps, Checks: req.Checks,
		CampaignID: id, InitiatedBy: initiatedBy, MaxPrivilege: req.ExecutionPolicy.MaxPrivilege,
	}
	skips := []map[string]string{}
	dispatched := 0
	for _, agentID := range req.AgentIDs {
		_, skip, err := h.dispatchRun(r.Context(), sc, agentID, opts)
```

Replace it with:

```go
	// Resolve the target set for this targetType. "agents" uses the request's
	// explicit list unchanged; "group" resolves live membership right now
	// (reusing the Fleet Job Engine's already-tested recursive resolver, not
	// a second copy of the query); "all" is every non-retired agent. The
	// result becomes the frozen `targets` snapshot below -- from this point
	// on, later changes to group membership never retroactively affect this
	// campaign.
	var targetAgentIDs []string
	switch targetType {
	case "group":
		if h.jobsStore == nil {
			jsonError(w, "job engine not loaded", http.StatusServiceUnavailable)
			return
		}
		resolved, rerr := h.jobsStore.ResolveGroupAgentIDs(r.Context(), []int64{*req.GroupID})
		if rerr != nil {
			jsonError(w, rerr.Error(), http.StatusInternalServerError)
			return
		}
		targetAgentIDs = resolved
	case "all":
		rows, qerr := h.db.Query(r.Context(), `SELECT agent_id FROM agents WHERE COALESCE(state, 'active') != 'retired'`)
		if qerr != nil {
			jsonError(w, qerr.Error(), http.StatusInternalServerError)
			return
		}
		for rows.Next() {
			var aid string
			if rows.Scan(&aid) == nil {
				targetAgentIDs = append(targetAgentIDs, aid)
			}
		}
		rows.Close()
	default:
		targetAgentIDs = req.AgentIDs
	}
	if len(req.ExcludeAgentIDs) > 0 {
		excl := make(map[string]bool, len(req.ExcludeAgentIDs))
		for _, aid := range req.ExcludeAgentIDs {
			excl[aid] = true
		}
		filtered := make([]string, 0, len(targetAgentIDs))
		for _, aid := range targetAgentIDs {
			if !excl[aid] {
				filtered = append(filtered, aid)
			}
		}
		targetAgentIDs = filtered
	}
	if len(targetAgentIDs) == 0 {
		jsonError(w, "no targets resolved for this campaign", http.StatusBadRequest)
		return
	}

	var initiatedBy *string
	if c, ok := auth.ClaimsFrom(r.Context()); ok && c != nil {
		initiatedBy = &c.UserID
	}

	id := newID()
	subset, _ := json.Marshal(map[string]any{
		"techniques": req.Techniques, "abilities": req.Abilities, "steps": req.Steps, "checks": req.Checks,
		"executionPolicy": req.ExecutionPolicy,
	})
	targets, _ := json.Marshal(targetAgentIDs)
	tags, _ := json.Marshal(req.Tags)
	if _, err := h.db.Exec(r.Context(),
		`INSERT INTO campaigns (id, name, scenario_id, scenario_name, mode, subset, reason, targets, notes, tags, created_by, target_type, target_group_id)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`,
		id, req.Name, sc.ID, sc.Name, mode, subset, req.Reason, targets, req.Notes, tags, initiatedBy, targetType, req.GroupID); err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	opts := dispatchOpts{
		Mode: mode, ConfirmLive: req.ConfirmLive, ConfirmLab: req.ConfirmLab, Reason: req.Reason,
		Techniques: req.Techniques, Abilities: req.Abilities, Steps: req.Steps, Checks: req.Checks,
		CampaignID: id, InitiatedBy: initiatedBy, MaxPrivilege: req.ExecutionPolicy.MaxPrivilege,
	}
	skips := []map[string]string{}
	dispatched := 0
	for _, agentID := range targetAgentIDs {
		_, skip, err := h.dispatchRun(r.Context(), sc, agentID, opts)
```

- [ ] **Step 8: Run the tests to verify they pass**

```bash
cd orchestrator
go build ./...
go vet ./internal/api/... ./internal/auth/...
go test ./internal/auth/... -v
```

Expected: clean build, `go vet` clean, `internal/auth` tests all PASS (including the three you modified).

```bash
go test ./internal/api/... -run TestCreateCampaign -v
```

Expected: every `TestCreateCampaign_*` test PASSES, including the 5 new ones and every pre-existing one (`TestCreateCampaign_ValidationErrors`, `TestCreateCampaign_ScenarioNotFound`, `TestCreateCampaign_InvalidMode`, `TestCreateCampaign_LiveModeRequiresConfirm`, `TestCreateCampaign_NonExecutableScenario_LiveRejected`, and any others matching that prefix) — confirming the refactor didn't change any existing behavior.

- [ ] **Step 9: Commit**

```bash
cd orchestrator
git add internal/db/postgres.go internal/auth/permissions.go internal/auth/permissions_test.go internal/api/campaign_handlers.go internal/api/campaign_crud_test.go
git commit -m "feat(api): Campaign group and all-agents targeting"
```

---

### Task 2: Backend — GetCampaign/ListCampaigns response additions

**Files:**
- Modify: `orchestrator/internal/api/campaign_handlers.go:133-142` (`campaignRow` struct), `:192-211` (`loadCampaign`), `:353-372` (`GetCampaign`), `:228-243` (`ListCampaigns`)
- Modify: `orchestrator/internal/campaign/store.go:16-25` (`Rollup` struct), `:34-81` (`ListWithRollups`)
- Modify: `orchestrator/internal/api/campaign_crud_test.go` (new tests)

**Interfaces:**
- Consumes: `campaigns.target_type`/`campaigns.target_group_id` columns (Task 1).
- Produces: `GET /api/campaigns/{id}` response gains `targetType`/`targetGroupId`. `GET /api/campaigns` (list) response items gain the same two fields. Task 3/4's frontend read these exact camelCase keys.

- [ ] **Step 1: Write the failing tests**

Add to `orchestrator/internal/api/campaign_crud_test.go`:

```go
func TestGetCampaign_ReturnsTargetTypeAndGroupID(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		sc, engine := minimalPostureScenario(t, "gc-target-sc")
		seedActiveAgent(t, pool, "gc-target-a1", "Windows")
		groupID := seedAgentGroup(t, pool, "gc-target-group", "gc-target-a1")

		jobsStore := jobs.NewStore(pool)
		h := New(pool, ws.NewHub(), engine, "").WithJobsDispatcher(jobsStore, jobs.NewDispatcher(jobsStore))
		createRec := httptest.NewRecorder()
		h.CreateCampaign(createRec, createCampaignReq(map[string]any{
			"name": "x", "scenarioId": sc.ID, "targetType": "group", "groupId": groupID,
		}))
		var createResp struct {
			CampaignID string `json:"campaignId"`
		}
		json.Unmarshal(createRec.Body.Bytes(), &createResp)

		req := httptest.NewRequest(http.MethodGet, "/api/campaigns/"+createResp.CampaignID, nil)
		req = withURLParam(req, "id", createResp.CampaignID)
		rec := httptest.NewRecorder()
		h.GetCampaign(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}
		var resp struct {
			TargetType    string `json:"targetType"`
			TargetGroupID *int64 `json:"targetGroupId"`
		}
		json.Unmarshal(rec.Body.Bytes(), &resp)
		if resp.TargetType != "group" {
			t.Errorf("targetType = %q, want %q", resp.TargetType, "group")
		}
		if resp.TargetGroupID == nil || *resp.TargetGroupID != groupID {
			t.Errorf("targetGroupId = %v, want %d", resp.TargetGroupID, groupID)
		}
	})
}

func TestListCampaigns_ReturnsTargetType(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		sc, engine := minimalPostureScenario(t, "lc-target-sc")
		seedActiveAgent(t, pool, "lc-target-a1", "Windows")
		h := New(pool, ws.NewHub(), engine, "")
		createRec := httptest.NewRecorder()
		h.CreateCampaign(createRec, createCampaignReq(map[string]any{
			"name": "x", "scenarioId": sc.ID, "agentIds": []string{"lc-target-a1"},
		}))
		if createRec.Code != http.StatusOK {
			t.Fatalf("create status = %d, body = %s", createRec.Code, createRec.Body.String())
		}

		req := httptest.NewRequest(http.MethodGet, "/api/campaigns", nil)
		rec := httptest.NewRecorder()
		h.ListCampaigns(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}
		var resp []struct {
			TargetType string `json:"targetType"`
		}
		json.Unmarshal(rec.Body.Bytes(), &resp)
		if len(resp) == 0 {
			t.Fatal("expected at least one campaign in the list")
		}
		found := false
		for _, c := range resp {
			if c.TargetType == "agents" {
				found = true
			}
		}
		if !found {
			t.Error("expected at least one campaign with targetType 'agents'")
		}
	})
}
```

- [ ] **Step 2: Run the tests to verify they fail**

```bash
cd orchestrator
go test ./internal/api/... -run "TestGetCampaign_ReturnsTargetTypeAndGroupID|TestListCampaigns_ReturnsTargetType" -v
```

Expected: FAIL — `targetType`/`targetGroupId` are absent from both responses (JSON-unmarshal into a field with no matching key leaves it at its zero value, so `TargetType` reads as `""` instead of `"group"`/`"agents"`).

- [ ] **Step 3: Add the fields to `campaignRow`, `loadCampaign`, and `GetCampaign`**

In `orchestrator/internal/api/campaign_handlers.go`, find this exact block:

```go
// campaignRow mirrors the stored campaign for JSON output and rollup.
type campaignRow struct {
	ID, Name, ScenarioID, ScenarioName, Mode, Reason, Notes, CreatedBy string
	Targets                                                            []string
	Skips                                                              []campaign.Skip
	Tags                                                               []string
	CreatedAt                                                          time.Time
	StartedAt                                                          time.Time
	Stopped                                                            bool
}
```

Replace it with:

```go
// campaignRow mirrors the stored campaign for JSON output and rollup.
type campaignRow struct {
	ID, Name, ScenarioID, ScenarioName, Mode, Reason, Notes, CreatedBy string
	Targets                                                            []string
	Skips                                                              []campaign.Skip
	Tags                                                               []string
	CreatedAt                                                          time.Time
	StartedAt                                                          time.Time
	Stopped                                                            bool
	TargetType                                                         string
	TargetGroupID                                                      *int64
}
```

Next, find this exact block (`loadCampaign`):

```go
	err := h.db.QueryRow(ctx,
		`SELECT id, name, scenario_id, scenario_name, mode, reason, notes,
		        COALESCE(created_by,''), targets, skips, tags, created_at, started_at, stopped_at
		   FROM campaigns WHERE id=$1`, id,
	).Scan(&c.ID, &c.Name, &c.ScenarioID, &c.ScenarioName, &c.Mode, &c.Reason, &c.Notes,
		&c.CreatedBy, &targetsRaw, &skipsRaw, &tagsRaw, &c.CreatedAt, &c.StartedAt, &stoppedAt)
```

Replace it with:

```go
	err := h.db.QueryRow(ctx,
		`SELECT id, name, scenario_id, scenario_name, mode, reason, notes,
		        COALESCE(created_by,''), targets, skips, tags, created_at, started_at, stopped_at,
		        target_type, target_group_id
		   FROM campaigns WHERE id=$1`, id,
	).Scan(&c.ID, &c.Name, &c.ScenarioID, &c.ScenarioName, &c.Mode, &c.Reason, &c.Notes,
		&c.CreatedBy, &targetsRaw, &skipsRaw, &tagsRaw, &c.CreatedAt, &c.StartedAt, &stoppedAt,
		&c.TargetType, &c.TargetGroupID)
```

Next, find this exact block (`GetCampaign`'s response):

```go
	respond(w, map[string]any{
		"id": c.ID, "name": c.Name, "scenarioId": c.ScenarioID, "scenarioName": c.ScenarioName,
		"mode": c.Mode, "reason": c.Reason, "notes": c.Notes, "tags": c.Tags,
		"targets": c.Targets, "skips": c.Skips, "createdBy": c.CreatedBy,
		"startedAt": c.StartedAt, "summary": s, "runs": children,
	})
```

Replace it with:

```go
	respond(w, map[string]any{
		"id": c.ID, "name": c.Name, "scenarioId": c.ScenarioID, "scenarioName": c.ScenarioName,
		"mode": c.Mode, "reason": c.Reason, "notes": c.Notes, "tags": c.Tags,
		"targets": c.Targets, "skips": c.Skips, "createdBy": c.CreatedBy,
		"startedAt": c.StartedAt, "summary": s, "runs": children,
		"targetType": c.TargetType, "targetGroupId": c.TargetGroupID,
	})
```

- [ ] **Step 4: Add the fields to `campaign.Rollup` and `ListWithRollups`**

In `orchestrator/internal/campaign/store.go`, find this exact block:

```go
type Rollup struct {
	ID           string    `json:"id"`
	Name         string    `json:"name"`
	ScenarioID   string    `json:"scenarioId"`
	ScenarioName string    `json:"scenarioName"`
	Mode         string    `json:"mode"`
	CreatedBy    string    `json:"createdBy"`
	StartedAt    time.Time `json:"startedAt"`
	Summary      Summary   `json:"summary"`
}
```

Replace it with:

```go
type Rollup struct {
	ID            string    `json:"id"`
	Name          string    `json:"name"`
	ScenarioID    string    `json:"scenarioId"`
	ScenarioName  string    `json:"scenarioName"`
	Mode          string    `json:"mode"`
	CreatedBy     string    `json:"createdBy"`
	StartedAt     time.Time `json:"startedAt"`
	Summary       Summary   `json:"summary"`
	TargetType    string    `json:"targetType"`
	TargetGroupID *int64    `json:"targetGroupId"`
}
```

Next, find this exact block:

```go
	rows, err := pool.Query(ctx, `
		SELECT id, name, scenario_id, scenario_name, mode, COALESCE(created_by,''), skips, started_at, stopped_at
		  FROM campaigns ORDER BY started_at DESC`)
	if err != nil {
		return nil, err
	}
	type campRow struct {
		id, name, scenarioID, scenarioName, mode, createdBy string
		skipsRaw                                            []byte
		startedAt                                           time.Time
		stoppedAt                                           *time.Time
	}
	var camps []campRow
	for rows.Next() {
		var c campRow
		if err := rows.Scan(&c.id, &c.name, &c.scenarioID, &c.scenarioName, &c.mode,
			&c.createdBy, &c.skipsRaw, &c.startedAt, &c.stoppedAt); err != nil {
			rows.Close()
			return nil, err
		}
		camps = append(camps, c)
	}
```

Replace it with:

```go
	rows, err := pool.Query(ctx, `
		SELECT id, name, scenario_id, scenario_name, mode, COALESCE(created_by,''), skips, started_at, stopped_at,
		       target_type, target_group_id
		  FROM campaigns ORDER BY started_at DESC`)
	if err != nil {
		return nil, err
	}
	type campRow struct {
		id, name, scenarioID, scenarioName, mode, createdBy string
		skipsRaw                                            []byte
		startedAt                                           time.Time
		stoppedAt                                           *time.Time
		targetType                                          string
		targetGroupID                                       *int64
	}
	var camps []campRow
	for rows.Next() {
		var c campRow
		if err := rows.Scan(&c.id, &c.name, &c.scenarioID, &c.scenarioName, &c.mode,
			&c.createdBy, &c.skipsRaw, &c.startedAt, &c.stoppedAt,
			&c.targetType, &c.targetGroupID); err != nil {
			rows.Close()
			return nil, err
		}
		camps = append(camps, c)
	}
```

Next, find this exact block:

```go
		out = append(out, Rollup{
			ID: c.id, Name: c.name, ScenarioID: c.scenarioID, ScenarioName: c.scenarioName,
			Mode: c.mode, CreatedBy: c.createdBy, StartedAt: c.startedAt, Summary: s,
		})
```

Replace it with:

```go
		out = append(out, Rollup{
			ID: c.id, Name: c.name, ScenarioID: c.scenarioID, ScenarioName: c.scenarioName,
			Mode: c.mode, CreatedBy: c.createdBy, StartedAt: c.startedAt, Summary: s,
			TargetType: c.targetType, TargetGroupID: c.targetGroupID,
		})
```

- [ ] **Step 5: Add the fields to `ListCampaigns`'s response map**

In `orchestrator/internal/api/campaign_handlers.go`, find this exact block:

```go
	out := make([]map[string]any, 0, len(rollups))
	for _, c := range rollups {
		out = append(out, map[string]any{
			"id": c.ID, "name": c.Name, "scenarioId": c.ScenarioID, "scenarioName": c.ScenarioName,
			"mode": c.Mode, "createdBy": c.CreatedBy, "startedAt": c.StartedAt, "summary": c.Summary,
		})
	}
```

Replace it with:

```go
	out := make([]map[string]any, 0, len(rollups))
	for _, c := range rollups {
		out = append(out, map[string]any{
			"id": c.ID, "name": c.Name, "scenarioId": c.ScenarioID, "scenarioName": c.ScenarioName,
			"mode": c.Mode, "createdBy": c.CreatedBy, "startedAt": c.StartedAt, "summary": c.Summary,
			"targetType": c.TargetType, "targetGroupId": c.TargetGroupID,
		})
	}
```

- [ ] **Step 6: Run the tests to verify they pass**

```bash
cd orchestrator
go build ./...
go test ./internal/api/... -run "TestGetCampaign_ReturnsTargetTypeAndGroupID|TestListCampaigns_ReturnsTargetType|TestGetCampaign_|TestListCampaigns_" -v
```

Expected: PASS, including the two new tests and every pre-existing `TestGetCampaign_*`/`TestListCampaigns_*` test (confirming the additive change didn't break the existing rollup/detail behavior).

```bash
go test ./internal/campaign/...
```

Expected: PASS.

- [ ] **Step 7: Commit**

```bash
cd orchestrator
git add internal/api/campaign_handlers.go internal/campaign/store.go internal/api/campaign_crud_test.go
git commit -m "feat(api): surface Campaign targetType/targetGroupId in GetCampaign and ListCampaigns"
```

---

### Task 3: Frontend — "New Campaign" modal redesign

**Files:**
- Modify: `orchestrator/wwwroot/index.html:4047-4098` (`#campaign-overlay` markup)
- Modify: `orchestrator/wwwroot/index.html` (`openCampaignLaunch`, `closeCampaignLaunch`, `submitCampaign` — all ~7463-7745 pre-Task-3, exact anchors re-verified at execution time)

**Interfaces:**
- Consumes: `GET /api/agent-groups` (existing, returns the nested group tree — same shape already consumed by Scheduled Assessments' `SCHED.groups`), `GET /api/agents?groupId=X` (existing, live recursive resolution + full agent objects), `ROLE` global (existing), `x()`/`apicall()`/`showToast()` (existing).
- Produces: new `CMP` state additions (`CMP.groups`, `CMP.groupsById`, `CMP.selectedGroupId`, `CMP.exclusions`), `cmpFlattenGroupNames(nodes, map)`, `cmpOnTargetTypeChange()`, `cmpOnGroupChange()`, `renderCampaignGroupPreview(agents)`, `cmpToggleExclusion(agentId, checked)`. Task 4 reads `CMP.groupsById` for the list/detail group-name lookups (a lighter-weight alternative: Task 4 can also just re-derive names from the group tree fetched fresh, same as Scheduled Assessments' list view does — either is acceptable, decided at Task 4 execution time since both are equally simple).

**Note on `CMP` vs `SCHED`:** this codebase's established convention (set explicitly during the Scheduled Assessments UI work) is that each feature gets its own state object and its own group-tree-flattening function rather than reaching into another feature's — `renderSchedGroupTree` did not reuse the pre-existing `renderAgentGroupTree`, and this task follows the same precedent: a new `CMP` object, not a reach into `SCHED`.

- [ ] **Step 1: Redesign the Campaign Targets section markup**

Find this exact block (the current Targets section of `#campaign-overlay`):

```html
    <label class="modal-lbl">Targets <span class="tiny muted" id="cmp-target-cnt">(0 selected)</span></label>
    <div style="display:flex;gap:0.5rem;margin-bottom:0.4rem">
      <select id="cmp-filter-os" onchange="renderCampaignTargets()" style="flex:1"><option value="">All OS</option><option value="windows">Windows</option><option value="linux">Linux</option><option value="darwin">macOS</option></select>
      <select id="cmp-filter-env" onchange="renderCampaignTargets()" style="flex:1"><option value="">All environments</option></select>
      <button class="btn btn-outline btn-sm" onclick="cmpSelectAllFiltered()">Select all</button>
    </div>
    <div id="cmp-targets" style="max-height:200px;overflow:auto;border:1px solid var(--border);border-radius:var(--radius);padding:0.4rem"></div>
    <label class="modal-lbl">Notes (optional)</label>
```

Replace it with:

```html
    <label class="modal-lbl" style="margin-top:0.9rem;display:block">Campaign Targets</label>
    <select id="cmp-target-type" onchange="cmpOnTargetTypeChange()">
      <option value="agents">Agents</option>
      <option value="group">Agent Group</option>
    </select>

    <div id="cmp-target-agents-wrap">
      <label class="modal-lbl" style="margin-top:0.6rem;display:block">Agents <span class="tiny muted" id="cmp-target-cnt">(0 selected)</span></label>
      <div style="display:flex;gap:0.5rem;margin-bottom:0.4rem">
        <select id="cmp-filter-os" onchange="renderCampaignTargets()" style="flex:1"><option value="">All OS</option><option value="windows">Windows</option><option value="linux">Linux</option><option value="darwin">macOS</option></select>
        <select id="cmp-filter-env" onchange="renderCampaignTargets()" style="flex:1"><option value="">All environments</option></select>
        <button class="btn btn-outline btn-sm" onclick="cmpSelectAllFiltered()">Select all</button>
      </div>
      <div id="cmp-targets" style="max-height:200px;overflow:auto;border:1px solid var(--border);border-radius:var(--radius);padding:0.4rem"></div>
    </div>

    <div id="cmp-target-group-wrap" style="display:none;margin-top:0.6rem">
      <label class="modal-lbl">Agent Group</label>
      <select id="cmp-group" onchange="cmpOnGroupChange()"></select>
      <div id="cmp-group-preview" style="margin-top:0.5rem;font-size:0.78rem;color:var(--muted)"></div>
      <label class="modal-lbl" style="margin-top:0.7rem;display:block">Exclude agents <span class="tiny muted" id="cmp-excl-cnt">(0 excluded)</span></label>
      <div id="cmp-exclusions" style="max-height:150px;overflow:auto;border:1px solid var(--border);border-radius:var(--radius);padding:0.4rem"></div>
    </div>

    <label class="modal-lbl">Notes (optional)</label>
```

- [ ] **Step 2: Add the All Agents option, Admin-only**

Find this exact block (still inside `#campaign-overlay`, immediately below the `Notes` input — the modal-actions footer):

```html
    <label class="modal-lbl">Notes (optional)</label>
    <input id="cmp-notes" type="text" placeholder="optional" style="width:100%;padding:0.5rem 0.7rem;background:var(--elevated);border:1px solid var(--border);border-radius:var(--radius);color:var(--text);font-family:inherit">
    <div class="modal-actions">
      <button class="btn btn-outline btn-sm" onclick="closeCampaignLaunch()">Cancel</button>
      <button class="btn btn-primary btn-sm" onclick="submitCampaign()">&#9654; Launch</button>
    </div>
```

Replace it with:

```html
    <label class="modal-lbl">Notes (optional)</label>
    <input id="cmp-notes" type="text" placeholder="optional" style="width:100%;padding:0.5rem 0.7rem;background:var(--elevated);border:1px solid var(--border);border-radius:var(--radius);color:var(--text);font-family:inherit">
    <div id="cmp-target-all-wrap" style="display:none;margin-top:0.6rem;padding:0.6rem 0.75rem;border-radius:var(--radius);border:1px solid rgba(218,54,51,0.5);background:rgba(218,54,51,0.08)">
      <div id="cmp-all-count" style="font-size:0.8rem;font-weight:600;color:var(--danger);margin-bottom:0.4rem"></div>
      <label style="display:flex;align-items:center;gap:0.5rem;cursor:pointer;font-size:0.8rem">
        <input type="checkbox" id="cmp-all-confirm" onchange="document.getElementById('cmp-launch-btn').disabled=!this.checked">
        I understand this will execute against all eligible agents.
      </label>
    </div>
    <div class="modal-actions">
      <button class="btn btn-outline btn-sm" onclick="closeCampaignLaunch()">Cancel</button>
      <button class="btn btn-primary btn-sm" id="cmp-launch-btn" onclick="submitCampaign()">&#9654; Launch</button>
    </div>
```

- [ ] **Step 3: Add the "All Agents" `<option>` conditionally, and wire up state reset**

Find this exact block (`openCampaignLaunch`):

```js
function openCampaignLaunch() {
  if (!scenarios.length) { showToast('Scenarios not loaded yet', 'err'); return; }
  if (!agents.length) { showToast('No agents registered yet', 'err'); return; }
  document.getElementById('cmp-name').value = '';
  document.getElementById('cmp-notes').value = '';
  document.getElementById('cmp-scenario').innerHTML = scenarios.map(function(s) {
    return '<option value="' + x(s.id) + '">' + x(s.name) + '</option>';
  }).join('');
  document.getElementById('cmp-mode').value = 'posture';
  var envs = {};
  agents.forEach(function(a) { if (a.envLabel) envs[a.envLabel] = true; });
  document.getElementById('cmp-filter-env').innerHTML = '<option value="">All environments</option>' +
    Object.keys(envs).map(function(e) { return '<option value="' + x(e) + '">' + x(e) + '</option>'; }).join('');
  _cmpSel = {};
  renderCampaignTargets();
  document.getElementById('campaign-overlay').classList.add('open');
}
```

Replace it with:

```js
var CMP = { groups: [], groupsById: {}, exclusions: {} };

function cmpFlattenGroupNames(nodes, map) {
  (nodes || []).forEach(function(n) {
    map[n.id] = n.name;
    if (n.children && n.children.length) cmpFlattenGroupNames(n.children, map);
  });
  return map;
}

function openCampaignLaunch() {
  if (!scenarios.length) { showToast('Scenarios not loaded yet', 'err'); return; }
  if (!agents.length) { showToast('No agents registered yet', 'err'); return; }
  document.getElementById('cmp-name').value = '';
  document.getElementById('cmp-notes').value = '';
  document.getElementById('cmp-scenario').innerHTML = scenarios.map(function(s) {
    return '<option value="' + x(s.id) + '">' + x(s.name) + '</option>';
  }).join('');
  document.getElementById('cmp-mode').value = 'posture';
  var envs = {};
  agents.forEach(function(a) { if (a.envLabel) envs[a.envLabel] = true; });
  document.getElementById('cmp-filter-env').innerHTML = '<option value="">All environments</option>' +
    Object.keys(envs).map(function(e) { return '<option value="' + x(e) + '">' + x(e) + '</option>'; }).join('');
  _cmpSel = {};
  CMP.exclusions = {};
  var typeSel = document.getElementById('cmp-target-type');
  var opts = '<option value="agents">Agents</option><option value="group">Agent Group</option>';
  if (ROLE === 'admin') opts += '<option value="all">All Agents</option>';
  typeSel.innerHTML = opts;
  typeSel.value = 'agents';
  document.getElementById('cmp-all-confirm').checked = false;
  document.getElementById('cmp-launch-btn').disabled = false;
  apicall('/api/agent-groups').then(function(res) {
    CMP.groups = Array.isArray(res) ? res : [];
    CMP.groupsById = cmpFlattenGroupNames(CMP.groups, {});
    var groupSel = document.getElementById('cmp-group');
    groupSel.innerHTML = Object.keys(CMP.groupsById).map(function(id) {
      return '<option value="' + x(id) + '">' + x(CMP.groupsById[id]) + '</option>';
    }).join('');
  }).catch(function() { CMP.groups = []; CMP.groupsById = {}; });
  renderCampaignTargets();
  cmpOnTargetTypeChange();
  document.getElementById('campaign-overlay').classList.add('open');
}
```

- [ ] **Step 4: Add the targeting-mode switch, live preview, and exclusion checklist**

Insert immediately before the existing `function closeCampaignLaunch()` line:

```js
function cmpOnTargetTypeChange() {
  var type = document.getElementById('cmp-target-type').value;
  document.getElementById('cmp-target-agents-wrap').style.display = (type === 'agents') ? 'block' : 'none';
  document.getElementById('cmp-target-group-wrap').style.display = (type === 'group') ? 'block' : 'none';
  document.getElementById('cmp-target-all-wrap').style.display = (type === 'all') ? 'block' : 'none';
  var launchBtn = document.getElementById('cmp-launch-btn');
  if (type === 'all') {
    launchBtn.disabled = !document.getElementById('cmp-all-confirm').checked;
    var count = agents.filter(function(a) { return a.state !== 'retired'; }).length;
    document.getElementById('cmp-all-count').textContent = '⚠ This campaign will execute against ' + count + ' agents.';
  } else {
    launchBtn.disabled = false;
  }
  if (type === 'group') cmpOnGroupChange();
}

function cmpOnGroupChange() {
  var groupId = document.getElementById('cmp-group').value;
  CMP.exclusions = {};
  if (!groupId) { document.getElementById('cmp-group-preview').innerHTML = ''; document.getElementById('cmp-exclusions').innerHTML = ''; return; }
  apicall('/api/agents?groupId=' + encodeURIComponent(groupId)).then(function(list) {
    renderCampaignGroupPreview(Array.isArray(list) ? list : []);
  }).catch(function() { renderCampaignGroupPreview([]); });
}

function renderCampaignGroupPreview(list) {
  var osCounts = {};
  var online = 0, offline = 0;
  list.forEach(function(a) {
    var os = cmpAgentOS(a);
    osCounts[os] = (osCounts[os] || 0) + 1;
    if (a.status === 'offline') offline++; else online++;
  });
  var osLine = Object.keys(osCounts).map(function(os) { return osCounts[os] + ' ' + os; }).join(' · ');
  document.getElementById('cmp-group-preview').innerHTML =
    '<div>' + list.length + ' agents — ' + osLine + '</div>' +
    '<div>' + online + ' online · ' + offline + ' offline</div>';
  document.getElementById('cmp-exclusions').innerHTML = list.map(function(a) {
    return '<label style="display:flex;align-items:center;gap:0.5rem;padding:0.25rem 0.3rem;cursor:pointer">' +
      '<input type="checkbox" onchange="cmpToggleExclusion(\'' + x(a.agentId) + '\',this.checked)">' +
      '<code style="font-size:0.72rem">' + x(a.agentId) + '</code><span class="tiny muted">' + x(a.hostname) + '</span></label>';
  }).join('');
  cmpUpdateExclusionCount();
}

function cmpToggleExclusion(agentId, checked) {
  if (checked) CMP.exclusions[agentId] = true; else delete CMP.exclusions[agentId];
  cmpUpdateExclusionCount();
}

function cmpUpdateExclusionCount() {
  document.getElementById('cmp-excl-cnt').textContent = '(' + Object.keys(CMP.exclusions).length + ' excluded)';
}

```

- [ ] **Step 5: Update `submitCampaign` to send `targetType`/`groupId`/`excludeAgentIds`**

Find this exact block:

```js
function submitCampaign() {
  var name = document.getElementById('cmp-name').value.trim();
  var agentIds = Object.keys(_cmpSel).filter(function(k) { return _cmpSel[k]; });
  if (!name) { showToast('Campaign name required', 'err'); return; }
  if (!agentIds.length) { showToast('Select at least one target agent', 'err'); return; }
  var mode = document.getElementById('cmp-mode').value;
  if (mode !== 'posture' && !confirm(mode.toUpperCase() + ' mode runs real techniques and will generate alerts. Continue?')) return;
  var body = {
    name: name, scenarioId: document.getElementById('cmp-scenario').value, agentIds: agentIds,
    mode: mode, confirmLive: mode !== 'posture', confirmLab: mode === 'lab',
    notes: document.getElementById('cmp-notes').value.trim()
  };
  apicall('/api/campaigns', { method: 'POST', body: JSON.stringify(body) }).then(function(res) {
```

Replace it with:

```js
function submitCampaign() {
  var name = document.getElementById('cmp-name').value.trim();
  var targetType = document.getElementById('cmp-target-type').value;
  if (!name) { showToast('Campaign name required', 'err'); return; }
  var mode = document.getElementById('cmp-mode').value;
  if (mode !== 'posture' && !confirm(mode.toUpperCase() + ' mode runs real techniques and will generate alerts. Continue?')) return;
  var body = {
    name: name, scenarioId: document.getElementById('cmp-scenario').value, targetType: targetType,
    mode: mode, confirmLive: mode !== 'posture', confirmLab: mode === 'lab',
    notes: document.getElementById('cmp-notes').value.trim()
  };
  if (targetType === 'agents') {
    var agentIds = Object.keys(_cmpSel).filter(function(k) { return _cmpSel[k]; });
    if (!agentIds.length) { showToast('Select at least one target agent', 'err'); return; }
    body.agentIds = agentIds;
  } else if (targetType === 'group') {
    var groupId = document.getElementById('cmp-group').value;
    if (!groupId) { showToast('Select an agent group', 'err'); return; }
    body.groupId = Number(groupId);
    var excl = Object.keys(CMP.exclusions);
    if (excl.length) body.excludeAgentIds = excl;
  } else if (targetType === 'all') {
    if (!document.getElementById('cmp-all-confirm').checked) { showToast('Confirm targeting all agents first', 'err'); return; }
  }
  apicall('/api/campaigns', { method: 'POST', body: JSON.stringify(body) }).then(function(res) {
```

- [ ] **Step 6: Syntax-check**

```bash
cd orchestrator/wwwroot
awk '/^<script>$/{flag=1;next}/^<\/script>$/{flag=0}flag' index.html > /tmp/campaign-ui-check.js
node --check /tmp/campaign-ui-check.js
```

Expected: no output, exit code 0.

- [ ] **Step 7: Commit**

```bash
git add orchestrator/wwwroot/index.html
git commit -m "feat(ui): Campaign Targets — Agent Group and All Agents modes"
```

---

### Task 4: Frontend — Campaign list/detail additions

**Files:**
- Modify: `orchestrator/wwwroot/index.html` (`renderCampaignRows` and `openCampaignDetail`, exact anchors re-verified at execution time — Task 3 shifts subsequent line numbers)

**Interfaces:**
- Consumes: `targetType`/`targetGroupId` on each campaign object (Task 2), `CMP.groupsById` (Task 3 — same lazily-populated map; if a campaign row references a group not currently in `CMP.groupsById` because the New Campaign modal was never opened this session, fall back to displaying `"Group #<id>"`, matching the established fallback pattern from Scheduled Assessments' `schedTargetsText`).
- Produces: nothing new — this is the last task.

- [ ] **Step 1: Add a target-type indicator to the campaign list rows**

Find this exact block (`renderCampaignRows`):

```js
    return '<tr style="cursor:pointer" onclick="openCampaignDetail(\'' + x(c.id) + '\')">' +
      '<td><div class="cell-main">' + x(c.name) + '</div><div class="tiny muted" style="font-family:var(--font-mono);font-size:0.6rem">' + x(c.id) + (c.createdBy ? ' · ' + x(c.createdBy) : '') + '</div></td>' +
      '<td class="tiny muted">' + x(c.scenarioName) + '</td>' +
      '<td class="tiny">' + (s.dispatched || 0) + '/' + (s.targets || 0) + (s.skipped ? ' <span class="tiny muted">(' + s.skipped + ' skipped)</span>' : '') + '</td>' +
      '<td>' + status + '</td>' +
      '<td>' + campaignMixBar(s) + '</td>' +
      '<td class="tiny muted">' + fmtDate(c.startedAt) + '</td></tr>';
```

Replace it with:

```js
    var targetLabel = c.targetType === 'group'
      ? (CMP.groupsById[c.targetGroupId] || ('Group #' + c.targetGroupId))
      : c.targetType === 'all' ? 'All Agents' : 'Agents';
    return '<tr style="cursor:pointer" onclick="openCampaignDetail(\'' + x(c.id) + '\')">' +
      '<td><div class="cell-main">' + x(c.name) + '</div><div class="tiny muted" style="font-family:var(--font-mono);font-size:0.6rem">' + x(c.id) + (c.createdBy ? ' · ' + x(c.createdBy) : '') + '</div></td>' +
      '<td class="tiny muted">' + x(c.scenarioName) + '<div class="tiny muted" style="opacity:0.75">' + x(targetLabel) + '</div></td>' +
      '<td class="tiny">' + (s.dispatched || 0) + '/' + (s.targets || 0) + (s.skipped ? ' <span class="tiny muted">(' + s.skipped + ' skipped)</span>' : '') + '</td>' +
      '<td>' + status + '</td>' +
      '<td>' + campaignMixBar(s) + '</td>' +
      '<td class="tiny muted">' + fmtDate(c.startedAt) + '</td></tr>';
```

- [ ] **Step 2: Add a Target row to the campaign detail's Run summary panel**

Find this exact block (`openCampaignDetail`):

```js
    var kv = function(k, v) { return '<div style="display:flex;gap:0.6rem;padding:0.35rem 0;border-bottom:1px solid var(--border);font-size:0.8rem"><span style="color:var(--muted);min-width:120px">' + k + '</span><span style="flex:1">' + v + '</span></div>'; };
    var summary = '<div class="dash-panel"><div class="dash-panel-hdr">Run summary</div><div class="dash-panel-body">' +
      kv('Campaign ID', '<code>' + x(c.id) + '</code>') + kv('Scenario', x(c.scenarioName)) +
      kv('Targets', (s.dispatched || 0) + ' dispatched · ' + (s.skipped || 0) + ' skipped of ' + (s.targets || 0)) +
      kv('Mode', x(c.mode || '—')) + kv('Initiated by', x(c.createdBy || '—')) +
      kv('Result mix', campaignMixBar(s)) + '</div></div>';
```

Replace it with:

```js
    var kv = function(k, v) { return '<div style="display:flex;gap:0.6rem;padding:0.35rem 0;border-bottom:1px solid var(--border);font-size:0.8rem"><span style="color:var(--muted);min-width:120px">' + k + '</span><span style="flex:1">' + v + '</span></div>'; };
    var targetKv = c.targetType === 'group'
      ? 'Agent Group — ' + x(CMP.groupsById[c.targetGroupId] || ('Group #' + c.targetGroupId))
      : c.targetType === 'all' ? 'All Agents' : (s.targets || 0) + ' agents selected';
    var summary = '<div class="dash-panel"><div class="dash-panel-hdr">Run summary</div><div class="dash-panel-body">' +
      kv('Campaign ID', '<code>' + x(c.id) + '</code>') + kv('Scenario', x(c.scenarioName)) +
      kv('Target', targetKv) +
      kv('Targets', (s.dispatched || 0) + ' dispatched · ' + (s.skipped || 0) + ' skipped of ' + (s.targets || 0)) +
      kv('Mode', x(c.mode || '—')) + kv('Initiated by', x(c.createdBy || '—')) +
      kv('Result mix', campaignMixBar(s)) + '</div></div>';
```

- [ ] **Step 3: Syntax-check**

```bash
cd orchestrator/wwwroot
awk '/^<script>$/{flag=1;next}/^<\/script>$/{flag=0}flag' index.html > /tmp/campaign-ui-check.js
node --check /tmp/campaign-ui-check.js
```

Expected: no output, exit code 0.

- [ ] **Step 4: Read back both edited regions to confirm well-formedness**

Use the `Read` tool on `orchestrator/wwwroot/index.html` around `renderCampaignRows` and `openCampaignDetail` (search for `function renderCampaignRows` / `function openCampaignDetail` to find current line numbers) and confirm both edits are syntactically clean JS (balanced quotes/braces/ternaries) in context.

- [ ] **Step 5: Commit**

```bash
git add orchestrator/wwwroot/index.html
git commit -m "feat(ui): Campaign list/detail show target type and group"
```

---

## Self-Review

**1. Spec coverage:**
- Data model (`target_type`, `target_group_id`, no new table, `DEFAULT 'agents'` needing no backfill) — Task 1 Step 3.
- Group resolution reusing `internal/jobs.Store.ResolveGroupAgentIDs`, no new package, no refactor of `GET /api/agents` — Task 1 Step 7 (explicitly noted as a plan-time refinement of the spec's "TBD at plan time" package placeholder).
- All Agents resolution (non-retired), Admin-only via a new dedicated permission — Task 1 Steps 4-7.
- Exclusions, applied after resolution — Task 1 Step 7.
- Single group per campaign (no multi-group) — the request shape (`groupId *int64`, singular) and every test only ever exercise one group; nothing in this plan supports multiple.
- Live preview via the existing `GET /api/agents?groupId=` endpoint, no new endpoint — Task 3 Step 4 (`cmpOnGroupChange`).
- "New Campaign" modal: Campaign Targets radio/select group, Agent Group + preview + exclusions, Agents mode unchanged/relabeled, All Agents Admin-gated + confirmation checkbox — Task 3.
- Campaign list/detail additions (target-type indicator in rows, Target row in detail's Run summary, group name resolved client-side) — Task 4.
- Run Scenario wizard untouched — no task in this plan touches `run-overlay`, `wizardSet`, or any `data-pane`/`data-pip` code.
- Backward compatibility for existing campaigns / callers omitting `targetType` — Task 1 Step 6 (`targetType` defaults to `"agents"`) and the dedicated `TestCreateCampaign_LegacyRequest_DefaultsToAgentsMode` test.

**2. Placeholder scan:** no TBD/TODO; every step has literal exact-match old/new code (Go and JS); the one spot with plan-time latitude explicitly flagged in the spec (Task 3's Interfaces note about how Task 4 looks up group names) offers two concretely equivalent options rather than leaving anything undefined, and Task 4 as written just reuses `CMP.groupsById` directly — no ambiguity in the actual steps.

**3. Type consistency:** `targetType` (`string`, values `"agents"|"group"|"all"`) and `groupId`/`GroupID` (`*int64` in Go request/response, `Number(...)` in JS before sending) are used identically across all 4 tasks — Task 1 defines the wire shape, Task 2 echoes it back verbatim in responses, Task 3 sends it, Task 4 reads it back the same way Task 2 shaped it (`c.targetType`, `c.targetGroupId`, camelCase, matching Task 2's response keys exactly). `CanTargetAllAgents` is declared once in Task 1 and referenced identically in the handler, both permission tests, and the RBAC-relevant guard — no alternate spelling anywhere.
