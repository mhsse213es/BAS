# Purple Team Exercise Templates Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship five purpose-built Purple Team exercise templates — one per existing flagship BAS scenario — replacing the single generic `builtin-soc-drill` as the only out-of-the-box option, plus structured `Metadata` on `Template` giving each its own identity.

**Architecture:** One structural addition (`Template.Metadata TemplateMetadata`, one new additive DB column), then five content-only entries in `BuiltinTemplates` cloning `builtin-soc-drill`'s proven execution graph. No changes to `Executor`, triggers, or the detection bridge.

**Tech Stack:** Go, PostgreSQL (`pgxpool`), the existing `internal/testutil` Docker-testcontainer test harness.

## Global Constraints

- **Depends on Phase A0+A1** (`docs/superpowers/plans/2026-07-27-automatic-verdict-persistence.md`, `docs/superpowers/plans/2026-07-27-exercise-detection-bridge.md`), both DONE and pushed.
- No changes to `internal/exercise/executor.go`, `detectionbridge.go`, or any trigger logic — every new template reuses the identical execution graph `builtin-soc-drill` and Phase A1's fixed templates already use. If any step of this plan requires touching those files, stop — that's a sign of scope creep, not this plan's job.
- No new BAS scenario content — all five templates reference existing, already-signed scenarios (`apt29-kill-chain`, `volt-typhoon-lotl`, `kerberoasting-ad-drill`, `collection-staging-exfil`, `dlp-exfiltration-validation`) via `ScenarioID`.
- No Sigma/Detection Rule Library content — `RuleIDs` stays exactly as built in Phase A, legitimately empty for these five templates.
- The Kerberoasting template's `wait_detect` step uses `DetectionTypes: []string{"security_control_detected"}` only (excludes `edr_detected`) — a deliberate identity-only gate, not an oversight; do not "fix" it to include `edr_detected`.
- The DLP template's `wait_detect` step uses `MinCount: 5` (not the default 1) — all five channels are one coherent claim; do not "simplify" it back to the default.
- Docker Desktop must be running for every `internal/exercise` test (Postgres testcontainer via `internal/testutil`). Check `docker info` before running these suites.

---

### Task 1: `Template.Metadata` + migration + store CRUD

**Files:**
- Modify: `orchestrator/internal/exercise/types.go` (new `TemplateMetadata` struct, `Template` gains `Metadata` field)
- Modify: `orchestrator/internal/exercise/store.go` (`UpsertTemplate`, `GetTemplate`, `ListTemplates`)
- Modify: `orchestrator/internal/db/exercise_schema.go` (new migration line)
- Test: `orchestrator/internal/exercise/store_test.go` (extend `TestTemplate_UpsertAndSeed`)

**Interfaces:**
- Produces: `exercise.TemplateMetadata{SuccessCriteria, LearningObjectives, ExpectedTechniques, ExpectedDetections, RecommendedParticipants, RecommendedDuration, DiscussionPrompts}`, `Template.Metadata TemplateMetadata`. Consumed by every later task's template literals.

- [ ] **Step 1: Write the failing test**

`orchestrator/internal/exercise/store_test.go` currently has `TestTemplate_UpsertAndSeed` (around line 174):

```go
func TestTemplate_UpsertAndSeed(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		store := NewStore(pool)
		ctx := context.Background()

		tpl := &Template{ID: "tpl-1", Name: "Phishing", Version: 1, Category: "phishing",
			Steps: []PlanStep{{ID: "a", Type: StepTypeSendEmail}}}
		if err := store.UpsertTemplate(ctx, tpl); err != nil {
			t.Fatalf("UpsertTemplate insert: %v", err)
		}
		tpl.Name = "Phishing v2"
		if err := store.UpsertTemplate(ctx, tpl); err != nil {
			t.Fatalf("UpsertTemplate update: %v", err)
		}
		got, err := store.GetTemplate(ctx, "tpl-1")
		if err != nil || got.Name != "Phishing v2" {
			t.Fatalf("GetTemplate = %+v (err %v)", got, err)
		}

		// SeedBuiltinTemplates is idempotent.
		if err := store.SeedBuiltinTemplates(ctx); err != nil {
			t.Fatalf("SeedBuiltinTemplates 1: %v", err)
		}
		if err := store.SeedBuiltinTemplates(ctx); err != nil {
			t.Fatalf("SeedBuiltinTemplates 2 (idempotent): %v", err)
		}
		list, err := store.ListTemplates(ctx)
		if err != nil || len(list) == 0 {
			t.Fatalf("ListTemplates = %v (err %v)", list, err)
		}
	})
}
```

Insert a new assertion block right after the `GetTemplate` check (before the `SeedBuiltinTemplates` idempotency check), asserting `Metadata` round-trips through a real write/read:

```go
		got, err := store.GetTemplate(ctx, "tpl-1")
		if err != nil || got.Name != "Phishing v2" {
			t.Fatalf("GetTemplate = %+v (err %v)", got, err)
		}

		// Metadata round-trips through Postgres, not just Go-side construction.
		tpl.Metadata = TemplateMetadata{
			SuccessCriteria:    "test criterion",
			ExpectedTechniques: []string{"T1055"},
		}
		if err := store.UpsertTemplate(ctx, tpl); err != nil {
			t.Fatalf("UpsertTemplate with metadata: %v", err)
		}
		gotMeta, err := store.GetTemplate(ctx, "tpl-1")
		if err != nil {
			t.Fatalf("GetTemplate after metadata upsert: %v", err)
		}
		if gotMeta.Metadata.SuccessCriteria != "test criterion" || len(gotMeta.Metadata.ExpectedTechniques) != 1 || gotMeta.Metadata.ExpectedTechniques[0] != "T1055" {
			t.Fatalf("Metadata did not round-trip: %+v", gotMeta.Metadata)
		}

		// SeedBuiltinTemplates is idempotent.
```

- [ ] **Step 2: Run test to verify it fails**

Run (from `orchestrator/`): `go test ./internal/exercise/... -run TestTemplate_UpsertAndSeed -v`
Expected: FAIL — `tpl.Metadata undefined (type *Template has no field or method Metadata)`

- [ ] **Step 3: Add the migration**

In `orchestrator/internal/db/exercise_schema.go`, immediately after the existing line `` `ALTER TABLE exercise_templates ADD COLUMN IF NOT EXISTS tenant_id text NOT NULL DEFAULT 'default'`, `` (in the "Backward-compat: add columns to existing tables" block), add:

```go
		`ALTER TABLE exercise_templates ADD COLUMN IF NOT EXISTS metadata_json jsonb NOT NULL DEFAULT '{}'`,
```

- [ ] **Step 4: Add `TemplateMetadata` and `Template.Metadata`**

In `orchestrator/internal/exercise/types.go`, `Template` currently:

```go
type Template struct {
	ID          string     `json:"id"`
	Name        string     `json:"name"`
	Version     int        `json:"version"`
	Category    string     `json:"category"` // "phishing" | "ransomware" | "insider" | …
	Description string     `json:"description"`
	Variables   []VarDef   `json:"variables"`
	Steps       []PlanStep `json:"steps"`
	BuiltIn     bool       `json:"built_in"`
	Author      string     `json:"author"`
	CreatedAt   time.Time  `json:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at"`
}
```

Add `Metadata` and the new `TemplateMetadata` type immediately after:

```go
type Template struct {
	ID          string     `json:"id"`
	Name        string     `json:"name"`
	Version     int        `json:"version"`
	Category    string     `json:"category"` // "phishing" | "ransomware" | "insider" | …
	Description string     `json:"description"`
	Variables   []VarDef   `json:"variables"`
	Steps       []PlanStep `json:"steps"`
	BuiltIn     bool       `json:"built_in"`
	Author      string     `json:"author"`
	CreatedAt   time.Time  `json:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at"`
	Metadata    TemplateMetadata `json:"metadata,omitempty"`
}

// TemplateMetadata is structured descriptive content distinguishing one
// exercise template from another beyond its one-line Description — success
// criteria, learning objectives, and logistics an operator or a future
// template-picker UI can render without parsing free text. Optional on
// every field: a template with no populated metadata (every pre-Phase-B
// built-in) renders with all fields empty, not an error.
type TemplateMetadata struct {
	SuccessCriteria         string   `json:"success_criteria,omitempty"`
	LearningObjectives      []string `json:"learning_objectives,omitempty"`
	ExpectedTechniques      []string `json:"expected_techniques,omitempty"`      // MITRE ATT&CK technique IDs
	ExpectedDetections      []string `json:"expected_detections,omitempty"`      // provider/control display names
	RecommendedParticipants []string `json:"recommended_participants,omitempty"` // roles, e.g. "SOC Analyst"
	RecommendedDuration     string   `json:"recommended_duration,omitempty"`     // e.g. "1-2 hours"
	DiscussionPrompts       []string `json:"discussion_prompts,omitempty"`
}
```

- [ ] **Step 5: Update `UpsertTemplate`, `GetTemplate`, `ListTemplates`**

In `orchestrator/internal/exercise/store.go`, `UpsertTemplate` currently:

```go
func (s *Store) UpsertTemplate(ctx context.Context, t *Template) error {
	vars, _ := json.Marshal(t.Variables)
	steps, _ := json.Marshal(t.Steps)
	_, err := s.db.Exec(ctx,
		`INSERT INTO exercise_templates (id, name, version, category, description, variables_json, steps_json, built_in, author)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
		 ON CONFLICT (id) DO UPDATE SET
		   name=$2, version=$3, category=$4, description=$5,
		   variables_json=$6, steps_json=$7, author=$9, updated_at=NOW()`,
		t.ID, t.Name, t.Version, t.Category, t.Description,
		vars, steps, t.BuiltIn, t.Author)
	return err
}
```

Replace with (adds `metadata_json`/`$10`):

```go
func (s *Store) UpsertTemplate(ctx context.Context, t *Template) error {
	vars, _ := json.Marshal(t.Variables)
	steps, _ := json.Marshal(t.Steps)
	meta, _ := json.Marshal(t.Metadata)
	_, err := s.db.Exec(ctx,
		`INSERT INTO exercise_templates (id, name, version, category, description, variables_json, steps_json, built_in, author, metadata_json)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
		 ON CONFLICT (id) DO UPDATE SET
		   name=$2, version=$3, category=$4, description=$5,
		   variables_json=$6, steps_json=$7, author=$9, metadata_json=$10, updated_at=NOW()`,
		t.ID, t.Name, t.Version, t.Category, t.Description,
		vars, steps, t.BuiltIn, t.Author, meta)
	return err
}
```

`GetTemplate` currently:

```go
func (s *Store) GetTemplate(ctx context.Context, id string) (*Template, error) {
	var t Template
	var varsRaw, stepsRaw []byte
	err := s.db.QueryRow(ctx,
		`SELECT id, name, version, category, description, variables_json, steps_json,
		        built_in, author, created_at, updated_at
		 FROM exercise_templates WHERE id=$1`, id,
	).Scan(&t.ID, &t.Name, &t.Version, &t.Category, &t.Description,
		&varsRaw, &stepsRaw, &t.BuiltIn, &t.Author, &t.CreatedAt, &t.UpdatedAt)
	if err != nil {
		return nil, err
	}
	_ = json.Unmarshal(varsRaw, &t.Variables)
	_ = json.Unmarshal(stepsRaw, &t.Steps)
	return &t, nil
}
```

Replace with:

```go
func (s *Store) GetTemplate(ctx context.Context, id string) (*Template, error) {
	var t Template
	var varsRaw, stepsRaw, metaRaw []byte
	err := s.db.QueryRow(ctx,
		`SELECT id, name, version, category, description, variables_json, steps_json,
		        built_in, author, created_at, updated_at, metadata_json
		 FROM exercise_templates WHERE id=$1`, id,
	).Scan(&t.ID, &t.Name, &t.Version, &t.Category, &t.Description,
		&varsRaw, &stepsRaw, &t.BuiltIn, &t.Author, &t.CreatedAt, &t.UpdatedAt, &metaRaw)
	if err != nil {
		return nil, err
	}
	_ = json.Unmarshal(varsRaw, &t.Variables)
	_ = json.Unmarshal(stepsRaw, &t.Steps)
	_ = json.Unmarshal(metaRaw, &t.Metadata)
	return &t, nil
}
```

`ListTemplates` currently:

```go
func (s *Store) ListTemplates(ctx context.Context) ([]Template, error) {
	rows, err := s.db.Query(ctx,
		`SELECT id, name, version, category, description, variables_json, steps_json,
		        built_in, author, created_at, updated_at
		 FROM exercise_templates ORDER BY built_in DESC, name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Template
	for rows.Next() {
		var t Template
		var varsRaw, stepsRaw []byte
		if err := rows.Scan(&t.ID, &t.Name, &t.Version, &t.Category, &t.Description,
			&varsRaw, &stepsRaw, &t.BuiltIn, &t.Author, &t.CreatedAt, &t.UpdatedAt); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(varsRaw, &t.Variables)
		_ = json.Unmarshal(stepsRaw, &t.Steps)
		out = append(out, t)
	}
	return out, rows.Err()
}
```

Replace with:

```go
func (s *Store) ListTemplates(ctx context.Context) ([]Template, error) {
	rows, err := s.db.Query(ctx,
		`SELECT id, name, version, category, description, variables_json, steps_json,
		        built_in, author, created_at, updated_at, metadata_json
		 FROM exercise_templates ORDER BY built_in DESC, name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Template
	for rows.Next() {
		var t Template
		var varsRaw, stepsRaw, metaRaw []byte
		if err := rows.Scan(&t.ID, &t.Name, &t.Version, &t.Category, &t.Description,
			&varsRaw, &stepsRaw, &t.BuiltIn, &t.Author, &t.CreatedAt, &t.UpdatedAt, &metaRaw); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(varsRaw, &t.Variables)
		_ = json.Unmarshal(stepsRaw, &t.Steps)
		_ = json.Unmarshal(metaRaw, &t.Metadata)
		out = append(out, t)
	}
	return out, rows.Err()
}
```

- [ ] **Step 6: Run test to verify it passes**

Run: `go test ./internal/exercise/... -run TestTemplate_UpsertAndSeed -v`
Expected: PASS

- [ ] **Step 7: Run the full exercise suite to confirm no regression**

Run: `go test ./internal/exercise/... -v -count=1`
Expected: 100% PASS

- [ ] **Step 8: Commit**

```bash
git add orchestrator/internal/exercise/types.go orchestrator/internal/exercise/store.go orchestrator/internal/exercise/store_test.go orchestrator/internal/db/exercise_schema.go
git commit -m "feat(exercise): Template.Metadata field + metadata_json column"
```

---

### Task 2: APT29 Kill Chain Purple Team Drill

**Files:**
- Modify: `orchestrator/internal/exercise/templates.go` (append to `BuiltinTemplates`)
- Modify: `orchestrator/internal/exercise/templates_test.go` (extend with the two Phase-B cross-cutting tests, starting with this one template)

**Interfaces:**
- Consumes: `TemplateMetadata` (Task 1).
- Produces: `BuiltinTemplates` entry `"builtin-purple-apt29"`. `TestBuiltinTemplates_PurpleTeamDetectionBridgeWiring`/`TestBuiltinTemplates_PurpleTeamMetadataPopulated` (new, extended by every subsequent task).

- [ ] **Step 1: Write the failing tests**

`orchestrator/internal/exercise/templates_test.go` currently has one test, `TestBuiltinTemplates_DetectionBridgeWiring` (from Phase A1). Append two new test functions after it:

```go
func TestBuiltinTemplates_PurpleTeamDetectionBridgeWiring(t *testing.T) {
	findStep := func(steps []PlanStep, id string) *PlanStep {
		for i := range steps {
			if steps[i].ID == id {
				return &steps[i]
			}
		}
		return nil
	}
	findTemplate := func(id string) *Template {
		for i := range BuiltinTemplates {
			if BuiltinTemplates[i].ID == id {
				return &BuiltinTemplates[i]
			}
		}
		return nil
	}

	cases := []struct {
		templateID       string
		wantExecutionStepID string
	}{
		{"builtin-purple-apt29", "drill_sim"},
	}
	for _, tc := range cases {
		tpl := findTemplate(tc.templateID)
		if tpl == nil {
			t.Fatalf("%s: template not found", tc.templateID)
		}
		wait := findStep(tpl.Steps, "wait_detect")
		if wait == nil || wait.Config.WaitForDetection == nil {
			t.Fatalf("%s: wait_detect step or its WaitForDetection config is missing", tc.templateID)
		}
		if wait.Config.WaitForDetection.ExecutionStepID != tc.wantExecutionStepID {
			t.Errorf("%s: ExecutionStepID = %q, want %q", tc.templateID, wait.Config.WaitForDetection.ExecutionStepID, tc.wantExecutionStepID)
		}
	}
}

func TestBuiltinTemplates_PurpleTeamMetadataPopulated(t *testing.T) {
	findTemplate := func(id string) *Template {
		for i := range BuiltinTemplates {
			if BuiltinTemplates[i].ID == id {
				return &BuiltinTemplates[i]
			}
		}
		return nil
	}

	ids := []string{"builtin-purple-apt29"}
	for _, id := range ids {
		tpl := findTemplate(id)
		if tpl == nil {
			t.Fatalf("%s: template not found", id)
		}
		if tpl.Metadata.SuccessCriteria == "" {
			t.Errorf("%s: Metadata.SuccessCriteria is empty", id)
		}
		if len(tpl.Metadata.ExpectedTechniques) == 0 {
			t.Errorf("%s: Metadata.ExpectedTechniques is empty", id)
		}
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/exercise/... -run 'TestBuiltinTemplates_PurpleTeam' -v`
Expected: FAIL — `builtin-purple-apt29: template not found`

- [ ] **Step 3: Add the APT29 template**

Append to `BuiltinTemplates` in `orchestrator/internal/exercise/templates.go` (after the existing `builtin-soc-drill` entry, before the closing `}` of the `var BuiltinTemplates = []Template{...}` slice):

```go

	// ── 6. APT29 Kill Chain Purple Team Drill ─────────────────────────────────
	{
		ID:          "builtin-purple-apt29",
		Name:        "APT29 Kill Chain Purple Team Drill",
		Version:     1,
		Category:    "purple-team",
		Description: "Runs the APT29 (Cozy Bear) kill-chain simulation — GPO discovery, encoded PowerShell execution, registry run-key persistence, scheduled-task persistence, DNS-over-HTTPS C2 — and measures SOC detection latency across the full multi-stage chain.",
		Author:      "Audspect",
		BuiltIn:     true,
		Variables: []VarDef{
			{Name: "AgentID", Type: VarTypeEndpoint, Required: true, Description: "Target agent for the simulation"},
			{Name: "ScenarioID", Type: VarTypeString, Required: true, Default: "apt29-kill-chain", Description: "Scenario to execute"},
			{Name: "DetectionTimeout", Type: VarTypeDuration, Default: "30m", Description: "Max time to wait for detection before timing out"},
			{Name: "SOCNotifyEmail", Type: VarTypeEmailList, Description: "Email to notify when drill completes"},
		},
		Metadata: TemplateMetadata{
			SuccessCriteria: "The technical gate confirms at least one kill-chain stage was detected within the detection timeout (MTTD/MTTR recorded); full stage-by-stage coverage across all five stages is then reviewed by the SOC at the approval step using the complete evidence chain, not just the count that satisfied the gate. Only microsoft_defender (EDR-domain) evidence resolves automatically today — the microsoft_sentinel (SIEM) stage's detection requires either a configured Sentinel API connector or a SOC analyst manually attesting via the Detection Verification UI during the exercise.",
			LearningObjectives: []string{
				"Validate multi-stage kill-chain visibility across endpoint and SIEM",
				"Measure detection latency for a nation-state-style intrusion pattern",
				"Identify which chain stage, if any, breaks detection coverage",
			},
			ExpectedTechniques:      []string{"T1482", "T1059.001", "T1547.001", "T1053.005", "T1071.004"},
			ExpectedDetections:      []string{"Microsoft Defender", "Microsoft Sentinel"},
			RecommendedParticipants: []string{"SOC Analyst", "Detection Engineer", "IR Lead (approval)"},
			RecommendedDuration:     "1-2 hours",
			DiscussionPrompts: []string{
				"Which stage of the chain, if any, went undetected?",
				"What logging or rule change would close that gap fastest?",
				"Did any single stage's detection alone give away the whole chain, or did the SOC need to correlate across stages?",
			},
		},
		Steps: []PlanStep{
			{
				ID: "drill_sim", Type: StepTypeAgentTask, Label: "Trigger APT29 kill-chain simulation",
				Config: StepConfig{AgentTask: &AgentTaskConfig{AgentID: "${AgentID}", ScenarioID: "${ScenarioID}"}},
			},
			{
				ID: "wait_sim_done", Type: StepTypeWaitForAgent, Label: "Wait for simulation to complete",
				DependsOn:   []string{"drill_sim"},
				Config:      StepConfig{WaitForAgent: &WaitForAgentConfig{AgentTaskStepID: "drill_sim"}},
				TimeoutSecs: 1800,
			},
			{
				ID: "wait_detect", Type: StepTypeWaitForDetection, Label: "Wait for SOC detection",
				DependsOn:   []string{"wait_sim_done"},
				TimeoutSecs: 1800,
				Config: StepConfig{WaitForDetection: &WaitForDetectionConfig{
					DetectionTypes:  []string{"edr_detected", "siem_alerted", "security_control_detected"},
					ExecutionStepID: "drill_sim",
				}},
			},
			{
				ID: "approval_response", Type: StepTypeApproval, Label: "SOC: confirm incident response completed",
				DependsOn:   []string{"wait_detect"},
				TimeoutSecs: 7200,
				Config: StepConfig{
					ApprovalPrompt: "Has the SOC completed triage, containment, and documented the incident across all detected kill-chain stages?",
					ApproverRoles:  []string{"admin", "analyst"},
				},
			},
			{
				ID: "drill_complete", Type: StepTypeNotify, Label: "APT29 drill complete — check MTTD/MTTR",
				DependsOn: []string{"approval_response"},
				Config:    StepConfig{NotifyMsg: "APT29 Kill Chain Purple Team Drill complete. Review the technical score, MTTD/MTTR, and per-stage detection coverage."},
			},
		},
	},
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/exercise/... -run 'TestBuiltinTemplates_PurpleTeam' -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add orchestrator/internal/exercise/templates.go orchestrator/internal/exercise/templates_test.go
git commit -m "feat(exercise): APT29 Kill Chain Purple Team Drill template"
```

---

### Task 3: Volt Typhoon LOTL Purple Team Drill

**Files:**
- Modify: `orchestrator/internal/exercise/templates.go` (append to `BuiltinTemplates`)
- Modify: `orchestrator/internal/exercise/templates_test.go` (extend both cross-cutting tests)

**Interfaces:**
- Consumes: `TemplateMetadata` (Task 1). Extends `TestBuiltinTemplates_PurpleTeamDetectionBridgeWiring`/`TestBuiltinTemplates_PurpleTeamMetadataPopulated` (Task 2).
- Produces: `BuiltinTemplates` entry `"builtin-purple-volt-typhoon"`.

- [ ] **Step 1: Write the failing test extension**

In `orchestrator/internal/exercise/templates_test.go`, `TestBuiltinTemplates_PurpleTeamDetectionBridgeWiring`'s `cases` slice currently:

```go
	cases := []struct {
		templateID       string
		wantExecutionStepID string
	}{
		{"builtin-purple-apt29", "drill_sim"},
	}
```

Add a row:

```go
	cases := []struct {
		templateID       string
		wantExecutionStepID string
	}{
		{"builtin-purple-apt29", "drill_sim"},
		{"builtin-purple-volt-typhoon", "drill_sim"},
	}
```

`TestBuiltinTemplates_PurpleTeamMetadataPopulated`'s `ids` slice currently:

```go
	ids := []string{"builtin-purple-apt29"}
```

Add an entry:

```go
	ids := []string{"builtin-purple-apt29", "builtin-purple-volt-typhoon"}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/exercise/... -run 'TestBuiltinTemplates_PurpleTeam' -v`
Expected: FAIL — `builtin-purple-volt-typhoon: template not found`

- [ ] **Step 3: Add the Volt Typhoon template**

Append to `BuiltinTemplates` in `orchestrator/internal/exercise/templates.go`, immediately after the APT29 entry added in Task 2:

```go

	// ── 7. Volt Typhoon LOTL Purple Team Drill ────────────────────────────────
	{
		ID:          "builtin-purple-volt-typhoon",
		Name:        "Volt Typhoon LOTL Purple Team Drill",
		Version:     1,
		Category:    "purple-team",
		Description: "Runs the Volt Typhoon living-off-the-land simulation — network config discovery, SAM theft, LOLBin download cradles, scheduled-task persistence, log manipulation — with no malware involved, testing whether the SOC can detect abuse of built-in Windows tools.",
		Author:      "Audspect",
		BuiltIn:     true,
		Variables: []VarDef{
			{Name: "AgentID", Type: VarTypeEndpoint, Required: true, Description: "Target agent for the simulation"},
			{Name: "ScenarioID", Type: VarTypeString, Required: true, Default: "volt-typhoon-lotl", Description: "Scenario to execute"},
			{Name: "DetectionTimeout", Type: VarTypeDuration, Default: "30m", Description: "Max time to wait for detection before timing out"},
			{Name: "SOCNotifyEmail", Type: VarTypeEmailList, Description: "Email to notify when drill completes"},
		},
		Metadata: TemplateMetadata{
			SuccessCriteria: "The technical gate confirms at least one LOTL technique was detected within the detection timeout; full coverage across all techniques is reviewed by the SOC at the approval step using the complete evidence chain. Only microsoft_defender (EDR-domain) evidence resolves automatically today — the microsoft_sentinel/Sigma (SIEM) techniques require either a configured Sentinel API connector or a SOC analyst manually attesting via the Detection Verification UI during the exercise.",
			LearningObjectives: []string{
				"Validate detection coverage for native-tool abuse, not just malware",
				"Identify which built-in Windows utilities your EDR alerts on by default vs. only with custom rules",
				"Measure SOC readiness against a nation-state LOTL tradecraft pattern",
			},
			ExpectedTechniques:      []string{"T1082", "T1016", "T1090.001", "T1087.001", "T1003.002", "T1003.003", "T1105", "T1218.005", "T1053.005", "T1070.001"},
			ExpectedDetections:      []string{"Microsoft Defender", "Microsoft Sentinel", "Sigma-based SIEM rule"},
			RecommendedParticipants: []string{"SOC Analyst", "Detection Engineer", "IR Lead (approval)"},
			RecommendedDuration:     "1-2 hours",
			DiscussionPrompts: []string{
				"Which built-in Windows tools does your EDR alert on by default vs. only with custom rules?",
				"Would this activity have blended into normal admin behavior in your environment?",
				"Which detection, if any, was the first real signal — and how long did it take to fire?",
			},
		},
		Steps: []PlanStep{
			{
				ID: "drill_sim", Type: StepTypeAgentTask, Label: "Trigger Volt Typhoon LOTL simulation",
				Config: StepConfig{AgentTask: &AgentTaskConfig{AgentID: "${AgentID}", ScenarioID: "${ScenarioID}"}},
			},
			{
				ID: "wait_sim_done", Type: StepTypeWaitForAgent, Label: "Wait for simulation to complete",
				DependsOn:   []string{"drill_sim"},
				Config:      StepConfig{WaitForAgent: &WaitForAgentConfig{AgentTaskStepID: "drill_sim"}},
				TimeoutSecs: 1800,
			},
			{
				ID: "wait_detect", Type: StepTypeWaitForDetection, Label: "Wait for SOC detection",
				DependsOn:   []string{"wait_sim_done"},
				TimeoutSecs: 1800,
				Config: StepConfig{WaitForDetection: &WaitForDetectionConfig{
					DetectionTypes:  []string{"edr_detected", "siem_alerted", "security_control_detected"},
					ExecutionStepID: "drill_sim",
				}},
			},
			{
				ID: "approval_response", Type: StepTypeApproval, Label: "SOC: confirm incident response completed",
				DependsOn:   []string{"wait_detect"},
				TimeoutSecs: 7200,
				Config: StepConfig{
					ApprovalPrompt: "Has the SOC completed triage, containment, and documented the incident for this LOTL activity?",
					ApproverRoles:  []string{"admin", "analyst"},
				},
			},
			{
				ID: "drill_complete", Type: StepTypeNotify, Label: "Volt Typhoon drill complete — check MTTD/MTTR",
				DependsOn: []string{"approval_response"},
				Config:    StepConfig{NotifyMsg: "Volt Typhoon LOTL Purple Team Drill complete. Review the technical score, MTTD/MTTR, and which native-tool techniques went undetected."},
			},
		},
	},
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/exercise/... -run 'TestBuiltinTemplates_PurpleTeam' -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add orchestrator/internal/exercise/templates.go orchestrator/internal/exercise/templates_test.go
git commit -m "feat(exercise): Volt Typhoon LOTL Purple Team Drill template"
```

---

### Task 4: Kerberoasting & AD Credential Theft Purple Team Drill

**Files:**
- Modify: `orchestrator/internal/exercise/templates.go` (append to `BuiltinTemplates`)
- Modify: `orchestrator/internal/exercise/templates_test.go` (extend both cross-cutting tests + one dedicated identity-gate assertion)

**Interfaces:**
- Consumes: `TemplateMetadata` (Task 1). Extends both cross-cutting tests.
- Produces: `BuiltinTemplates` entry `"builtin-purple-kerberoasting"`.

- [ ] **Step 1: Write the failing test extensions**

Add a row to `TestBuiltinTemplates_PurpleTeamDetectionBridgeWiring`'s `cases`:

```go
		{"builtin-purple-apt29", "drill_sim"},
		{"builtin-purple-volt-typhoon", "drill_sim"},
		{"builtin-purple-kerberoasting", "drill_sim"},
```

Add to `TestBuiltinTemplates_PurpleTeamMetadataPopulated`'s `ids`:

```go
	ids := []string{"builtin-purple-apt29", "builtin-purple-volt-typhoon", "builtin-purple-kerberoasting"}
```

Add a new, dedicated test asserting the identity-only gate — this is the one behavioral property (not just wiring/metadata presence) this template must get right:

```go
func TestBuiltinTemplates_KerberoastingIdentityOnlyGate(t *testing.T) {
	var tpl *Template
	for i := range BuiltinTemplates {
		if BuiltinTemplates[i].ID == "builtin-purple-kerberoasting" {
			tpl = &BuiltinTemplates[i]
		}
	}
	if tpl == nil {
		t.Fatal("builtin-purple-kerberoasting: template not found")
	}
	var wait *PlanStep
	for i := range tpl.Steps {
		if tpl.Steps[i].ID == "wait_detect" {
			wait = &tpl.Steps[i]
		}
	}
	if wait == nil || wait.Config.WaitForDetection == nil {
		t.Fatal("wait_detect step or its WaitForDetection config is missing")
	}
	types := wait.Config.WaitForDetection.DetectionTypes
	if len(types) != 1 || types[0] != "security_control_detected" {
		t.Errorf("DetectionTypes = %v, want exactly [security_control_detected] — an EDR alert must not be able to satisfy this identity-focused drill's gate", types)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/exercise/... -run 'TestBuiltinTemplates_PurpleTeam|TestBuiltinTemplates_KerberoastingIdentityOnlyGate' -v`
Expected: FAIL — `builtin-purple-kerberoasting: template not found`

- [ ] **Step 3: Add the Kerberoasting template**

Append to `BuiltinTemplates`, immediately after the Volt Typhoon entry added in Task 3:

```go

	// ── 8. Kerberoasting & AD Credential Theft Purple Team Drill ──────────────
	{
		ID:          "builtin-purple-kerberoasting",
		Name:        "Kerberoasting & AD Credential Theft Purple Team Drill",
		Version:     1,
		Category:    "purple-team",
		Description: "Runs the Kerberoasting and AS-REP roasting simulation against Active Directory — service-account ticket requests, AD enumeration, GPO discovery — and measures identity-layer detection coverage independent of endpoint EDR.",
		Author:      "Audspect",
		BuiltIn:     true,
		Variables: []VarDef{
			{Name: "AgentID", Type: VarTypeEndpoint, Required: true, Description: "Target agent for the simulation"},
			{Name: "ScenarioID", Type: VarTypeString, Required: true, Default: "kerberoasting-ad-drill", Description: "Scenario to execute"},
			{Name: "DetectionTimeout", Type: VarTypeDuration, Default: "30m", Description: "Max time to wait for detection before timing out"},
			{Name: "SOCNotifyEmail", Type: VarTypeEmailList, Description: "Email to notify when drill completes"},
		},
		Metadata: TemplateMetadata{
			SuccessCriteria: "An identity-layer detection (Kerberos ticket requests, AD enumeration) is confirmed within the detection timeout — deliberately gated on identity-domain evidence only, not endpoint EDR, so an unrelated EDR alert can't silently satisfy this drill's real question. Microsoft Defender for Identity (and Sigma/SIEM providers generally) default to manual verification in this platform; confirming this signal today means either a SOC analyst manually attesting via the Detection Verification UI during the exercise, or a configured identity/SIEM API connector. A timeout with no manual attestation is itself the finding: identity-layer verification isn't wired up yet.",
			LearningObjectives: []string{
				"Validate identity/AD detection coverage independent of endpoint telemetry",
				"Confirm Microsoft Defender for Identity (or equivalent) is actually alerting on Kerberoasting/AS-REP roasting patterns",
				"Identify which service accounts are exposed to ticket-request-based credential theft",
				"Surface whether identity-layer verification is automated (API connector) or still manual-only in this environment",
			},
			ExpectedTechniques:      []string{"T1558.003", "T1558.004", "T1087.002", "T1482", "T1069.002", "T1615", "T1552.006"},
			ExpectedDetections:      []string{"Microsoft Defender for Identity", "Microsoft Defender"},
			RecommendedParticipants: []string{"SOC Analyst", "Identity/AD Administrator", "IR Lead (approval)"},
			RecommendedDuration:     "1-2 hours",
			DiscussionPrompts: []string{
				"Did the identity-layer control detect this before or independent of endpoint EDR?",
				"Which service accounts used in this drill have weak/crackable passwords in production?",
				"How quickly could an analyst distinguish this from legitimate Kerberos ticket activity?",
				"If wait_detect timed out: was that because nothing fired, or because no one attested it during the window?",
			},
		},
		Steps: []PlanStep{
			{
				ID: "drill_sim", Type: StepTypeAgentTask, Label: "Trigger Kerberoasting/AD simulation",
				Config: StepConfig{AgentTask: &AgentTaskConfig{AgentID: "${AgentID}", ScenarioID: "${ScenarioID}"}},
			},
			{
				ID: "wait_sim_done", Type: StepTypeWaitForAgent, Label: "Wait for simulation to complete",
				DependsOn:   []string{"drill_sim"},
				Config:      StepConfig{WaitForAgent: &WaitForAgentConfig{AgentTaskStepID: "drill_sim"}},
				TimeoutSecs: 1800,
			},
			{
				ID: "wait_detect", Type: StepTypeWaitForDetection, Label: "Wait for identity-layer detection",
				DependsOn:   []string{"wait_sim_done"},
				TimeoutSecs: 1800,
				Config: StepConfig{WaitForDetection: &WaitForDetectionConfig{
					DetectionTypes:  []string{"security_control_detected"}, // identity-only, deliberately excludes edr_detected
					ExecutionStepID: "drill_sim",
				}},
			},
			{
				ID: "approval_response", Type: StepTypeApproval, Label: "SOC: confirm incident response completed",
				DependsOn:   []string{"wait_detect"},
				TimeoutSecs: 7200,
				Config: StepConfig{
					ApprovalPrompt: "Has the SOC/identity team completed triage and confirmed which service accounts were affected?",
					ApproverRoles:  []string{"admin", "analyst"},
				},
			},
			{
				ID: "drill_complete", Type: StepTypeNotify, Label: "Kerberoasting drill complete — check identity detection coverage",
				DependsOn: []string{"approval_response"},
				Config:    StepConfig{NotifyMsg: "Kerberoasting & AD Credential Theft Purple Team Drill complete. Review identity-layer detection coverage and MTTD/MTTR."},
			},
		},
	},
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/exercise/... -run 'TestBuiltinTemplates_PurpleTeam|TestBuiltinTemplates_KerberoastingIdentityOnlyGate' -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add orchestrator/internal/exercise/templates.go orchestrator/internal/exercise/templates_test.go
git commit -m "feat(exercise): Kerberoasting & AD Credential Theft Purple Team Drill template (identity-only gate)"
```

---

### Task 5: Collection→Staging→Exfiltration Purple Team Drill

**Files:**
- Modify: `orchestrator/internal/exercise/templates.go` (append to `BuiltinTemplates`)
- Modify: `orchestrator/internal/exercise/templates_test.go` (extend both cross-cutting tests)

**Interfaces:**
- Consumes: `TemplateMetadata` (Task 1). Extends both cross-cutting tests.
- Produces: `BuiltinTemplates` entry `"builtin-purple-collection-exfil"`.

- [ ] **Step 1: Write the failing test extension**

Add a row to `TestBuiltinTemplates_PurpleTeamDetectionBridgeWiring`'s `cases`:

```go
		{"builtin-purple-apt29", "drill_sim"},
		{"builtin-purple-volt-typhoon", "drill_sim"},
		{"builtin-purple-kerberoasting", "drill_sim"},
		{"builtin-purple-collection-exfil", "drill_sim"},
```

Add to `TestBuiltinTemplates_PurpleTeamMetadataPopulated`'s `ids`:

```go
	ids := []string{"builtin-purple-apt29", "builtin-purple-volt-typhoon", "builtin-purple-kerberoasting", "builtin-purple-collection-exfil"}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/exercise/... -run 'TestBuiltinTemplates_PurpleTeam' -v`
Expected: FAIL — `builtin-purple-collection-exfil: template not found`

- [ ] **Step 3: Add the Collection-Exfil template**

Append to `BuiltinTemplates`, immediately after the Kerberoasting entry added in Task 4:

```go

	// ── 9. Collection to Exfiltration Purple Team Drill ────────────────────────
	{
		ID:          "builtin-purple-collection-exfil",
		Name:        "Collection to Exfiltration Purple Team Drill",
		Version:     1,
		Category:    "purple-team",
		Description: "Runs the collection-staging-exfiltration simulation — file discovery, local staging, archive creation, and network egress over multiple channels — and measures whether exfil-path telemetry is captured end-to-end, not just at the initial discovery step.",
		Author:      "Audspect",
		BuiltIn:     true,
		Variables: []VarDef{
			{Name: "AgentID", Type: VarTypeEndpoint, Required: true, Description: "Target agent for the simulation"},
			{Name: "ScenarioID", Type: VarTypeString, Required: true, Default: "collection-staging-exfil", Description: "Scenario to execute"},
			{Name: "DetectionTimeout", Type: VarTypeDuration, Default: "30m", Description: "Max time to wait for detection before timing out"},
			{Name: "SOCNotifyEmail", Type: VarTypeEmailList, Description: "Email to notify when drill completes"},
		},
		Metadata: TemplateMetadata{
			SuccessCriteria: "The technical gate confirms at least one exfil-path signal (archive staging or network egress — the two steps in this scenario with detection profiles attached) was detected within the detection timeout; full chain-stage coverage is reviewed by the SOC at the approval step using the complete evidence chain. Only microsoft_defender (EDR-domain) evidence resolves automatically today — the microsoft_purview (DLP-domain, per this platform's provider registry) and microsoft_sentinel (SIEM) signals require either a configured API connector or a SOC analyst manually attesting via the Detection Verification UI during the exercise.",
			LearningObjectives: []string{
				"Validate end-to-end exfil-chain visibility, not just discovery-stage detection",
				"Confirm DLP/CASB (Microsoft Purview) and network egress controls catch staged data leaving the host",
				"Identify which exfil channel (local staging vs. archive vs. cloud egress) is weakest",
			},
			ExpectedTechniques:      []string{"T1083", "T1074.001", "T1560.001", "T1048.001", "T1048.003", "T1567.002"},
			ExpectedDetections:      []string{"Microsoft Defender", "Microsoft Purview", "Microsoft Sentinel"},
			RecommendedParticipants: []string{"SOC Analyst", "Detection Engineer", "IR Lead (approval)"},
			RecommendedDuration:     "1-2 hours",
			DiscussionPrompts: []string{
				"Was the initial file discovery detected, or only the later staging/egress steps?",
				"Which exfil channel in this chain would be hardest to detect in your environment?",
				"Did DLP/CASB tooling catch the archive or cloud-upload step independent of endpoint EDR?",
			},
		},
		Steps: []PlanStep{
			{
				ID: "drill_sim", Type: StepTypeAgentTask, Label: "Trigger collection-to-exfiltration simulation",
				Config: StepConfig{AgentTask: &AgentTaskConfig{AgentID: "${AgentID}", ScenarioID: "${ScenarioID}"}},
			},
			{
				ID: "wait_sim_done", Type: StepTypeWaitForAgent, Label: "Wait for simulation to complete",
				DependsOn:   []string{"drill_sim"},
				Config:      StepConfig{WaitForAgent: &WaitForAgentConfig{AgentTaskStepID: "drill_sim"}},
				TimeoutSecs: 1800,
			},
			{
				ID: "wait_detect", Type: StepTypeWaitForDetection, Label: "Wait for SOC/DLP detection",
				DependsOn:   []string{"wait_sim_done"},
				TimeoutSecs: 1800,
				Config: StepConfig{WaitForDetection: &WaitForDetectionConfig{
					DetectionTypes:  []string{"edr_detected", "siem_alerted", "security_control_detected"},
					ExecutionStepID: "drill_sim",
				}},
			},
			{
				ID: "approval_response", Type: StepTypeApproval, Label: "SOC: confirm incident response completed",
				DependsOn:   []string{"wait_detect"},
				TimeoutSecs: 7200,
				Config: StepConfig{
					ApprovalPrompt: "Has the SOC completed triage and confirmed which stage of the exfil chain was (or wasn't) detected?",
					ApproverRoles:  []string{"admin", "analyst"},
				},
			},
			{
				ID: "drill_complete", Type: StepTypeNotify, Label: "Exfil drill complete — check per-stage coverage",
				DependsOn: []string{"approval_response"},
				Config:    StepConfig{NotifyMsg: "Collection to Exfiltration Purple Team Drill complete. Review per-stage detection coverage, MTTD/MTTR."},
			},
		},
	},
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/exercise/... -run 'TestBuiltinTemplates_PurpleTeam' -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add orchestrator/internal/exercise/templates.go orchestrator/internal/exercise/templates_test.go
git commit -m "feat(exercise): Collection to Exfiltration Purple Team Drill template"
```

---

### Task 6: DLP Exfiltration Purple Team Drill + final regression

**Files:**
- Modify: `orchestrator/internal/exercise/templates.go` (append to `BuiltinTemplates`)
- Modify: `orchestrator/internal/exercise/templates_test.go` (extend both cross-cutting tests + one dedicated MinCount assertion)

**Interfaces:**
- Consumes: `TemplateMetadata` (Task 1). Extends both cross-cutting tests.
- Produces: `BuiltinTemplates` entry `"builtin-purple-dlp-exfil"` — the fifth and final template.

- [ ] **Step 1: Write the failing test extensions**

Add the final row to `TestBuiltinTemplates_PurpleTeamDetectionBridgeWiring`'s `cases`:

```go
		{"builtin-purple-apt29", "drill_sim"},
		{"builtin-purple-volt-typhoon", "drill_sim"},
		{"builtin-purple-kerberoasting", "drill_sim"},
		{"builtin-purple-collection-exfil", "drill_sim"},
		{"builtin-purple-dlp-exfil", "drill_sim"},
```

Add to `TestBuiltinTemplates_PurpleTeamMetadataPopulated`'s `ids`:

```go
	ids := []string{"builtin-purple-apt29", "builtin-purple-volt-typhoon", "builtin-purple-kerberoasting", "builtin-purple-collection-exfil", "builtin-purple-dlp-exfil"}
```

Add a new, dedicated test asserting the `MinCount: 5` behavioral property:

```go
func TestBuiltinTemplates_DLPRequiresAllFiveChannels(t *testing.T) {
	var tpl *Template
	for i := range BuiltinTemplates {
		if BuiltinTemplates[i].ID == "builtin-purple-dlp-exfil" {
			tpl = &BuiltinTemplates[i]
		}
	}
	if tpl == nil {
		t.Fatal("builtin-purple-dlp-exfil: template not found")
	}
	var wait *PlanStep
	for i := range tpl.Steps {
		if tpl.Steps[i].ID == "wait_detect" {
			wait = &tpl.Steps[i]
		}
	}
	if wait == nil || wait.Config.WaitForDetection == nil {
		t.Fatal("wait_detect step or its WaitForDetection config is missing")
	}
	if wait.Config.WaitForDetection.MinCount != 5 {
		t.Errorf("MinCount = %d, want 5 — DLP's five channels are one coherent claim, not partial-credit signal", wait.Config.WaitForDetection.MinCount)
	}
	types := wait.Config.WaitForDetection.DetectionTypes
	if len(types) != 1 || types[0] != "security_control_detected" {
		t.Errorf("DetectionTypes = %v, want exactly [security_control_detected]", types)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/exercise/... -run 'TestBuiltinTemplates_PurpleTeam|TestBuiltinTemplates_DLPRequiresAllFiveChannels' -v`
Expected: FAIL — `builtin-purple-dlp-exfil: template not found`

- [ ] **Step 3: Add the DLP template**

Append to `BuiltinTemplates`, immediately after the Collection-Exfil entry added in Task 5:

```go

	// ── 10. DLP Exfiltration Purple Team Drill ─────────────────────────────────
	{
		ID:          "builtin-purple-dlp-exfil",
		Name:        "DLP Exfiltration Purple Team Drill",
		Version:     1,
		Category:    "purple-team",
		Description: "Runs the DLP exfiltration validation simulation — synthetic regulated data (PAN/Aadhaar/SWIFT/UPI/credit-card) attempted over USB, clipboard, print, archive, and local-staging channels — and measures whether DLP policy actually blocks each channel, not just logs it.",
		Author:      "Audspect",
		BuiltIn:     true,
		Variables: []VarDef{
			{Name: "AgentID", Type: VarTypeEndpoint, Required: true, Description: "Target agent for the simulation"},
			{Name: "ScenarioID", Type: VarTypeString, Required: true, Default: "dlp-exfiltration-validation", Description: "Scenario to execute"},
			{Name: "DetectionTimeout", Type: VarTypeDuration, Default: "30m", Description: "Max time to wait for detection before timing out"},
			{Name: "SOCNotifyEmail", Type: VarTypeEmailList, Description: "Email to notify when drill completes"},
		},
		Metadata: TemplateMetadata{
			SuccessCriteria: "DLP policy blocks regulated-data exfiltration across all five channels (USB, clipboard, print, archive, local-staging) within the detection timeout — a policy that only logs/warns does not meet this criterion (see the DLP Validation Suite's asymmetric truth table: a local verifier can only prove Block, not softer outcomes).",
			LearningObjectives: []string{
				"Validate DLP policy actually blocks (not just logs) regulated-data exfiltration",
				"Confirm coverage across all agent-native channels an insider or malware could use, not only network egress",
				"Identify which channel, if any, DLP policy doesn't yet cover",
			},
			ExpectedTechniques:      []string{"T1052.001", "T1115", "T1052", "T1560.001", "T1074.001"},
			ExpectedDetections:      []string{"Trellix DLP"},
			RecommendedParticipants: []string{"SOC Analyst", "DLP/Compliance Administrator", "IR Lead (approval)"},
			RecommendedDuration:     "1-2 hours",
			DiscussionPrompts: []string{
				"Which of the five channels, if any, was NOT blocked by DLP policy?",
				"Is the gap a policy-coverage gap or an agent-visibility gap?",
				"Would this synthetic data pattern (PAN/Aadhaar/SWIFT/UPI/credit-card) be representative of what your DLP policy is actually tuned to catch in production?",
			},
		},
		Steps: []PlanStep{
			{
				ID: "drill_sim", Type: StepTypeAgentTask, Label: "Trigger DLP exfiltration simulation",
				Config: StepConfig{AgentTask: &AgentTaskConfig{AgentID: "${AgentID}", ScenarioID: "${ScenarioID}"}},
			},
			{
				ID: "wait_sim_done", Type: StepTypeWaitForAgent, Label: "Wait for simulation to complete",
				DependsOn:   []string{"drill_sim"},
				Config:      StepConfig{WaitForAgent: &WaitForAgentConfig{AgentTaskStepID: "drill_sim"}},
				TimeoutSecs: 1800,
			},
			{
				ID: "wait_detect", Type: StepTypeWaitForDetection, Label: "Wait for DLP block confirmation",
				DependsOn:   []string{"wait_sim_done"},
				TimeoutSecs: 1800,
				Config: StepConfig{WaitForDetection: &WaitForDetectionConfig{
					DetectionTypes:  []string{"security_control_detected"},
					MinCount:        5, // all 5 channels — one coherent claim, unlike the other templates' default MinCount:1
					ExecutionStepID: "drill_sim",
				}},
			},
			{
				ID: "approval_response", Type: StepTypeApproval, Label: "SOC/Compliance: confirm DLP coverage reviewed",
				DependsOn:   []string{"wait_detect"},
				TimeoutSecs: 7200,
				Config: StepConfig{
					ApprovalPrompt: "Has the SOC/DLP team reviewed which of the five channels were blocked vs. not blocked?",
					ApproverRoles:  []string{"admin", "analyst"},
				},
			},
			{
				ID: "drill_complete", Type: StepTypeNotify, Label: "DLP drill complete — check per-channel block coverage",
				DependsOn: []string{"approval_response"},
				Config:    StepConfig{NotifyMsg: "DLP Exfiltration Purple Team Drill complete. Review per-channel block coverage across USB, clipboard, print, archive, and local-staging."},
			},
		},
	},
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/exercise/... -run 'TestBuiltinTemplates_PurpleTeam|TestBuiltinTemplates_DLPRequiresAllFiveChannels|TestBuiltinTemplates_KerberoastingIdentityOnlyGate' -v`
Expected: PASS

- [ ] **Step 5: Verify it compiles**

Run: `go build ./...`
Expected: no errors

- [ ] **Step 6: Run the full exercise package suite**

Run: `go test ./internal/exercise/... -v -count=1`
Expected: 100% PASS — all Phase A0/A1 tests plus every test added in this plan, unmodified assertions on the pre-existing ones

- [ ] **Step 7: Run `go vet`**

Run: `go vet ./...`
Expected: no output

- [ ] **Step 8: Commit**

```bash
git add orchestrator/internal/exercise/templates.go orchestrator/internal/exercise/templates_test.go
git commit -m "feat(exercise): DLP Exfiltration Purple Team Drill template — all 5 Purple Team templates shipped"
```
