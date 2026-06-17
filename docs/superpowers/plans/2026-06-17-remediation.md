# Remediation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans (inline; no subagents per user preference). Steps use checkbox (`- [ ]`) syntax.

**Goal:** A computed-on-read Remediation view: per-technique fixes derived from open findings, surfacing authoritative ATT&CK mitigations + detection guidance, with re-validation.

**Architecture:** A pure `findings.Remediations` groups open-finding projections into per-technique remediations (worst severity, finding/agent counts, missed/detected split, sorted). A read endpoint `GET /api/remediations` queries open findings, runs the helper, and attaches `attackdata` mitigations/detection. A frontend page renders the cards + detail drawer. No new table; no persistent state.

**Tech Stack:** Go (chi, pgx, embedded `attackdata`), vanilla JS in `wwwroot/index.html`.

**Spec:** `docs/superpowers/specs/2026-06-17-remediation-design.md`

## Global Constraints

- **No remediations table** — computed-on-read; findings own all state.
- Content is **authoritative MITRE ATT&CK** (mitigations + detection), labelled as such; no fabricated steps, no effort rating, no posture-gain points.
- Keep `findingCount` and `agentCount` **separate**; expose `missed` / `detectedOnly` breakdown.
- Mitigation `id` is in the response contract but empty until the enrichment bundle is regenerated (do not fabricate M-codes).
- Sort: `severity DESC, missed DESC, agentCount DESC`.
- Unbuilt actions (Export/Jira/Report) are **not rendered** (no greyed buttons).
- Reads = viewer+.
- No tests against real/prod Postgres.

---

## Task 1: pure remediation grouping (TDD)

**Files:** Modify `orchestrator/internal/findings/findings.go`, `orchestrator/internal/findings/findings_test.go`

**Interfaces produced** (used by Task 2):
- `type FindingRef struct { TechniqueID, TechniqueName, Tactic, Severity, ControlClass, ExposureState, AgentID string }`
- `type Remediation struct { TechniqueID, TechniqueName, Tactic, Severity string; ControlClasses []string; FindingCount, AgentCount, Missed, DetectedOnly int; RecommendedTargets []string }`
- `func Remediations(refs []FindingRef) []Remediation`

- [ ] **Step 1: Failing test** (append to `findings_test.go`):

```go
func TestRemediations(t *testing.T) {
	refs := []FindingRef{
		{TechniqueID: "T1003", TechniqueName: "OS Credential Dumping", Tactic: "credential-access", Severity: "Critical", ControlClass: "Endpoint", ExposureState: "missed", AgentID: "WIN-01"},
		{TechniqueID: "T1003", TechniqueName: "OS Credential Dumping", Tactic: "credential-access", Severity: "High", ControlClass: "Endpoint", ExposureState: "detected_only", AgentID: "WIN-02"},
		{TechniqueID: "T1003", TechniqueName: "OS Credential Dumping", Tactic: "credential-access", Severity: "Critical", ControlClass: "Identity", ExposureState: "missed", AgentID: "WIN-01"},
		{TechniqueID: "T1059", TechniqueName: "Command Interpreter", Tactic: "execution", Severity: "Critical", ControlClass: "Endpoint", ExposureState: "missed", AgentID: "WIN-09"},
	}
	got := Remediations(refs)
	if len(got) != 2 {
		t.Fatalf("want 2 remediations, got %d", len(got))
	}
	// T1003 sorts first: same Critical severity but more missed (2 vs 1).
	r := got[0]
	if r.TechniqueID != "T1003" {
		t.Fatalf("want T1003 first, got %s", r.TechniqueID)
	}
	if r.Severity != "Critical" {
		t.Errorf("severity = %q, want Critical (worst)", r.Severity)
	}
	if r.FindingCount != 3 || r.AgentCount != 2 {
		t.Errorf("counts: findings=%d agents=%d, want 3/2", r.FindingCount, r.AgentCount)
	}
	if r.Missed != 2 || r.DetectedOnly != 1 {
		t.Errorf("exposure: missed=%d detected=%d, want 2/1", r.Missed, r.DetectedOnly)
	}
	if len(r.ControlClasses) != 2 {
		t.Errorf("control classes = %v, want 2 distinct", r.ControlClasses)
	}
	if len(r.RecommendedTargets) != 2 { // WIN-01 (deduped) + WIN-02
		t.Errorf("targets = %v, want 2 distinct agents", r.RecommendedTargets)
	}
}
```

- [ ] **Step 2: Run, confirm FAIL:** `cd orchestrator && go test ./internal/findings/` → undefined `Remediations`.

- [ ] **Step 3: Implement** — append to `findings.go`:

```go
// FindingRef is the open-finding projection the remediation grouper consumes.
type FindingRef struct {
	TechniqueID, TechniqueName, Tactic, Severity, ControlClass, ExposureState, AgentID string
}

// Remediation is one per-technique fix derived from open findings (computed; not
// stored). ATT&CK mitigations/detection are attached by the caller.
type Remediation struct {
	TechniqueID        string   `json:"techniqueId"`
	TechniqueName      string   `json:"techniqueName"`
	Tactic             string   `json:"tactic"`
	Severity           string   `json:"severity"`
	ControlClasses     []string `json:"controlClasses"`
	FindingCount       int      `json:"findingCount"`
	AgentCount         int      `json:"agentCount"`
	Missed             int      `json:"missed"`
	DetectedOnly       int      `json:"detectedOnly"`
	RecommendedTargets []string `json:"recommendedTargets"`
}

func sevRank(s string) int {
	switch s {
	case "Critical":
		return 4
	case "High":
		return 3
	case "Medium":
		return 2
	case "Low":
		return 1
	}
	return 0
}

// Remediations groups open-finding refs into per-technique remediations: worst
// severity, distinct control classes + agents, missed/detected-only split, and
// recommended targets. Sorted severity DESC, then missed DESC, then agents DESC.
func Remediations(refs []FindingRef) []Remediation {
	type acc struct {
		r        *Remediation
		controls map[string]bool
		agents   map[string]bool
	}
	byTech := map[string]*acc{}
	order := []string{}
	for _, f := range refs {
		a := byTech[f.TechniqueID]
		if a == nil {
			a = &acc{r: &Remediation{TechniqueID: f.TechniqueID, TechniqueName: f.TechniqueName, Tactic: f.Tactic, Severity: f.Severity},
				controls: map[string]bool{}, agents: map[string]bool{}}
			byTech[f.TechniqueID] = a
			order = append(order, f.TechniqueID)
		}
		a.r.FindingCount++
		if sevRank(f.Severity) > sevRank(a.r.Severity) {
			a.r.Severity = f.Severity
		}
		if f.ExposureState == "detected_only" {
			a.r.DetectedOnly++
		} else {
			a.r.Missed++
		}
		if f.ControlClass != "" && !a.controls[f.ControlClass] {
			a.controls[f.ControlClass] = true
			a.r.ControlClasses = append(a.r.ControlClasses, f.ControlClass)
		}
		if f.AgentID != "" && !a.agents[f.AgentID] {
			a.agents[f.AgentID] = true
			a.r.RecommendedTargets = append(a.r.RecommendedTargets, f.AgentID)
		}
	}
	out := make([]Remediation, 0, len(order))
	for _, id := range order {
		a := byTech[id]
		a.r.AgentCount = len(a.agents)
		out = append(out, *a.r)
	}
	sort.Slice(out, func(i, j int) bool {
		if a, b := sevRank(out[i].Severity), sevRank(out[j].Severity); a != b {
			return a > b
		}
		if out[i].Missed != out[j].Missed {
			return out[i].Missed > out[j].Missed
		}
		return out[i].AgentCount > out[j].AgentCount
	})
	return out
}
```
(`sort` is already imported in findings.go from the `All()`/ControlClass work — confirm; it is used by neither currently in findings.go, so add `"sort"` to the import block if absent.)

- [ ] **Step 4: Run, confirm PASS:** `cd orchestrator && go test ./internal/findings/`.
- [ ] **Step 5: Commit:** `feat(findings): Remediations — per-technique grouping of open findings`.

---

## Task 2: `GET /api/remediations` endpoint

**Files:** Modify `orchestrator/internal/api/finding_handlers.go`, `orchestrator/internal/api/routes.go`

**Interfaces consumed:** `findings.FindingRef`, `findings.Remediation`, `findings.Remediations`; `attackdata.Lookup(id)` (`.Mitigations`, `.Detection`).

- [ ] **Step 1: Handler** — append to `finding_handlers.go`:

```go
// ListRemediations groups open findings into per-technique remediations and
// attaches authoritative ATT&CK mitigations + detection guidance. Computed on
// read — no remediations table. GET /api/remediations
func (h *Handler) ListRemediations(w http.ResponseWriter, r *http.Request) {
	rows, err := h.db.Query(r.Context(),
		`SELECT technique_id, technique_name, tactic, severity, control_class, exposure_state, agent_id
		   FROM findings WHERE status='open'`)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	var refs []findings.FindingRef
	for rows.Next() {
		var f findings.FindingRef
		if rows.Scan(&f.TechniqueID, &f.TechniqueName, &f.Tactic, &f.Severity, &f.ControlClass, &f.ExposureState, &f.AgentID) == nil {
			refs = append(refs, f)
		}
	}
	rows.Close()

	out := []map[string]any{}
	for _, rem := range findings.Remediations(refs) {
		mits := []map[string]string{}
		detection := ""
		if e := attackdata.Lookup(rem.TechniqueID); e != nil {
			for _, m := range e.Mitigations {
				mits = append(mits, map[string]string{"id": "", "name": m.Name, "description": m.Description})
			}
			detection = e.Detection
		}
		out = append(out, map[string]any{
			"techniqueId": rem.TechniqueID, "techniqueName": rem.TechniqueName, "tactic": rem.Tactic,
			"severity": rem.Severity, "controlClasses": rem.ControlClasses,
			"findingCount": rem.FindingCount, "agentCount": rem.AgentCount,
			"missed": rem.Missed, "detectedOnly": rem.DetectedOnly,
			"recommendedTargets": rem.RecommendedTargets, "mitigations": mits, "detection": detection,
		})
	}
	respond(w, out)
}
```

- [ ] **Step 2: Route** in `routes.go` outer authed read group (near `/api/findings`):

```go
		r.Get("/api/remediations", h.ListRemediations)
```

- [ ] **Step 3: Build + vet + test:** `cd orchestrator && go build ./... && go vet ./internal/api/ && go test ./internal/api/ ./internal/findings/`.
- [ ] **Step 4: Commit:** `feat(api): GET /api/remediations (computed from open findings + ATT&CK)`.

---

## Task 3: Remediation page (frontend)

**Files:** Modify `orchestrator/wwwroot/index.html`

- [ ] **Step 1: Nav + tab registration** — add a "Remediation" nav item in the Visibility group (after Findings), add `'remediation'` to the `showTab`/`activateTab` arrays, `if (name === 'remediation') loadRemediations();`, and `TAB_TITLES` entry `remediation: 'Remediation'`.

- [ ] **Step 2: Tab markup** after `#tab-findings`:

```html
      <!-- Remediation -->
      <div id="tab-remediation" style="display:none">
        <div style="margin-bottom:1rem">
          <h1 style="font-family:var(--font-display);font-size:1.5rem;font-weight:700;letter-spacing:-0.02em;margin:0 0 0.3rem;color:var(--text)">Remediation</h1>
          <div style="font-size:0.8rem;color:var(--muted)">Prioritized fixes from your open findings, with authoritative MITRE ATT&amp;CK mitigations. Re-validate after applying a fix.</div>
        </div>
        <div class="kpi-row" id="rem-tiles"></div>
        <div id="rem-list"><div class="empty" style="padding:2rem">Loading…</div></div>
      </div>
```

- [ ] **Step 3: JS** (near `loadFindings`):

```js
function loadRemediations() {
  apicall('/api/remediations').then(function(list) {
    window._rems = list || [];
    renderRemTiles(); renderRemList();
  }).catch(function(e) { document.getElementById('rem-list').innerHTML = '<div class="empty" style="padding:2rem">' + x(e.message) + '</div>'; });
}
function renderRemTiles() {
  var l = window._rems || [];
  var findingsTotal = l.reduce(function(s, r) { return s + (r.findingCount || 0); }, 0);
  var crit = l.filter(function(r) { return r.severity === 'Critical'; }).length;
  var tile = function(lbl, val, col) {
    return '<div class="kpi-card stat-tile"><div class="stat-top"><div><div class="kpi-label">' + lbl +
      '</div><div class="kpi-value" style="color:' + col + '">' + val + '</div></div></div></div>';
  };
  document.getElementById('rem-tiles').innerHTML =
    tile('Open remediations', l.length, 'var(--warning)') +
    tile('Affected findings', findingsTotal, findingsTotal ? 'var(--danger)' : 'var(--success)') +
    tile('Critical remediations', crit, crit ? 'var(--danger)' : 'var(--muted)');
}
function renderRemList() {
  var l = window._rems || [];
  var el = document.getElementById('rem-list');
  if (!l.length) { el.innerHTML = '<div class="empty" style="padding:2rem">No open remediations — nothing to fix right now.</div>'; return; }
  el.innerHTML = l.map(function(r, i) {
    return '<div class="dash-panel" style="margin-bottom:0.75rem"><div class="dash-panel-body" style="display:flex;gap:0.9rem;align-items:flex-start">' +
      '<div style="flex:1;min-width:0">' +
        '<div style="display:flex;align-items:center;gap:0.5rem;margin-bottom:0.25rem">' + findingSevBadge(r.severity, '') +
          ' <span class="tech-id">' + x(r.techniqueId) + '</span></div>' +
        '<div style="font-weight:600;color:var(--text);margin-bottom:0.3rem">' + x(r.techniqueName) + '</div>' +
        '<div class="tiny muted" style="display:flex;gap:1rem;flex-wrap:wrap">' +
          '<span>' + (r.controlClasses || []).map(x).join(', ') + '</span>' +
          '<span>Closes ' + r.findingCount + ' finding' + (r.findingCount === 1 ? '' : 's') + ' on ' + r.agentCount + ' agent' + (r.agentCount === 1 ? '' : 's') + '</span>' +
          '<span>Missed: ' + r.missed + ' · Detected only: ' + r.detectedOnly + '</span></div>' +
      '</div>' +
      '<button class="btn btn-outline btn-sm" style="flex-shrink:0" onclick="openRemediation(' + i + ')">View</button>' +
      '<button class="btn btn-primary btn-sm" style="flex-shrink:0" onclick="revalidateRemediation(\'' + x(r.techniqueId) + '\')">&#8635; Re-validate</button>' +
      '</div></div>';
  }).join('');
}
function openRemediation(i) {
  var r = (window._rems || [])[i];
  if (!r) return;
  document.getElementById('results-title').textContent = r.techniqueId + ' — Remediation';
  document.getElementById('results-export').innerHTML =
    '<button class="btn btn-primary btn-sm" onclick="revalidateRemediation(\'' + x(r.techniqueId) + '\')">&#8635; Re-validate</button>';
  var mits = (r.mitigations || []).map(function(m) {
    return '<div style="padding:0.4rem 0;border-bottom:1px solid var(--border)"><div style="font-weight:600;font-size:0.8rem">' + x(m.name) + '</div>' +
      (m.description ? '<div class="tiny muted" style="margin-top:0.2rem;line-height:1.5">' + x(m.description) + '</div>' : '') + '</div>';
  }).join('') || '<div class="tiny muted">No ATT&CK mitigations listed for this technique.</div>';
  var head = function(t) { return '<div style="font-size:0.65rem;font-weight:700;text-transform:uppercase;letter-spacing:.08em;color:var(--accent);margin:0.7rem 0 0.3rem">' + t + '</div>'; };
  document.getElementById('results-body').innerHTML =
    '<div style="margin-bottom:0.6rem">' + findingSevBadge(r.severity, '') + ' <span class="tech-id">' + x(r.techniqueId) + '</span> ' + x(r.techniqueName) + '</div>' +
    '<div class="tiny muted">Closes ' + r.findingCount + ' finding(s) on ' + r.agentCount + ' agent(s) · Missed ' + r.missed + ' · Detected only ' + r.detectedOnly + '</div>' +
    head('ATT&CK Mitigations') + mits +
    (r.detection ? head('ATT&CK Detection Guidance') + '<div class="tiny" style="color:var(--text-dim);line-height:1.55">' + x(r.detection) + '</div>' : '') +
    head('Affected agents') + '<div class="tiny muted">' + (r.recommendedTargets || []).map(x).join(', ') + '</div>' +
    '<div class="tiny muted" style="margin-top:0.8rem;opacity:0.8">Mitigation &amp; detection content © MITRE ATT&CK®.</div>';
  document.getElementById('results-overlay').classList.add('open');
}
function revalidateRemediation(techniqueId) {
  showToast('Re-validate ' + techniqueId + ' — pick a scenario + target', 'ok');
  openModal();
}
```

- [ ] **Step 4: Validate + commit:** `node -e "...new Function(script)..."` → OK. Commit: `feat(remediation): Remediation page — tiles, cards, detail drawer, re-validate`.

---

## Self-Review

**Spec coverage:** per-technique grouping ✓ (T1); worst severity + finding/agent counts + missed/detected split + recommendedTargets + sort ✓ (T1, tested); `GET /api/remediations` with ATT&CK mitigations (id field empty) + detection ✓ (T2); computed-on-read, no table ✓; page with 3 tiles (Open / Affected findings / Critical) + cards + detail drawer + re-validate ✓ (T3); ATT&CK source labelled ("ATT&CK Mitigations" / "ATT&CK Detection Guidance" + © MITRE) ✓; Export/Jira/Report not rendered ✓; no effort/posture-gain ✓.

**Placeholder scan:** none. Mitigation `id:""` is intentional (documented contract field pending bundle regen), not a placeholder.

**Type consistency:** `FindingRef`/`Remediation`/`Remediations` defined T1, consumed T2. Response JSON keys (`techniqueId`, `controlClasses`, `findingCount`, `agentCount`, `missed`, `detectedOnly`, `recommendedTargets`, `mitigations`, `detection`) consistent T2↔T3. `findingSevBadge` reused from the Findings page. `openModal` is the existing run-wizard opener. `activateTab` (from the campaigns work) gets the new tab name too.

**Risk notes:** the endpoint reads all open findings each call (fine at expected volume; same pattern as ListFindings). attackdata.Lookup nil → empty mitigations/detection (degrades cleanly). Re-validate opens the wizard untargeted in v1 (recommendedTargets ships for future pre-fill). No DB-backed handler test (no prod-DB rule); the pure grouper carries the logic coverage.
