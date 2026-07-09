package api

// Detection Validation SP2 — manual-verification API. These handlers are the
// write path INTO the independent Verification Store (analyst attestations +
// evidence) and the read path for the verification queue. Reporting reads the
// same store separately; nothing here touches report generation. SP3 connectors
// will reuse verification.Store.Attest with Source=api and add no code here.

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/audspect/bas/internal/auth"
	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/verification"
)

// maxEvidenceBytes caps a single evidence upload (25 MiB) — screenshots,
// exported alerts, KQL/CSV files, short PDFs.
const maxEvidenceBytes = 25 << 20

// WithVerificationStore attaches the Verification Store to the handler.
func (h *Handler) WithVerificationStore(s *verification.Store) *Handler {
	h.verification = s
	return h
}

// QueueItem is one row of the verification queue: an off-host expectation that
// needs analyst attestation, merged with its current stored verdict (if any).
type QueueItem struct {
	RunID           string     `json:"runId"`
	ExpectationID   string     `json:"expectationId"`
	TechniqueID     string     `json:"techniqueId"`
	Domain          string     `json:"domain"`
	Provider        string     `json:"provider"`
	ProviderDisplay string     `json:"providerDisplay"`
	Confidence      string     `json:"confidence"`
	Verification    string     `json:"verification"`
	ProfileName     string     `json:"profileName,omitempty"`
	ProfileVersion  int        `json:"profileVersion,omitempty"`
	VerificationID  string     `json:"verificationId,omitempty"`
	Status          string     `json:"status"` // Pending / NeedsReview / Rejected / Detected / NotDetected / NotApplicable
	Result          string     `json:"result,omitempty"`
	WorkflowState   string     `json:"workflowState"` // Pending / NeedsReview / Approved / Rejected
	Source          string     `json:"source,omitempty"`
	VerifiedBy      string     `json:"verifiedBy,omitempty"`
	VerifiedAt      *time.Time `json:"verifiedAt,omitempty"`
	Note            string     `json:"note,omitempty"`
	AlertID         string     `json:"alertId,omitempty"`
	EvidenceCount   int        `json:"evidenceCount"`
}

// runScenario loads the scenario for a run id.
func (h *Handler) runScenario(ctx context.Context, runID string) (*scenario.Scenario, bool) {
	if h.engine == nil {
		return nil, false
	}
	var scenarioID string
	if err := h.db.QueryRow(ctx, `SELECT scenario_id FROM scenario_runs WHERE id=$1`, runID).Scan(&scenarioID); err != nil || scenarioID == "" {
		return nil, false
	}
	return h.engine.Get(scenarioID)
}

// expMeta is the authoritative, server-resolved metadata for one expectation.
type expMeta struct {
	techniqueID    string
	domain         string
	provider       string
	confidence     string
	verification   string
	profileName    string
	profileVersion int
	found          bool
}

// expectationMeta resolves an expectation's metadata from the run's scenario, so
// audit fields (technique/domain/provider/profile) are trustworthy rather than
// client-supplied.
func (h *Handler) expectationMeta(sc *scenario.Scenario, expID string) expMeta {
	for _, step := range sc.Steps {
		exps, refs := h.engine.ResolveStepExpectations(step)
		for _, e := range exps {
			if e.ID != expID {
				continue
			}
			m := expMeta{
				techniqueID:  step.TechniqueID,
				domain:       scenario.ResolveDomain(e),
				provider:     e.Provider,
				confidence:   e.Confidence,
				verification: scenario.ResolveVerification(e),
				found:        true,
			}
			if len(refs) > 0 {
				m.profileName, m.profileVersion = refs[0].Profile, refs[0].Version
			}
			return m
		}
	}
	return expMeta{}
}

// ListRunVerifications is the verification queue for a run: every off-host
// (manual/API) expectation merged with its current stored verdict.
// Query params: domain (siem/identity/cloud/dlp/network), status.
// GET /api/scenarios/runs/{runId}/verifications
func (h *Handler) ListRunVerifications(w http.ResponseWriter, r *http.Request) {
	if h.verification == nil {
		jsonError(w, "verification store unavailable", http.StatusServiceUnavailable)
		return
	}
	runID := chi.URLParam(r, "runId")
	sc, ok := h.runScenario(r.Context(), runID)
	if !ok {
		jsonError(w, "run or scenario not found", http.StatusNotFound)
		return
	}
	current, err := h.verification.CurrentForRun(r.Context(), runID)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	counts, _ := h.verification.EvidenceCountsForRun(r.Context(), runID)

	domainFilter := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("domain")))
	statusFilter := strings.TrimSpace(r.URL.Query().Get("status"))

	items := []QueueItem{}
	seen := map[string]bool{}
	for _, step := range sc.Steps {
		exps, refs := h.engine.ResolveStepExpectations(step)
		var pName string
		var pVer int
		if len(refs) > 0 {
			pName, pVer = refs[0].Profile, refs[0].Version
		}
		for _, e := range exps {
			ver := scenario.ResolveVerification(e)
			if ver == scenario.VerificationAutomatic {
				continue // resolved on-host by the automatic engine
			}
			if seen[e.ID] {
				continue
			}
			seen[e.ID] = true
			domain := scenario.ResolveDomain(e)
			if domainFilter != "" && domain != domainFilter {
				continue
			}
			item := QueueItem{
				RunID: runID, ExpectationID: e.ID, TechniqueID: step.TechniqueID,
				Domain: domain, Provider: e.Provider, ProviderDisplay: providerDisplayName(e.Provider),
				Confidence: e.Confidence, Verification: ver,
				ProfileName: pName, ProfileVersion: pVer,
				Status: "Pending", WorkflowState: verification.StatePending,
			}
			if rec, ok := current[e.ID]; ok {
				vt := rec.VerifiedAt
				item.VerificationID = rec.ID
				item.Result = rec.Result
				item.WorkflowState = rec.WorkflowState
				item.Source = rec.Source
				item.VerifiedBy = rec.VerifiedBy
				item.VerifiedAt = &vt
				item.Note = rec.Note
				item.AlertID = rec.AlertID
				item.EvidenceCount = counts[rec.ID]
				item.Status = queueStatus(rec.WorkflowState, rec.Result)
			}
			if statusFilter != "" && !strings.EqualFold(item.Status, statusFilter) {
				continue
			}
			items = append(items, item)
		}
	}

	// Pending/NeedsReview first so the analyst sees outstanding work at the top.
	sort.SliceStable(items, func(i, j int) bool {
		return queueOrder(items[i].Status) < queueOrder(items[j].Status)
	})
	respond(w, map[string]any{"runId": runID, "items": items})
}

// CreateVerification records a new attestation (supersedes any prior). Server
// resolves audit metadata from the scenario. Requires CanVerify; setting an
// Approved/Rejected workflow additionally requires CanReview.
// POST /api/verifications
func (h *Handler) CreateVerification(w http.ResponseWriter, r *http.Request) {
	if h.verification == nil {
		jsonError(w, "verification store unavailable", http.StatusServiceUnavailable)
		return
	}
	var body struct {
		RunID         string `json:"runId"`
		ExpectationID string `json:"expectationId"`
		Result        string `json:"result"`
		WorkflowState string `json:"workflowState"`
		Note          string `json:"note"`
		AlertID       string `json:"alertId"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.RunID == "" || body.ExpectationID == "" {
		jsonError(w, "runId and expectationId are required", http.StatusBadRequest)
		return
	}
	if !validResult(body.Result) {
		jsonError(w, "result must be Detected, NotDetected or NotApplicable", http.StatusBadRequest)
		return
	}
	ws := body.WorkflowState
	if ws == "" {
		ws = verification.StateApproved
	}
	if !validWorkflow(ws) {
		jsonError(w, "invalid workflowState", http.StatusBadRequest)
		return
	}
	claims, _ := auth.ClaimsFrom(r.Context())
	if (ws == verification.StateApproved || ws == verification.StateRejected) &&
		!auth.HasPermission(claims.Role, auth.CanReview) {
		jsonError(w, "review permission required to approve or reject", http.StatusForbidden)
		return
	}

	sc, ok := h.runScenario(r.Context(), body.RunID)
	if !ok {
		jsonError(w, "run or scenario not found", http.StatusNotFound)
		return
	}
	meta := h.expectationMeta(sc, body.ExpectationID)
	if !meta.found {
		jsonError(w, "expectation not found in run scenario", http.StatusNotFound)
		return
	}

	rec, err := h.verification.Attest(r.Context(), verification.AttestInput{
		RunID: body.RunID, ExpectationID: body.ExpectationID,
		ProfileName: meta.profileName, ProfileVersion: meta.profileVersion,
		TechniqueID: meta.techniqueID, Domain: meta.domain, Provider: meta.provider,
		Result: body.Result, WorkflowState: ws, Source: verification.SourceManual,
		Note: body.Note, AlertID: body.AlertID, VerifiedBy: claims.UserID,
	})
	if errors.Is(err, verification.ErrConflict) {
		jsonError(w, "another analyst just updated this verification — reload and retry", http.StatusConflict)
		return
	}
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	h.auditLog(r, "Verification Created", "verification:"+rec.ID, map[string]any{
		"runId": body.RunID, "expectationId": body.ExpectationID,
		"result": body.Result, "workflowState": ws,
	}, "ok")
	respondStatus(w, rec, http.StatusCreated)
}

// GetVerificationHistory returns the full immutable attestation chain for one
// expectation in a run.
// GET /api/scenarios/runs/{runId}/verifications/{expectationId}/history
func (h *Handler) GetVerificationHistory(w http.ResponseWriter, r *http.Request) {
	if h.verification == nil {
		jsonError(w, "verification store unavailable", http.StatusServiceUnavailable)
		return
	}
	runID := chi.URLParam(r, "runId")
	expID := chi.URLParam(r, "expectationId")
	list, err := h.verification.History(r.Context(), runID, expID)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	respond(w, map[string]any{"runId": runID, "expectationId": expID, "history": list})
}

// UploadVerificationEvidence attaches one evidence file (hashed at receipt) to a
// verification. Independent of the attestation call so the UI can drag-drop
// multiple files. Requires CanUploadEvidence.
// POST /api/verifications/{id}/evidence
func (h *Handler) UploadVerificationEvidence(w http.ResponseWriter, r *http.Request) {
	if h.verification == nil {
		jsonError(w, "verification store unavailable", http.StatusServiceUnavailable)
		return
	}
	vid := chi.URLParam(r, "id")
	if _, ok, err := h.verification.Get(r.Context(), vid); err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	} else if !ok {
		jsonError(w, "verification not found", http.StatusNotFound)
		return
	}
	if err := r.ParseMultipartForm(maxEvidenceBytes); err != nil {
		jsonError(w, "invalid multipart form", http.StatusBadRequest)
		return
	}
	file, hdr, err := r.FormFile("file")
	if err != nil {
		jsonError(w, "file field is required", http.StatusBadRequest)
		return
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, maxEvidenceBytes+1))
	if err != nil {
		jsonError(w, "failed to read upload", http.StatusInternalServerError)
		return
	}
	if int64(len(data)) > maxEvidenceBytes {
		jsonError(w, "file exceeds 25 MiB limit", http.StatusRequestEntityTooLarge)
		return
	}
	claims, _ := auth.ClaimsFrom(r.Context())
	ev, err := h.verification.AddEvidence(r.Context(), verification.EvidenceInput{
		VerificationID:   vid,
		OriginalFilename: hdr.Filename,
		DisplayFilename:  strings.TrimSpace(r.FormValue("displayName")),
		MIME:             hdr.Header.Get("Content-Type"),
		UploadedBy:       claims.UserID,
		Bytes:            data,
	})
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	h.auditLog(r, "Evidence Uploaded", "verification:"+vid, map[string]any{
		"evidenceId": ev.ID, "filename": ev.OriginalFilename,
		"hashAlgorithm": ev.HashAlgorithm, "contentHash": ev.ContentHash, "size": ev.Size,
	}, "ok")
	respondStatus(w, ev, http.StatusCreated)
}

// ListVerificationEvidence lists non-deleted evidence for a verification.
// GET /api/verifications/{id}/evidence
func (h *Handler) ListVerificationEvidence(w http.ResponseWriter, r *http.Request) {
	if h.verification == nil {
		jsonError(w, "verification store unavailable", http.StatusServiceUnavailable)
		return
	}
	vid := chi.URLParam(r, "id")
	list, err := h.verification.ListEvidence(r.Context(), vid)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if list == nil {
		list = []verification.Evidence{}
	}
	respond(w, map[string]any{"verificationId": vid, "evidence": list})
}

// DownloadEvidence streams the stored bytes for one evidence item and records a
// download audit event. The SHA-256 is returned in a header so the client can
// re-verify integrity.
// GET /api/evidence/{id}/download
func (h *Handler) DownloadEvidence(w http.ResponseWriter, r *http.Request) {
	if h.verification == nil {
		jsonError(w, "verification store unavailable", http.StatusServiceUnavailable)
		return
	}
	id := chi.URLParam(r, "id")
	ev, ok, err := h.verification.EvidenceByID(r.Context(), id)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if !ok || ev.Deleted {
		jsonError(w, "evidence not found", http.StatusNotFound)
		return
	}
	data, err := h.verification.EvidenceBytes(r.Context(), ev)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	h.auditLog(r, "Evidence Downloaded", "evidence:"+id, map[string]any{
		"verificationId": ev.VerificationID, "filename": ev.OriginalFilename,
	}, "ok")
	mime := ev.MIME
	if mime == "" {
		mime = "application/octet-stream"
	}
	name := ev.DisplayFilename
	if name == "" {
		name = ev.OriginalFilename
	}
	w.Header().Set("Content-Type", mime)
	w.Header().Set("Content-Disposition", "attachment; filename=\""+sanitizeFilename(name)+"\"")
	w.Header().Set("X-Content-SHA256", ev.ContentHash)
	w.Header().Set("X-Hash-Algorithm", ev.HashAlgorithm)
	_, _ = w.Write(data)
}

// DeleteEvidence soft-deletes an evidence item (retained as audit material).
// Requires CanDeleteEvidence.
// DELETE /api/evidence/{id}
func (h *Handler) DeleteEvidence(w http.ResponseWriter, r *http.Request) {
	if h.verification == nil {
		jsonError(w, "verification store unavailable", http.StatusServiceUnavailable)
		return
	}
	id := chi.URLParam(r, "id")
	ev, ok, err := h.verification.EvidenceByID(r.Context(), id)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if !ok || ev.Deleted {
		jsonError(w, "evidence not found", http.StatusNotFound)
		return
	}
	claims, _ := auth.ClaimsFrom(r.Context())
	if err := h.verification.SoftDeleteEvidence(r.Context(), id, claims.UserID); err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	h.auditLog(r, "Evidence Deleted", "evidence:"+id, map[string]any{
		"verificationId": ev.VerificationID, "filename": ev.OriginalFilename,
	}, "ok")
	respond(w, map[string]any{"deleted": true})
}

// GetMyPermissions returns the caller's role and verification permissions so the
// UI can enable/disable controls.
// GET /api/me/permissions
func (h *Handler) GetMyPermissions(w http.ResponseWriter, r *http.Request) {
	claims, ok := auth.ClaimsFrom(r.Context())
	if !ok {
		jsonError(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	respond(w, map[string]any{"role": claims.Role, "permissions": auth.Permissions(claims.Role)})
}

// ── helpers ───────────────────────────────────────────────────────────────────

func validResult(s string) bool {
	switch s {
	case verification.ResultDetected, verification.ResultNotDetected, verification.ResultNotApplicable:
		return true
	}
	return false
}

func validWorkflow(s string) bool {
	switch s {
	case verification.StatePending, verification.StateNeedsReview, verification.StateApproved, verification.StateRejected:
		return true
	}
	return false
}

// queueStatus is the display status: the concrete result once Approved,
// otherwise the workflow state.
func queueStatus(workflow, result string) string {
	if workflow == verification.StateApproved {
		return result
	}
	return workflow
}

// queueOrder sorts outstanding work (Pending/NeedsReview) above completed rows.
func queueOrder(status string) int {
	switch status {
	case verification.StatePending:
		return 0
	case verification.StateNeedsReview:
		return 1
	case verification.StateRejected:
		return 2
	default: // Detected / NotDetected / NotApplicable
		return 3
	}
}

func providerDisplayName(key string) string {
	if p, ok := scenario.LookupProvider(key); ok && p.DisplayName != "" {
		return p.DisplayName
	}
	return key
}
