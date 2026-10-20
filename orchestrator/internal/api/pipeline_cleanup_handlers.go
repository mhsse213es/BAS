package api

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/audspect/bas/internal/auth"
	"github.com/audspect/bas/internal/db"
	"github.com/audspect/bas/internal/injectionapproval"
	"github.com/audspect/bas/internal/pipelinecheck"
)

// cleanupPayload is the exact set a cleanup approval covers: each eligible record's identity and the
// event time it was judged on, plus the run and index. Records are sorted by identity, so the same
// set always encodes to the same bytes and the same hash.
type cleanupPayload struct {
	RunID          string                        `json:"runId"`
	Index          string                        `json:"index"`
	RetentionHours int64                         `json:"retentionHours"`
	Records        []pipelinecheck.CleanupRecord `json:"records"`
}

func buildCleanupPayload(runID, index string, records []pipelinecheck.CleanupRecord) (string, string, error) {
	sorted := make([]pipelinecheck.CleanupRecord, len(records))
	copy(sorted, records)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].ID < sorted[j].ID })
	b, err := json.Marshal(cleanupPayload{
		RunID: runID, Index: index,
		RetentionHours: int64(pipelinecheck.RetentionWindow / time.Hour),
		Records:        sorted,
	})
	if err != nil {
		return "", "", err
	}
	sum := sha256.Sum256(b)
	return string(b), hex.EncodeToString(sum[:]), nil
}

// elasticFor loads a stored connector for cleanup. Only an enabled Elastic connector qualifies.
func (h *Handler) elasticFor(ctx context.Context, connectorID string) (pipelinecheck.ElasticConfig, *http.Client, error) {
	cfg, err := h.loadDetectionConnector(ctx, connectorID)
	if err != nil {
		return pipelinecheck.ElasticConfig{}, nil, fmt.Errorf("connector %s could not be loaded", connectorID)
	}
	if !cfg.Enabled {
		return pipelinecheck.ElasticConfig{}, nil, fmt.Errorf("connector %s is disabled", connectorID)
	}
	if cfg.Provider != "elastic" {
		return pipelinecheck.ElasticConfig{}, nil, fmt.Errorf("provider %q has no cleanup in this build", cfg.Provider)
	}
	client := &http.Client{Timeout: 30 * time.Second, Transport: pipelineTransport(cfg.InsecureTLS)}
	return pipelinecheck.ElasticConfig{BaseURL: cfg.BaseURL, APIKey: cfg.APIToken}, client, nil
}

// requestCleanupApproval previews the cleanup at server time and binds the eligible set, with each
// record's event time, into the approval. The caller names the run and the index; the server decides
// which records are eligible.
func (h *Handler) requestCleanupApproval(w http.ResponseWriter, r *http.Request, userID string, body createApprovalBody) {
	if len(body.Document) != 0 {
		jsonError(w, "a cleanup request takes no document", http.StatusBadRequest)
		return
	}
	if !pipelinecheck.ValidIndexName(body.Index) {
		jsonError(w, "index must be one explicit name", http.StatusBadRequest)
		return
	}
	if !pipelinecheck.ValidTestRunID(body.RunID) {
		jsonError(w, "runId must be the run identifier of the injection to clean up", http.StatusBadRequest)
		return
	}
	cfg, client, err := h.elasticFor(r.Context(), body.ConnectorID)
	if err != nil {
		jsonError(w, err.Error(), http.StatusBadRequest)
		return
	}
	now := time.Now().UTC()
	p := pipelinecheck.PreviewElasticCleanupAt(r.Context(), client, cfg, body.Index, body.RunID, now)
	if p.Status != "previewed" {
		jsonError(w, "cleanup cannot be previewed: "+p.Reason, http.StatusConflict)
		return
	}
	payloadJSON, hash, err := buildCleanupPayload(body.RunID, body.Index, p.Records)
	if err != nil {
		jsonError(w, "could not encode the candidate set", http.StatusInternalServerError)
		return
	}
	scope := injectionapproval.Scope{
		Kind: injectionapproval.KindCleanup, ConnectorID: body.ConnectorID, Target: body.Index,
		PayloadHash: hash, TestScope: "test run " + body.RunID,
		ExpectedChange: fmt.Sprintf("%d tagged test records older than %d hours deleted", len(p.Records), int64(pipelinecheck.RetentionWindow/time.Hour)),
		Payload:        payloadJSON,
	}
	id, err := newApprovalID()
	if err != nil {
		jsonError(w, "could not create an approval id", http.StatusInternalServerError)
		return
	}
	store := db.KillChainStore{Pool: h.db}
	if err := store.RequestApproval(r.Context(), id, userID, scope, now); err != nil {
		jsonError(w, "could not record the request", http.StatusInternalServerError)
		return
	}
	h.auditLog(r, "pipeline.cleanup.requested", id, map[string]any{
		"runId": body.RunID, "target": body.Index, "eligible": len(p.Records),
		"heldByRetention": len(p.RetentionHeld), "scopeHash": scope.Hash(),
	}, "ok")
	respond(w, map[string]any{
		"approvalId": id, "runId": body.RunID, "records": p.Records,
		"retentionHeld": p.RetentionHeld, "retained": p.Retained,
		"scopeHash": scope.Hash(), "status": "pending",
	})
}

// ExecuteCleanupApproval deletes the approved set. At execution it re-runs the preview at server time
// and compares the eligible records, identities and event times with what was approved. If they differ,
// it refuses and does not consume the approval. Otherwise it consumes the approval, deletes only those
// records with the retention cutoff in the delete query, and records the outcome. A partial or failed
// deletion is recorded as failed. Retrying needs a new approval.
// POST /api/pipeline-approvals/{id}/execute-cleanup
func (h *Handler) ExecuteCleanupApproval(w http.ResponseWriter, r *http.Request) {
	claims, ok := auth.ClaimsFrom(r.Context())
	if !ok {
		jsonError(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	id := chi.URLParam(r, "id")
	store := db.KillChainStore{Pool: h.db}
	v, err := store.GetApproval(r.Context(), id)
	if err != nil {
		writeApprovalError(w, err)
		return
	}
	if v.Kind != string(injectionapproval.KindCleanup) {
		jsonError(w, "not a cleanup approval", http.StatusBadRequest)
		return
	}
	if !requireKindPermission(w, r, v.Kind) {
		return
	}
	var pl cleanupPayload
	if err := json.Unmarshal([]byte(v.Scope.Payload), &pl); err != nil {
		jsonError(w, "stored approval payload is unreadable", http.StatusInternalServerError)
		return
	}
	cfg, client, err := h.elasticFor(r.Context(), v.Scope.ConnectorID)
	if err != nil {
		jsonError(w, err.Error(), http.StatusConflict)
		return
	}
	now := time.Now().UTC()
	p := pipelinecheck.PreviewElasticCleanupAt(r.Context(), client, cfg, pl.Index, pl.RunID, now)
	if p.Status != "previewed" {
		jsonError(w, "candidates cannot be verified now; nothing was deleted: "+p.Reason, http.StatusConflict)
		return
	}
	_, hash, err := buildCleanupPayload(pl.RunID, pl.Index, p.Records)
	if err != nil || hash != v.Scope.PayloadHash {
		h.auditLog(r, "pipeline.cleanup.refused", id, map[string]any{"reason": "eligible set or event times changed"}, "refused")
		jsonError(w, "the eligible records or their event times changed since approval; nothing was deleted; request a new approval", http.StatusConflict)
		return
	}
	if err := store.ConsumeApproval(r.Context(), id, claims.UserID, v.Scope, h.approvalClassification(), now); err != nil {
		writeApprovalError(w, err)
		return
	}
	ids := make([]string, 0, len(p.Records))
	for _, rec := range p.Records {
		ids = append(ids, rec.ID)
	}
	cutoff := now.Add(-pipelinecheck.RetentionWindow)
	res, derr := pipelinecheck.DeleteElasticCandidates(r.Context(), client, cfg, pl.Index, pl.RunID, ids, cutoff)
	reason := res.Reason
	outcome := "executed"
	if derr != nil {
		reason = derr.Error()
	}
	if derr != nil || res.Status != "deleted" {
		outcome = "failed"
	}
	if err := store.RecordExecutionOutcome(r.Context(), id, claims.UserID, outcome, time.Now().UTC()); err != nil {
		jsonError(w, "the cleanup ran but its outcome could not be recorded; check the audit trail before retrying: "+err.Error(), http.StatusInternalServerError)
		return
	}
	h.auditLog(r, "pipeline.cleanup.executed", id, map[string]any{
		"runId": pl.RunID, "target": pl.Index, "requested": res.Requested, "deleted": res.Deleted,
		"conflicts": res.Conflicts, "status": res.Status,
	}, outcome)
	respond(w, map[string]any{
		"approvalId": id, "status": res.Status, "reason": reason, "requested": res.Requested,
		"deleted": res.Deleted, "conflicts": res.Conflicts, "outcome": outcome, "retained": p.Retained,
		"retentionHeld": p.RetentionHeld,
	})
}
