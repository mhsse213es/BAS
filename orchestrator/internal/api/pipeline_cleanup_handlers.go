package api

import (
	"context"
	"crypto/rand"
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

// newExecutionID identifies one execution attempt in the audit trail. It is new for every attempt,
// including attempts that are refused.
func newExecutionID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return "exec-" + hex.EncodeToString(b[:]), nil
}

// auditDurable writes one audit record synchronously and returns only after it is committed. Cleanup
// uses this, not the fire-and-forget audit helpers, because a deletion must never happen without a
// committed start record.
func (h *Handler) auditDurable(ctx context.Context, actorID, action, resource string, detail map[string]any, outcome string) error {
	b, err := json.Marshal(detail)
	if err != nil {
		return err
	}
	_, err = h.db.Exec(ctx,
		`INSERT INTO audit_logs (actor_id, action, resource, detail, ip, outcome) VALUES ($1,$2,$3,$4,'',$5)`,
		actorID, action, resource, b, outcome)
	return err
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

// ExecuteCleanupApproval deletes the approved set. Only the user who approved this request may execute
// it; for a customer deployment that is never the requester. The order is fixed:
//
//  1. Identity, permission, approval state and expiry are checked. Any failure refuses, spends nothing.
//  2. The eligible set is previewed at server time. If it differs from what was approved, refuse.
//  3. A durable cleanup.started audit record is committed. If it cannot be, nothing is deleted.
//  4. The approval is consumed. It is single-use and is checked again under lock.
//  5. Only the approved records are deleted, with the retention cutoff in the delete query.
//  6. A durable cleanup.finished audit record is committed with the counts.
//
// If step 6 cannot be committed after a deletion ran, the response is unresolved. The start record
// stays, and nothing is replayed automatically.
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
	executionID, err := newExecutionID()
	if err != nil {
		jsonError(w, "could not create an execution id", http.StatusInternalServerError)
		return
	}
	ctx := context.WithoutCancel(r.Context())

	// Step 1. Only the approver may execute. For a customer this is never the requester. For a lab,
	// self-approval makes the requester the approver, so the same check covers both.
	refuse := func(status int, msg, reason string) {
		_ = h.auditDurable(ctx, claims.UserID, "pipeline.cleanup.refused", id, map[string]any{
			"executionId": executionID, "reason": reason,
		}, "refused")
		jsonError(w, msg, status)
	}
	if v.ApprovedBy == "" {
		refuse(http.StatusConflict, "the approval has not been granted", "not approved")
		return
	}
	if claims.UserID != v.ApprovedBy {
		refuse(http.StatusForbidden, "only the user who approved this cleanup may execute it", "executor is not the approver")
		return
	}
	now := time.Now().UTC()
	if !v.ConsumedAt.IsZero() {
		refuse(http.StatusConflict, "the approval has already been used", "already consumed")
		return
	}
	if now.After(v.ExpiresAt) {
		refuse(http.StatusConflict, "the approval has expired; request a new one", "expired")
		return
	}
	var pl cleanupPayload
	if err := json.Unmarshal([]byte(v.Scope.Payload), &pl); err != nil {
		refuse(http.StatusInternalServerError, "stored approval payload is unreadable", "payload unreadable")
		return
	}
	cfg, client, err := h.elasticFor(ctx, v.Scope.ConnectorID)
	if err != nil {
		refuse(http.StatusConflict, err.Error(), err.Error())
		return
	}

	// Step 2. Revalidate the eligible set immediately before anything is written.
	p := pipelinecheck.PreviewElasticCleanupAt(ctx, client, cfg, pl.Index, pl.RunID, now)
	if p.Status != "previewed" {
		refuse(http.StatusConflict, "candidates cannot be verified now; nothing was deleted: "+p.Reason, "preview failed: "+p.Reason)
		return
	}
	_, hash, err := buildCleanupPayload(pl.RunID, pl.Index, p.Records)
	if err != nil || hash != v.Scope.PayloadHash {
		refuse(http.StatusConflict, "the eligible records or their event times changed since approval; nothing was deleted; request a new approval",
			"eligible set or event times changed")
		return
	}

	// Step 3. The start record must be committed before anything is deleted.
	started := map[string]any{
		"executionId": executionID, "approvalId": id, "candidateSetHash": hash,
		"runId": pl.RunID, "target": pl.Index, "eligible": len(p.Records),
		"cutoff":   now.Add(-pipelinecheck.RetentionWindow).Format(time.RFC3339Nano),
		"executor": claims.UserID, "approver": v.ApprovedBy,
	}
	if err := h.auditDurable(ctx, claims.UserID, "pipeline.cleanup.started", id, started, "started"); err != nil {
		jsonError(w, "could not record the start of the cleanup; nothing was deleted", http.StatusServiceUnavailable)
		return
	}

	// Step 4. Consume. A failure here still leaves a committed start record, so it is closed with a
	// not-run record. Nothing was deleted.
	if err := store.ConsumeApproval(ctx, id, claims.UserID, v.Scope, h.approvalClassification(), now); err != nil {
		_ = h.auditDurable(ctx, claims.UserID, "pipeline.cleanup.not_run", id, map[string]any{
			"executionId": executionID, "reason": err.Error(),
		}, "not_run")
		writeApprovalError(w, err)
		return
	}

	// Step 5. Delete only the approved records. The cutoff is repeated in the delete query.
	ids := make([]string, 0, len(p.Records))
	for _, rec := range p.Records {
		ids = append(ids, rec.ID)
	}
	cutoff := now.Add(-pipelinecheck.RetentionWindow)
	res, derr := pipelinecheck.DeleteElasticCandidates(ctx, client, cfg, pl.Index, pl.RunID, ids, cutoff)
	outcome := "executed"
	reason := res.Reason
	if derr != nil {
		reason = derr.Error()
	}
	if derr != nil || res.Status != "deleted" {
		outcome = "failed"
	}
	notDeleted := res.Requested - int(res.Deleted)

	// Step 6. The finish record carries the counts. If it cannot be committed, the deletion may have
	// run, so the response is unresolved and nothing is retried.
	finished := map[string]any{
		"executionId": executionID, "approvalId": id, "candidateSetHash": hash,
		"requested": res.Requested, "deleted": res.Deleted, "notDeleted": notDeleted,
		"versionConflicts": res.Conflicts, "status": res.Status, "reason": reason,
	}
	if err := h.auditDurable(ctx, claims.UserID, "pipeline.cleanup.finished", id, finished, outcome); err != nil {
		jsonError(w, fmt.Sprintf("unresolved: execution %s ran but its finish record could not be committed (%v); the start record stands; no deletion will be retried automatically", executionID, err),
			http.StatusInternalServerError)
		return
	}
	if err := store.RecordExecutionOutcome(ctx, id, claims.UserID, outcome, time.Now().UTC()); err != nil {
		jsonError(w, fmt.Sprintf("execution %s finished and is audited, but the approval outcome could not be recorded (%v)", executionID, err),
			http.StatusInternalServerError)
		return
	}
	respond(w, map[string]any{
		"executionId": executionID, "approvalId": id, "status": res.Status, "reason": reason,
		"requested": res.Requested, "deleted": res.Deleted, "notDeleted": notDeleted,
		"versionConflicts": res.Conflicts, "outcome": outcome,
	})
}
