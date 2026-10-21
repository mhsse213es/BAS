package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/audspect/bas/internal/auth"
	"github.com/audspect/bas/internal/db"
	"github.com/audspect/bas/internal/injectionapproval"
	"github.com/audspect/bas/internal/pipelinecheck"
)

// ExecuteInjectionApproval writes the approved test record. It is the only way a record is written.
// Only the user who approved this request may execute it. The order mirrors cleanup:
//
//  1. Identity, permission, approval state and expiry are checked. Any failure refuses and writes nothing.
//  2. The stored payload is checked against its hash. A mismatch refuses.
//  3. A durable injection.started record is committed. If it cannot be, nothing is written.
//  4. The approval is consumed. It is single-use and is checked again under lock.
//  5. The record is written with a create-only request. An unconfirmed write is recorded as failed.
//  6. A durable injection.finished record is committed. If it cannot be, the response is unresolved.
//
// POST /api/pipeline-approvals/{id}/execute-injection
func (h *Handler) ExecuteInjectionApproval(w http.ResponseWriter, r *http.Request) {
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
	if v.Kind != string(injectionapproval.KindInjection) {
		jsonError(w, "not an injection approval", http.StatusBadRequest)
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

	refuse := func(status int, msg, reason string) {
		_ = h.auditDurable(ctx, claims.UserID, "pipeline.injection.refused", id, map[string]any{
			"executionId": executionID, "reason": reason,
		}, "refused")
		jsonError(w, msg, status)
	}
	if v.ApprovedBy == "" {
		refuse(http.StatusConflict, "the approval has not been granted", "not approved")
		return
	}
	if claims.UserID != v.ApprovedBy {
		refuse(http.StatusForbidden, "only the user who approved this injection may execute it", "executor is not the approver")
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

	// The stored payload is the tagged document that was approved. Re-hash it before anything is written.
	var doc map[string]any
	if err := json.Unmarshal([]byte(v.Scope.Payload), &doc); err != nil || doc == nil {
		refuse(http.StatusInternalServerError, "stored approval payload is unreadable", "payload unreadable")
		return
	}
	hash, err := pipelinecheck.PayloadHash(doc)
	if err != nil || hash != v.Scope.PayloadHash {
		refuse(http.StatusConflict, "the stored payload does not match its approved hash; nothing was written", "payload hash mismatch")
		return
	}
	audspect, _ := doc["audspect"].(map[string]any)
	runID, _ := audspect["test_run"].(string)
	if !pipelinecheck.ValidTestRunID(runID) {
		refuse(http.StatusConflict, "the stored payload has no valid run identifier; nothing was written", "run identifier invalid")
		return
	}
	cfg, client, err := h.elasticFor(ctx, v.Scope.ConnectorID)
	if err != nil {
		refuse(http.StatusConflict, err.Error(), err.Error())
		return
	}
	inj := pipelinecheck.ElasticInjector{Client: client, Cfg: cfg}

	// Step 3. The start record must be committed before anything is written.
	started := map[string]any{
		"executionId": executionID, "approvalId": id, "payloadHash": hash,
		"runId": runID, "target": v.Scope.Target, "executor": claims.UserID, "approver": v.ApprovedBy,
	}
	if err := h.auditDurable(ctx, claims.UserID, "pipeline.injection.started", id, started, "started"); err != nil {
		jsonError(w, "could not record the start of the injection; nothing was written", http.StatusServiceUnavailable)
		return
	}

	// Step 4. Consume. A failure here is closed with a not-run record. Nothing was written.
	if err := store.ConsumeApproval(ctx, id, claims.UserID, v.Scope, h.approvalClassification(), now); err != nil {
		_ = h.auditDurable(ctx, claims.UserID, "pipeline.injection.not_run", id, map[string]any{
			"executionId": executionID, "reason": err.Error(),
		}, "not_run")
		writeApprovalError(w, err)
		return
	}

	// Step 5. One create-only write. Any failure, including an unconfirmed one, is a failed outcome.
	out, werr := inj.Inject(ctx, pipelinecheck.InjectionRequest{RunID: runID, Index: v.Scope.Target, Document: doc})
	outcome, status, reason := "executed", "EXECUTED", out.Reason
	if werr != nil || out.Status != "EXECUTED" {
		outcome, status = "failed", "ERROR"
		reason = fmt.Sprint(werr)
		if werr == nil {
			reason = out.Reason
		}
	}

	// Step 6. The finish record is committed before the approval outcome is written.
	finished := map[string]any{
		"executionId": executionID, "approvalId": id, "payloadHash": hash, "runId": runID,
		"target": v.Scope.Target, "status": status, "reason": reason,
	}
	if err := h.auditDurable(ctx, claims.UserID, "pipeline.injection.finished", id, finished, outcome); err != nil {
		jsonError(w, fmt.Sprintf("unresolved: execution %s wrote its record but the finish record could not be committed (%v); no write will be retried automatically", executionID, err),
			http.StatusInternalServerError)
		return
	}
	if err := store.RecordExecutionOutcome(ctx, id, claims.UserID, outcome, time.Now().UTC()); err != nil {
		jsonError(w, fmt.Sprintf("execution %s is audited, but the approval outcome could not be recorded (%v)", executionID, err), http.StatusInternalServerError)
		return
	}
	respond(w, map[string]any{
		"executionId": executionID, "approvalId": id, "status": status, "reason": reason, "outcome": outcome,
	})
}
