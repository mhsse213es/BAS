package api

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/audspect/bas/internal/auth"
	"github.com/audspect/bas/internal/db"
	"github.com/audspect/bas/internal/injectionapproval"
	"github.com/audspect/bas/internal/pipelinecheck"
)

// unresolvedCleanup is a cleanup execution that started and has no closing record. Its deletion may or
// may not have run. Nothing here deletes anything or retries it.
type unresolvedCleanup struct {
	ExecutionID      string    `json:"executionId"`
	ApprovalID       string    `json:"approvalId"`
	CandidateSetHash string    `json:"candidateSetHash"`
	Target           string    `json:"target"`
	RunID            string    `json:"runId"`
	Executor         string    `json:"executor"`
	StartedAt        time.Time `json:"startedAt"`
}

// closingActions are the audit actions that close an execution. A started execution with none of them
// is unresolved.
const closingActions = `'pipeline.cleanup.finished','pipeline.cleanup.not_run','pipeline.cleanup.reconciled'`

// ListUnresolvedCleanups lists cleanup executions that started and were never closed.
// GET /api/pipeline-approvals/unresolved-cleanups
func (h *Handler) ListUnresolvedCleanups(w http.ResponseWriter, r *http.Request) {
	rows, err := h.db.Query(r.Context(), `
		SELECT s.detail->>'executionId', s.detail->>'approvalId', s.detail->>'candidateSetHash',
		       s.detail->>'target', s.detail->>'runId', s.detail->>'executor', s.ts
		FROM audit_logs s
		WHERE s.action = 'pipeline.cleanup.started'
		  AND NOT EXISTS (
		      SELECT 1 FROM audit_logs f
		      WHERE f.action IN (`+closingActions+`)
		        AND f.detail->>'executionId' = s.detail->>'executionId')
		ORDER BY s.ts`)
	if err != nil {
		jsonError(w, "could not list unresolved executions", http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	out := []unresolvedCleanup{}
	for rows.Next() {
		var u unresolvedCleanup
		var execID, approvalID, hash, target, runID, executor *string
		if err := rows.Scan(&execID, &approvalID, &hash, &target, &runID, &executor, &u.StartedAt); err != nil {
			jsonError(w, "could not read unresolved executions", http.StatusInternalServerError)
			return
		}
		u.ExecutionID, u.ApprovalID, u.CandidateSetHash = deref(execID), deref(approvalID), deref(hash)
		u.Target, u.RunID, u.Executor = deref(target), deref(runID), deref(executor)
		out = append(out, u)
	}
	respond(w, map[string]any{"executions": out})
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// reconcileBody is the human resolution of an unresolved execution.
type reconcileBody struct {
	// Resolution is "deleted" (the records are gone) or "not_deleted" (they are still there).
	Resolution string `json:"resolution"`
	// Note says how the operator established it, for the audit trail. It is required.
	Note string `json:"note"`
}

// ReconcileCleanupExecution closes an unresolved execution with a recorded human resolution. It writes
// one durable audit record and changes nothing else. It deletes nothing, and it never reopens the
// approval, so the approval stays spent.
// POST /api/pipeline-approvals/unresolved-cleanups/{executionId}/reconcile
func (h *Handler) ReconcileCleanupExecution(w http.ResponseWriter, r *http.Request) {
	claims, ok := auth.ClaimsFrom(r.Context())
	if !ok {
		jsonError(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	execID := chi.URLParam(r, "executionId")
	var body reconcileBody
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&body); err != nil {
		jsonError(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if body.Resolution != "deleted" && body.Resolution != "not_deleted" {
		jsonError(w, `resolution must be "deleted" or "not_deleted"`, http.StatusBadRequest)
		return
	}
	body.Note = strings.TrimSpace(body.Note)
	if body.Note == "" {
		jsonError(w, "a note describing how the outcome was established is required", http.StatusBadRequest)
		return
	}
	ctx := context.WithoutCancel(r.Context())
	approvalID, err := h.unresolvedApprovalFor(ctx, execID)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if approvalID == "" {
		jsonError(w, "no unresolved execution with that id", http.StatusNotFound)
		return
	}
	if err := h.auditDurable(ctx, claims.UserID, "pipeline.cleanup.reconciled", approvalID, map[string]any{
		"executionId": execID, "resolution": body.Resolution, "note": body.Note, "reconciler": claims.UserID,
	}, "reconciled"); err != nil {
		jsonError(w, "the resolution could not be recorded; the execution remains unresolved", http.StatusInternalServerError)
		return
	}
	respond(w, map[string]any{"executionId": execID, "approvalId": approvalID, "resolution": body.Resolution, "reconciledAt": time.Now().UTC()})
}

// unresolvedApprovalFor returns the approval of an execution that is still unresolved, or "" when the
// execution is unknown or already closed.
func (h *Handler) unresolvedApprovalFor(ctx context.Context, execID string) (string, error) {
	var approvalID *string
	err := h.db.QueryRow(ctx, `
		SELECT s.detail->>'approvalId'
		FROM audit_logs s
		WHERE s.action = 'pipeline.cleanup.started'
		  AND s.detail->>'executionId' = $1
		  AND NOT EXISTS (
		      SELECT 1 FROM audit_logs f
		      WHERE f.action IN (`+closingActions+`)
		        AND f.detail->>'executionId' = s.detail->>'executionId')
		LIMIT 1`, execID).Scan(&approvalID)
	if err != nil {
		if strings.Contains(err.Error(), "no rows") {
			return "", nil
		}
		return "", err
	}
	return deref(approvalID), nil
}

// CheckCleanupExecution reports which of an unresolved execution's approved records are still in the
// index. It reads only, and suggests a resolution from the count. The person still records the
// resolution through the reconcile endpoint.
// GET /api/pipeline-approvals/unresolved-cleanups/{executionId}/check
func (h *Handler) CheckCleanupExecution(w http.ResponseWriter, r *http.Request) {
	execID := chi.URLParam(r, "executionId")
	ctx := context.WithoutCancel(r.Context())
	approvalID, err := h.unresolvedApprovalFor(ctx, execID)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if approvalID == "" {
		jsonError(w, "no unresolved execution with that id", http.StatusNotFound)
		return
	}
	v, err := db.KillChainStore{Pool: h.db}.GetApproval(ctx, approvalID)
	if err != nil {
		writeApprovalError(w, err)
		return
	}
	if v.Kind != string(injectionapproval.KindCleanup) {
		jsonError(w, "only cleanup executions can be checked", http.StatusBadRequest)
		return
	}
	var pl cleanupPayload
	if err := json.Unmarshal([]byte(v.Scope.Payload), &pl); err != nil {
		jsonError(w, "stored approval payload is unreadable", http.StatusInternalServerError)
		return
	}
	ids := make([]string, 0, len(pl.Records))
	for _, rec := range pl.Records {
		ids = append(ids, rec.ID)
	}
	cfg, client, err := h.elasticFor(ctx, v.Scope.ConnectorID)
	if err != nil {
		respond(w, map[string]any{"executionId": execID, "approvalId": approvalID, "status": "error", "reason": err.Error()})
		return
	}
	res := pipelinecheck.CheckRemainingElastic(ctx, client, cfg, pl.Index, pl.RunID, ids)
	respond(w, map[string]any{
		"executionId": execID, "approvalId": approvalID, "status": res.Status, "reason": res.Reason,
		"requested": res.Requested, "remaining": res.Remaining, "suggested": res.Suggested,
	})
}
