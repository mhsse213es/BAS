package api

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/audspect/bas/internal/auth"
	"github.com/audspect/bas/internal/db"
	"github.com/audspect/bas/internal/injectionapproval"
	"github.com/audspect/bas/internal/pipelinecheck"
)

// WithDeploymentClass sets the deployment class from trusted startup configuration. It is the
// only place the class is set. No request, campaign parameter or caller can change it.
func (h *Handler) WithDeploymentClass(c injectionapproval.Classification) *Handler {
	h.approvalClass = c
	return h
}

// approvalClassification returns the deployment class. A handler that was never configured is
// customer, the stricter class.
func (h *Handler) approvalClassification() injectionapproval.Classification {
	if h.approvalClass == "" {
		return injectionapproval.Customer
	}
	return h.approvalClass
}

// kindPermission is the permission an approval of this kind needs. It is checked on the server
// for every decision, not only at the route.
func kindPermission(kind string) (auth.Permission, bool) {
	switch kind {
	case string(injectionapproval.KindInjection):
		return auth.CanApprovePipelineInjection, true
	case string(injectionapproval.KindCleanup):
		return auth.CanApprovePipelineCleanup, true
	}
	return "", false
}

func requireKindPermission(w http.ResponseWriter, r *http.Request, kind string) bool {
	perm, ok := kindPermission(kind)
	if !ok {
		jsonError(w, "unknown approval kind", http.StatusBadRequest)
		return false
	}
	claims, ok := auth.ClaimsFrom(r.Context())
	if !ok || !auth.HasPermission(claims.Role, perm) {
		jsonError(w, "forbidden", http.StatusForbidden)
		return false
	}
	return true
}

func newApprovalID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return "ap-" + hex.EncodeToString(b[:]), nil
}

type createApprovalBody struct {
	Kind           string          `json:"kind"`
	CampaignID     string          `json:"campaignId"`
	StageKey       string          `json:"stageKey"`
	ConnectorID    string          `json:"connectorId"`
	Index          string          `json:"index"`
	Document       json.RawMessage `json:"document"`
	TestScope      string          `json:"testScope"`
	ExpectedChange string          `json:"expectedChange"`
}

// CreatePipelineApproval requests an injection approval. The run identifier is generated here,
// the document is tagged here, and the scope is built here from those, so the caller cannot
// supply a run identifier or a payload hash that differs from what is written.
// POST /api/pipeline-approvals
func (h *Handler) CreatePipelineApproval(w http.ResponseWriter, r *http.Request) {
	claims, ok := auth.ClaimsFrom(r.Context())
	if !ok {
		jsonError(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	var body createApprovalBody
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&body); err != nil {
		jsonError(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if body.Kind != string(injectionapproval.KindInjection) {
		jsonError(w, "only injection approvals can be requested; cleanup approvals are not available yet", http.StatusBadRequest)
		return
	}
	if !pipelinecheck.ValidIndexName(body.Index) {
		jsonError(w, "index must be one explicit name", http.StatusBadRequest)
		return
	}
	var doc map[string]any
	if err := json.Unmarshal(body.Document, &doc); err != nil || doc == nil {
		jsonError(w, "document must be a JSON object", http.StatusBadRequest)
		return
	}
	runID, err := pipelinecheck.NewTestRunID()
	if err != nil {
		jsonError(w, "could not create a run identifier", http.StatusInternalServerError)
		return
	}
	tagged, err := pipelinecheck.TagDocument(doc, runID)
	if err != nil {
		jsonError(w, err.Error(), http.StatusBadRequest)
		return
	}
	payloadJSON, err := json.Marshal(tagged)
	if err != nil {
		jsonError(w, "could not encode the document", http.StatusBadRequest)
		return
	}
	hash, err := pipelinecheck.PayloadHash(tagged)
	if err != nil {
		jsonError(w, "could not hash the document", http.StatusBadRequest)
		return
	}
	scope := injectionapproval.Scope{
		Kind: injectionapproval.KindInjection, CampaignID: body.CampaignID, StageKey: body.StageKey,
		ConnectorID: body.ConnectorID, Target: body.Index, PayloadHash: hash,
		TestScope: body.TestScope, ExpectedChange: body.ExpectedChange, Payload: string(payloadJSON),
	}
	id, err := newApprovalID()
	if err != nil {
		jsonError(w, "could not create an approval id", http.StatusInternalServerError)
		return
	}
	store := db.KillChainStore{Pool: h.db}
	if err := store.RequestApproval(r.Context(), id, claims.UserID, scope, time.Now()); err != nil {
		jsonError(w, "could not record the request", http.StatusInternalServerError)
		return
	}
	h.auditLog(r, "pipeline.approval.requested", id, map[string]any{
		"kind": body.Kind, "runId": runID, "target": body.Index, "scopeHash": scope.Hash(),
	}, "ok")
	respond(w, map[string]any{"approvalId": id, "runId": runID, "scopeHash": scope.Hash(), "status": "pending"})
}

// GetPipelineApproval returns one approval, its scope and its history. Approvers read it to see
// exactly what they would approve.
// GET /api/pipeline-approvals/{id}
func (h *Handler) GetPipelineApproval(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	store := db.KillChainStore{Pool: h.db}
	v, err := store.GetApproval(r.Context(), id)
	if errors.Is(err, db.ErrApprovalNotFound) {
		jsonError(w, "approval not found", http.StatusNotFound)
		return
	}
	if err != nil {
		jsonError(w, "could not read the approval", http.StatusInternalServerError)
		return
	}
	if !requireKindPermission(w, r, v.Kind) {
		return
	}
	respond(w, approvalResponse(v))
}

// ApprovePipelineApproval approves a pending request. The approver is the authenticated user.
// The deployment class is the startup value. Self-approval follows the classification rule.
// POST /api/pipeline-approvals/{id}/approve
func (h *Handler) ApprovePipelineApproval(w http.ResponseWriter, r *http.Request) {
	claims, ok := auth.ClaimsFrom(r.Context())
	if !ok {
		jsonError(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	id := chi.URLParam(r, "id")
	store := db.KillChainStore{Pool: h.db}
	v, err := store.GetApproval(r.Context(), id)
	if errors.Is(err, db.ErrApprovalNotFound) {
		jsonError(w, "approval not found", http.StatusNotFound)
		return
	}
	if err != nil {
		jsonError(w, "could not read the approval", http.StatusInternalServerError)
		return
	}
	if !requireKindPermission(w, r, v.Kind) {
		return
	}
	err = store.ApproveRequest(r.Context(), id, claims.UserID, h.approvalClassification(), time.Now())
	h.auditLog(r, "pipeline.approval.decided", id, map[string]any{"decision": "approve"}, outcomeOf(err))
	if err != nil {
		writeApprovalError(w, err)
		return
	}
	v, _ = store.GetApproval(r.Context(), id)
	respond(w, approvalResponse(v))
}

// RefusePipelineApproval refuses a pending request. Only a request that has not been decided can be
// refused; an approved request is not revoked by refusal.
// POST /api/pipeline-approvals/{id}/refuse
func (h *Handler) RefusePipelineApproval(w http.ResponseWriter, r *http.Request) {
	claims, ok := auth.ClaimsFrom(r.Context())
	if !ok {
		jsonError(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	id := chi.URLParam(r, "id")
	var body struct {
		Reason string `json:"reason"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&body); err != nil || body.Reason == "" {
		jsonError(w, "a reason is required", http.StatusBadRequest)
		return
	}
	store := db.KillChainStore{Pool: h.db}
	v, err := store.GetApproval(r.Context(), id)
	if errors.Is(err, db.ErrApprovalNotFound) {
		jsonError(w, "approval not found", http.StatusNotFound)
		return
	}
	if err != nil {
		jsonError(w, "could not read the approval", http.StatusInternalServerError)
		return
	}
	if !requireKindPermission(w, r, v.Kind) {
		return
	}
	err = store.RefuseApproval(r.Context(), id, claims.UserID, body.Reason, time.Now())
	h.auditLog(r, "pipeline.approval.decided", id, map[string]any{"decision": "refuse"}, outcomeOf(err))
	if err != nil {
		writeApprovalError(w, err)
		return
	}
	respond(w, map[string]any{"approvalId": id, "status": "refused"})
}

func outcomeOf(err error) string {
	if err != nil {
		return "refused"
	}
	return "ok"
}

func writeApprovalError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, db.ErrApprovalNotFound):
		jsonError(w, "approval not found", http.StatusNotFound)
	case errors.Is(err, db.ErrApprovalDecided), errors.Is(err, injectionapproval.ErrConsumed):
		jsonError(w, "approval is already decided", http.StatusConflict)
	case errors.Is(err, injectionapproval.ErrSelfApproval):
		jsonError(w, err.Error(), http.StatusForbidden)
	case errors.Is(err, injectionapproval.ErrNotApproved):
		jsonError(w, err.Error(), http.StatusBadRequest)
	default:
		jsonError(w, "could not record the decision", http.StatusInternalServerError)
	}
}

func approvalResponse(v db.ApprovalView) map[string]any {
	events := make([]map[string]any, 0, len(v.History))
	for _, e := range v.History {
		events = append(events, map[string]any{"event": e.Event, "actor": e.Actor, "at": e.At, "detail": e.Detail})
	}
	return map[string]any{
		"approvalId": v.ID, "kind": v.Kind, "scope": v.Scope, "scopeHash": v.ScopeHash,
		"requestedBy": v.RequestedBy, "approvedBy": v.ApprovedBy, "approvedAt": v.ApprovedAt,
		"expiresAt": v.ExpiresAt, "consumedAt": v.ConsumedAt, "consumedBy": v.ConsumedBy,
		"history": events,
	}
}
