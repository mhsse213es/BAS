package api

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	apibasjobs "github.com/audspect/bas/internal/apibas/jobs"
	"github.com/audspect/bas/internal/db"
	"github.com/audspect/bas/internal/notifications"
)

// Production approval records. These endpoints only create, approve and show approvals. Production execution is still refused by
// the job service in this release, so an approved record does not make anything run; it is the reviewed record that production
// execution will require (see jobs.CheckApproval).

type apibasApprovalBody struct {
	TargetID    string   `json:"target_id"`
	Fixture     string   `json:"fixture"`
	ScenarioIDs []string `json:"scenario_ids"`
}

// approvalStatus is the single place that turns an approval record into a state. Revoked and used win over expired, and
// expired wins over approved, so the status always names why an approval cannot be used.
func approvalStatus(a db.APIBASApproval, now time.Time) string {
	switch {
	case a.RevokedAt != nil:
		return "revoked"
	case a.ConsumedAt != nil:
		return "used"
	case a.ApprovedBy == "" && now.After(a.CreatedAt.Add(db.ApprovalRequestWindow)):
		return "expired"
	case a.ApprovedBy == "":
		return "pending"
	case a.ExpiresAt == nil || !now.Before(*a.ExpiresAt):
		return "expired"
	}
	return "approved"
}

// emitAPIBASApproval raises a notification for an approval event: stored, pushed to connected browser sessions and sent to
// enabled webhooks by the notification service. It is a broadcast, not addressed to individual approvers, and it never carries
// the binding hash. A server without the notification service skips it.
func (h *Handler) emitAPIBASApproval(ctx context.Context, typ notifications.EventType, sev notifications.Severity, a db.APIBASApproval, actor, msg string) {
	if h.notifications == nil {
		return
	}
	h.notifications.Emit(ctx, notifications.Event{
		Type: typ, TargetID: a.TargetID, Severity: sev, Message: msg,
		Metadata: map[string]any{"approval_id": a.ID, "target_id": a.TargetID, "requested_by": a.RequestedBy, "actor": actor},
	})
}

func approvalView(a db.APIBASApproval) map[string]any {
	return map[string]any{
		"id": a.ID, "target_id": a.TargetID, "requested_by": a.RequestedBy, "approved_by": a.ApprovedBy,
		"approved_at": a.ApprovedAt, "created_at": a.CreatedAt, "expires_at": a.ExpiresAt, "status": approvalStatus(a, time.Now()),
		"revoked_by": a.RevokedBy, "revoked_at": a.RevokedAt, "revoke_reason": a.RevokeReason,
		"used_by_job": a.ConsumedByJob, "used_at": a.ConsumedAt,
		"executable": false, // production execution is not enabled in this release
	}
}

// RequestAPIBASApproval records a request to approve one exact production assessment configuration.
// POST /api/apibas/approvals
func (h *Handler) RequestAPIBASApproval(w http.ResponseWriter, r *http.Request) {
	actor, ok := apibasActor(r)
	if !ok {
		jsonError(w, "unauthenticated", http.StatusUnauthorized)
		return
	}
	var b apibasApprovalBody
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&b); err != nil || b.TargetID == "" || b.Fixture == "" || len(b.ScenarioIDs) == 0 {
		jsonError(w, "target_id, fixture and scenario_ids are required", http.StatusBadRequest)
		return
	}
	t, err := db.GetAPIBASTarget(r.Context(), h.db, b.TargetID)
	if errors.Is(err, db.ErrAPIBASTargetNotFound) {
		jsonError(w, "target not found", http.StatusNotFound)
		return
	}
	if err != nil {
		jsonError(w, "could not load target", http.StatusInternalServerError)
		return
	}
	if t.Environment != "production" {
		jsonError(w, "only production targets need an approval", http.StatusBadRequest)
		return
	}
	for _, id := range b.ScenarioIDs {
		if !slices.Contains(t.AllowedScenarios, id) {
			jsonError(w, "scenario "+id+" is not allowed on this target", http.StatusForbidden)
			return
		}
	}
	hash := apibasjobs.Binding(t.ID, t.Environment, b.Fixture, b.ScenarioIDs, t.AllowedHosts, t.AllowedPaths)
	id, err := db.CreateAPIBASApproval(r.Context(), h.db, db.APIBASApproval{BindingHash: hash, TargetID: t.ID, RequestedBy: actor})
	if err != nil {
		jsonError(w, "could not record the approval request", http.StatusInternalServerError)
		return
	}
	_ = h.auditDurable(r.Context(), actor, "apibas.approval.request", "apibas-approval:"+id, map[string]any{
		"target_id": t.ID, "fixture": b.Fixture, "scenario_ids": b.ScenarioIDs, "binding_hash": hash,
	}, "success")
	h.emitAPIBASApproval(r.Context(), notifications.EventAPIBASApprovalRequested, notifications.SeverityWarning,
		db.APIBASApproval{ID: id, TargetID: t.ID, RequestedBy: actor}, actor,
		"Production assessment approval requested for target "+t.ID+" by "+actor)
	apibasRespond(w, http.StatusCreated, map[string]any{"id": id, "status": "pending", "binding_hash": hash})
}

// ApproveAPIBASApproval records the approver of a pending request. The requester cannot approve their own request and a
// request is approved once. POST /api/apibas/approvals/{id}/approve
func (h *Handler) ApproveAPIBASApproval(w http.ResponseWriter, r *http.Request) {
	actor, ok := apibasActor(r)
	if !ok {
		jsonError(w, "unauthenticated", http.StatusUnauthorized)
		return
	}
	id := chi.URLParam(r, "id")
	a, err := db.GetAPIBASApproval(r.Context(), h.db, id)
	if errors.Is(err, db.ErrAPIBASApprovalNotFound) {
		jsonError(w, "approval not found", http.StatusNotFound)
		return
	}
	if err != nil {
		jsonError(w, "could not load approval", http.StatusInternalServerError)
		return
	}
	refuse := func(code int, msg string) {
		_ = h.auditDurable(r.Context(), actor, "apibas.approval.refused", "apibas-approval:"+id, map[string]any{"reason": msg}, "denied")
		jsonError(w, msg, code)
	}
	switch {
	case a.RevokedAt != nil:
		refuse(http.StatusConflict, "this request was revoked")
		return
	case a.ApprovedBy != "":
		refuse(http.StatusConflict, "this request is already approved")
		return
	case approvalStatus(a, time.Now()) == "expired":
		refuse(http.StatusConflict, "this request expired before it was approved")
		return
	case a.RequestedBy == actor:
		refuse(http.StatusForbidden, "the requester cannot approve their own request")
		return
	}
	if err := db.ApproveAPIBASApproval(r.Context(), h.db, id, actor); err != nil {
		// Another approver won the race, or the row changed: report it as already handled.
		refuse(http.StatusConflict, "this request could not be approved; it may already be approved")
		return
	}
	_ = h.auditDurable(r.Context(), actor, "apibas.approval.approve", "apibas-approval:"+id, map[string]any{
		"target_id": a.TargetID, "requested_by": a.RequestedBy, "binding_hash": a.BindingHash,
	}, "success")
	h.emitAPIBASApproval(r.Context(), notifications.EventAPIBASApprovalApproved, notifications.SeverityInfo, a, actor,
		"Production assessment approval for target "+a.TargetID+" approved by "+actor)
	got, err := db.GetAPIBASApproval(r.Context(), h.db, id)
	if err != nil {
		apibasRespond(w, http.StatusOK, map[string]any{"id": id, "status": "approved"})
		return
	}
	apibasRespond(w, http.StatusOK, approvalView(got))
}

type apibasRevokeBody struct {
	Reason string `json:"reason"`
}

// RevokeAPIBASApproval withdraws a pending or approved approval so it can no longer be used. An approval that was already used
// cannot be revoked. POST /api/apibas/approvals/{id}/revoke
func (h *Handler) RevokeAPIBASApproval(w http.ResponseWriter, r *http.Request) {
	actor, ok := apibasActor(r)
	if !ok {
		jsonError(w, "unauthenticated", http.StatusUnauthorized)
		return
	}
	var b apibasRevokeBody
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&b); err != nil || len(b.Reason) > 500 {
		jsonError(w, "invalid body", http.StatusBadRequest)
		return
	}
	id := chi.URLParam(r, "id")
	a, err := db.GetAPIBASApproval(r.Context(), h.db, id)
	if errors.Is(err, db.ErrAPIBASApprovalNotFound) {
		jsonError(w, "approval not found", http.StatusNotFound)
		return
	}
	if err != nil {
		jsonError(w, "could not load approval", http.StatusInternalServerError)
		return
	}
	if a.RevokedAt != nil || a.ConsumedAt != nil {
		msg := "this approval was already revoked"
		if a.ConsumedAt != nil {
			msg = "this approval was already used and cannot be revoked"
		}
		_ = h.auditDurable(r.Context(), actor, "apibas.approval.refused", "apibas-approval:"+id, map[string]any{"reason": msg}, "denied")
		jsonError(w, msg, http.StatusConflict)
		return
	}
	if err := db.RevokeAPIBASApproval(r.Context(), h.db, id, actor, b.Reason); err != nil {
		jsonError(w, "this approval could not be revoked; it may have just been used", http.StatusConflict)
		return
	}
	_ = h.auditDurable(r.Context(), actor, "apibas.approval.revoke", "apibas-approval:"+id, map[string]any{
		"target_id": a.TargetID, "requested_by": a.RequestedBy, "approved_by": a.ApprovedBy, "reason": b.Reason,
	}, "success")
	h.emitAPIBASApproval(r.Context(), notifications.EventAPIBASApprovalRevoked, notifications.SeverityInfo, a, actor,
		"Production assessment approval for target "+a.TargetID+" revoked by "+actor)
	got, err := db.GetAPIBASApproval(r.Context(), h.db, id)
	if err != nil {
		apibasRespond(w, http.StatusOK, map[string]any{"id": id, "status": "revoked"})
		return
	}
	apibasRespond(w, http.StatusOK, approvalView(got))
}

// encodeApprovalCursor and decodeApprovalCursor turn a list position (created_at, id) into an opaque token and back.
func encodeApprovalCursor(a db.APIBASApproval) string {
	return base64.RawURLEncoding.EncodeToString([]byte(a.CreatedAt.UTC().Format(time.RFC3339Nano) + "|" + a.ID))
}

func decodeApprovalCursor(c string) (time.Time, string, bool) {
	raw, err := base64.RawURLEncoding.DecodeString(c)
	if err != nil {
		return time.Time{}, "", false
	}
	ts, id, ok := strings.Cut(string(raw), "|")
	t, terr := time.Parse(time.RFC3339Nano, ts)
	if !ok || terr != nil || len(id) != 36 {
		return time.Time{}, "", false
	}
	return t, id, true
}

// ListAPIBASApprovals lists approvals, newest first, a page at a time.
// GET /api/apibas/approvals?state=pending|approved|all&target_id=&requested_by=&limit=&cursor=
// The default state is pending, which is what an approver needs. next_cursor is present when more rows follow; pass it back as
// cursor to continue. The binding hash is not returned.
func (h *Handler) ListAPIBASApprovals(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	state := q.Get("state")
	if state == "" {
		state = "pending"
	}
	if state != "pending" && state != "approved" && state != "all" {
		jsonError(w, "state must be pending, approved or all", http.StatusBadRequest)
		return
	}
	f := db.APIBASApprovalFilter{State: state, TargetID: q.Get("target_id"), Requester: q.Get("requested_by")}
	if v := q.Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 200 {
			jsonError(w, "limit must be between 1 and 200", http.StatusBadRequest)
			return
		}
		f.Limit = n
	}
	if c := q.Get("cursor"); c != "" {
		t, id, ok := decodeApprovalCursor(c)
		if !ok {
			jsonError(w, "cursor is not valid", http.StatusBadRequest)
			return
		}
		f.AfterTime, f.AfterID = &t, id
	}
	rows, more, err := db.ListAPIBASApprovals(r.Context(), h.db, f)
	if err != nil {
		jsonError(w, "could not list approvals", http.StatusInternalServerError)
		return
	}
	out := make([]map[string]any, 0, len(rows))
	for _, a := range rows {
		out = append(out, approvalView(a))
	}
	resp := map[string]any{"approvals": out, "state": state}
	if more && len(rows) > 0 {
		resp["next_cursor"] = encodeApprovalCursor(rows[len(rows)-1])
	}
	apibasRespond(w, http.StatusOK, resp)
}

// GetAPIBASApproval shows one approval. GET /api/apibas/approvals/{id}
func (h *Handler) GetAPIBASApproval(w http.ResponseWriter, r *http.Request) {
	a, err := db.GetAPIBASApproval(r.Context(), h.db, chi.URLParam(r, "id"))
	if errors.Is(err, db.ErrAPIBASApprovalNotFound) {
		jsonError(w, "approval not found", http.StatusNotFound)
		return
	}
	if err != nil {
		jsonError(w, "could not load approval", http.StatusInternalServerError)
		return
	}
	apibasRespond(w, http.StatusOK, approvalView(a))
}
