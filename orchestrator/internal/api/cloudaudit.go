package api

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"

	"github.com/audspect/bas/internal/auth"
	"github.com/audspect/bas/internal/cloudgraph"
)

// Audit and telemetry for cloud requests are separate records:
//   - Audit (audit_logs) is the record of who asked for what, against which
//     account, and what happened. It keeps identifiers. It is written
//     synchronously, so a caller can require it to exist before it acts.
//   - Telemetry (internal/observability) counts and times behaviour. Its labels
//     are bounded and never carry account or identity IDs.
// A refusal is written to both, because it is both a security event and a
// measurable outcome.

// recordCloudAudit writes one audit entry synchronously and returns its error.
// Unlike auditLogAs, which is fire-and-forget, a cloud request needs to know
// whether the record exists before it acts. Tests may override the writer with
// h.probeAudit.
func (h *Handler) recordCloudAudit(ctx context.Context, r *http.Request, actorID, action, resource string, detail map[string]any, outcome string) error {
	if h.probeAudit != nil {
		return h.probeAudit(ctx, actorID, action, resource, detail, outcome)
	}
	if h.db == nil {
		return errors.New("audit store unavailable")
	}
	body, err := json.Marshal(detail)
	if err != nil {
		return err
	}
	ip := r.Header.Get("X-Real-IP")
	if ip == "" {
		ip = r.RemoteAddr
	}
	_, err = h.db.Exec(ctx,
		`INSERT INTO audit_logs (actor_id, action, resource, detail, ip, outcome)
		 VALUES ($1,$2,$3,$4,$5,$6)`,
		actorID, action, resource, body, ip, outcome)
	return err
}

// refuseCloudRequest records a refusal and writes the HTTP error for it.
func (h *Handler) refuseCloudRequest(w http.ResponseWriter, r *http.Request, action string, account cloudgraph.AccountScope, err error) {
	h.recordCloudRefusal(r, action, account, err)
	jsonError(w, err.Error(), discoveryStatusCode(err))
}

// recordCloudRefusal counts and audits a request refused before any provider was
// contacted. The refusal happens whether or not the audit write succeeds, so a
// failed write is logged rather than allowing the request through.
func (h *Handler) recordCloudRefusal(r *http.Request, action string, account cloudgraph.AccountScope, err error) {
	reason := refusalReason(err)
	h.cloudSettings().recordRefusal(reason)

	actor := ""
	if c, ok := auth.ClaimsFrom(r.Context()); ok && c != nil {
		actor = c.UserID
	}
	detail := map[string]any{
		"action":    action,
		"provider":  account.Provider,
		"accountId": account.AccountID,
		"reason":    reason,
	}
	resource := "cloud-account:" + account.Provider + ":" + account.AccountID
	if werr := h.recordCloudAudit(r.Context(), r, actor, action+".refused", resource, detail, "refused"); werr != nil {
		slog.Error("cloud refusal audit write failed", "event", "cloud.refusal.audit_failed", "action", action, "reason", reason, "error", werr.Error())
	}
	slog.Warn("cloud request refused", "event", "cloud.refused", "action", action, "provider", account.Provider, "account_id", account.AccountID, "reason", reason)
}

// refusalReason names why a request was refused, using bounded values.
func refusalReason(err error) string {
	switch {
	case errors.Is(err, errCloudAccountNotAllowed):
		return "allow-list"
	case errors.Is(err, errCloudAccountBusy):
		return "busy"
	case errors.Is(err, errCloudServerSaturated):
		return "saturated"
	default:
		return "other"
	}
}

// isCloudRefusal reports whether err is one of the refusals above.
func isCloudRefusal(err error) bool {
	return errors.Is(err, errCloudAccountNotAllowed) || errors.Is(err, errCloudAccountBusy) || errors.Is(err, errCloudServerSaturated)
}
