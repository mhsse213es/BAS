package api

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/jackc/pgx/v5"

	"github.com/audspect/bas/internal/auth"
	"github.com/audspect/bas/internal/scenario"
)

// resolveInProcessPolicy returns the in-process policy a run is judged against,
// resolved once at dispatch. The result is stored on the run as a snapshot, so
// later changes to the installation default never rewrite a historical verdict.
//
// explicit is the policy for this dispatch, from the request or from a campaign
// override. It takes precedence. Otherwise the installation default applies. If
// neither is set the result is "" (not stated), which keeps the verdict
// UNVERIFIED. Nothing is ever assumed.
func (h *Handler) resolveInProcessPolicy(ctx context.Context, explicit string) (string, error) {
	var dflt string
	err := h.db.QueryRow(ctx,
		`SELECT in_process_policy FROM execution_policy_default WHERE id = 1`).Scan(&dflt)
	if err != nil && err != pgx.ErrNoRows {
		return "", err
	}
	return scenario.EffectiveInProcessPolicy(explicit, dflt)
}

// GetExecutionPolicyDefault returns the installation-wide default. An unset
// default is reported as "", meaning not stated.
func (h *Handler) GetExecutionPolicyDefault(w http.ResponseWriter, r *http.Request) {
	var dflt string
	err := h.db.QueryRow(r.Context(),
		`SELECT in_process_policy FROM execution_policy_default WHERE id = 1`).Scan(&dflt)
	if err != nil && err != pgx.ErrNoRows {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	jsonOK(w, map[string]any{"inProcessPolicy": dflt})
}

// PutExecutionPolicyDefault sets the installation-wide default. Only an
// authorised user reaches this handler (CanManageExecutionPolicy). Values other
// than restricted, unrestricted, or "" are rejected, and "" clears the default.
func (h *Handler) PutExecutionPolicyDefault(w http.ResponseWriter, r *http.Request) {
	var body struct {
		InProcessPolicy string `json:"inProcessPolicy"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonError(w, "invalid JSON body", http.StatusBadRequest)
		return
	}
	if !scenario.ValidInProcessPolicy(body.InProcessPolicy) {
		jsonError(w, "inProcessPolicy must be restricted, unrestricted, or empty (not stated)", http.StatusBadRequest)
		return
	}
	actor := ""
	if c, ok := auth.ClaimsFrom(r.Context()); ok && c != nil {
		actor = c.UserID
	}
	if _, err := h.db.Exec(r.Context(),
		`INSERT INTO execution_policy_default (id, in_process_policy, updated_at, updated_by)
		 VALUES (1, $1, NOW(), $2)
		 ON CONFLICT (id) DO UPDATE SET in_process_policy = EXCLUDED.in_process_policy,
		   updated_at = NOW(), updated_by = EXCLUDED.updated_by`,
		body.InProcessPolicy, actor); err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	h.auditLog(r, "execution-policy.default.update", "in-process", map[string]any{"inProcessPolicy": body.InProcessPolicy}, "ok")
	jsonOK(w, map[string]any{"inProcessPolicy": body.InProcessPolicy})
}
