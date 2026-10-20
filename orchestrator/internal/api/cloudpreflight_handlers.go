package api

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/audspect/bas/internal/cloudgraph"
)

// preflightTimeout bounds one preflight. It is a set of single reads, so it is
// much shorter than a discovery pass.
const preflightTimeout = 2 * time.Minute

// POST /api/cloud-preflight -- runs the prerequisite checks for one account and
// returns every check, without reading inventory. It makes read-only calls to the
// account, using the same server-side credentials as discovery.
func (h *Handler) TriggerCloudPreflight(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Account cloudgraph.AccountScope `json:"account"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonError(w, "invalid request body: "+err.Error(), http.StatusBadRequest)
		return
	}
	if body.Account.Provider == "" || body.Account.AccountID == "" {
		jsonError(w, "account.provider and account.accountId are required", http.StatusBadRequest)
		return
	}

	d, err := cloudDiscovererFor(r.Context(), body.Account)
	if err != nil {
		h.auditLog(r, "cloud.preflight", body.Account.AccountID, map[string]any{
			"provider": body.Account.Provider, "error": err.Error(),
		}, "error")
		jsonError(w, err.Error(), discoveryStatusCode(err))
		return
	}
	p, ok := d.(cloudgraph.Preflighter)
	if !ok {
		jsonError(w, "this discovery source cannot be preflighted", http.StatusInternalServerError)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), preflightTimeout)
	checks := p.Preflight(ctx)
	cancel()

	failed := cloudgraph.PreflightFailures(checks)
	outcome := "ok"
	if len(failed) > 0 {
		outcome = "blocked"
	}
	h.auditLog(r, "cloud.preflight", body.Account.AccountID, map[string]any{
		"provider": body.Account.Provider, "checks": len(checks), "failed": len(failed),
	}, outcome)

	jsonOK(w, map[string]any{
		"passed": len(failed) == 0,
		"checks": checks,
	})
}
