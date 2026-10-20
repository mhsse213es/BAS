package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/sts"

	"github.com/audspect/bas/internal/auth"
	"github.com/audspect/bas/internal/cloudgraph"
)

// cloudProbeAllowListEnv names the server setting that lists the accounts a live
// probe may target, as provider:accountId entries. It is read on the server
// and never taken from a request. Unset means no account is probe-able.
const cloudProbeAllowListEnv = "CLOUD_PROBE_ALLOWED_ACCOUNTS"

// probeTimeout bounds one probe. A probe is a single read or simulation.
const probeTimeout = time.Minute

// POST /api/cloud-probes -- runs one registered read-only probe against an
// allow-listed account. Dry-run is the default and contacts no provider. Live
// mode still passes every server-side check in cloudgraph.RunProbe.
//
// Audit is fail-closed. A "requested" entry is written before anything runs, and
// if it cannot be written the probe does not run. The "outcome" entry is written
// after the probe, and if it cannot be written the result is withheld.
func (h *Handler) TriggerCloudProbe(w http.ResponseWriter, r *http.Request) {
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	var req cloudgraph.ProbeRequest
	if err := dec.Decode(&req); err != nil {
		jsonError(w, "invalid request body: "+err.Error(), http.StatusBadRequest)
		return
	}
	if req.Mode == "" {
		req.Mode = cloudgraph.ProbeDryRun
	}

	claims, ok := auth.ClaimsFrom(r.Context())
	if !ok || claims == nil || claims.UserID == "" {
		// Without an authenticated actor the audit entry cannot say who asked.
		jsonError(w, "probe requests need an authenticated actor", http.StatusUnauthorized)
		return
	}

	allow, err := cloudgraph.ParseProbeAllowList(os.Getenv(cloudProbeAllowListEnv))
	if err != nil {
		jsonError(w, "probe allow-list is misconfigured on this server", http.StatusServiceUnavailable)
		return
	}

	resource := fmt.Sprintf("cloud-probe:%s:%s", req.Provider, req.AccountID)
	detail := probeAuditDetail(req)
	if err := h.recordProbeAudit(r.Context(), r, claims.UserID, "cloud.probe.requested", resource, detail, "pending"); err != nil {
		jsonError(w, "audit record could not be written; probe not run", http.StatusServiceUnavailable)
		return
	}

	var prober cloudgraph.Prober
	if req.Mode == cloudgraph.ProbeLiveReadOnly {
		prober, err = h.probeProberFor(r.Context(), req.Provider, req.AccountID)
		if err != nil {
			h.finishProbe(w, r, claims.UserID, resource, detail, "error", err.Error(), http.StatusServiceUnavailable)
			return
		}
	}

	ctx, cancel := context.WithTimeout(r.Context(), probeTimeout)
	res, err := cloudgraph.RunProbe(ctx, req, allow, prober)
	cancel()
	if err != nil {
		if errors.Is(err, cloudgraph.ErrProbeRejected) {
			h.finishProbe(w, r, claims.UserID, resource, detail, "rejected", err.Error(), http.StatusBadRequest)
			return
		}
		h.finishProbe(w, r, claims.UserID, resource, detail, "error", err.Error(), http.StatusBadGateway)
		return
	}

	detail["outcome"] = res.Outcome
	detail["evidence"] = string(res.Evidence)
	detail["simulated"] = res.Simulated
	if err := h.recordProbeAudit(r.Context(), r, claims.UserID, "cloud.probe.outcome", resource, detail, res.Outcome); err != nil {
		jsonError(w, "probe ran but its outcome could not be recorded; result withheld", http.StatusInternalServerError)
		return
	}
	jsonOK(w, res)
}

// finishProbe writes the outcome entry for a probe that did not produce a result,
// then reports the failure. A failed outcome write is reported as such.
func (h *Handler) finishProbe(w http.ResponseWriter, r *http.Request, actorID, resource string, detail map[string]any, outcome, message string, status int) {
	detail["outcome"] = outcome
	detail["message"] = message
	if err := h.recordProbeAudit(r.Context(), r, actorID, "cloud.probe.outcome", resource, detail, outcome); err != nil {
		jsonError(w, "probe did not run; the failure could not be recorded", http.StatusInternalServerError)
		return
	}
	jsonError(w, message, status)
}

// probeAuditDetail is the part of a probe that goes into the audit trail. It holds
// the requested operation and account. It never holds credentials.
func probeAuditDetail(req cloudgraph.ProbeRequest) map[string]any {
	return map[string]any{
		"provider":  req.Provider,
		"accountId": req.AccountID,
		"operation": req.Operation,
		"target":    req.Target,
		"action":    req.Action,
		"mode":      string(req.Mode),
	}
}

// recordProbeAudit writes one audit entry synchronously and returns its error.
// Unlike auditLogAs, which is fire-and-forget, a probe needs to know whether the
// record exists before it acts.
func (h *Handler) recordProbeAudit(ctx context.Context, r *http.Request, actorID, action, resource string, detail map[string]any, outcome string) error {
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

// probeProberFor builds the prober for a provider from server configuration.
// Building it contacts no provider. Only the probe itself does.
func (h *Handler) probeProberFor(ctx context.Context, provider, accountID string) (cloudgraph.Prober, error) {
	if h.cloudProber != nil {
		return h.cloudProber(ctx, provider, accountID)
	}
	switch provider {
	case "aws":
		cfg, err := awsConfigFor(ctx, cloudgraph.AccountScope{Provider: "aws", AccountID: accountID})
		if err != nil {
			return nil, err
		}
		return cloudgraph.NewAWSProber(sts.NewFromConfig(cfg), s3.NewFromConfig(cfg), iam.NewFromConfig(cfg)), nil
	default:
		return nil, fmt.Errorf("no probe prober for provider %q", provider)
	}
}
