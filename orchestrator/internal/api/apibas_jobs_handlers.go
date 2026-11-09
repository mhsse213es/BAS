package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"regexp"
	"slices"

	apibasjobs "github.com/audspect/bas/internal/apibas/jobs"
	"github.com/audspect/bas/internal/apibas/scope"
	"github.com/audspect/bas/internal/auth"
	"github.com/audspect/bas/internal/db"
	"github.com/audspect/bas/internal/secretstore"
	"github.com/go-chi/chi/v5"
)

var apibasTargetIDRE = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{1,62}$`)

// WithAPIBASJobs attaches the assessment execution service. A nil service leaves the job endpoints answering 503.
func (h *Handler) WithAPIBASJobs(s *apibasjobs.Service) *Handler {
	h.apibasJobs = s
	return h
}

// apibasAsync runs fn off the request path. Tests replace it to keep a job queued.
func (h *Handler) apibasAsync(fn func()) {
	if h.apibasAsyncHook != nil {
		h.apibasAsyncHook(fn)
		return
	}
	go fn()
}

// respondStatus writes a JSON body with an explicit status. The Content-Type header is set before the status is sent.
func apibasRespond(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func apibasActor(r *http.Request) (string, bool) {
	c, ok := auth.ClaimsFrom(r.Context())
	if !ok || c == nil || c.UserID == "" {
		return "", false
	}
	return c.UserID, true
}

type apibasTargetBody struct {
	ID               string            `json:"id"`
	Name             string            `json:"name"`
	BaseURL          string            `json:"base_url"`
	Environment      string            `json:"environment"`
	AllowedHosts     []string          `json:"allowed_hosts"`
	AllowedPaths     []string          `json:"allowed_paths"`
	AllowedScenarios []string          `json:"allowed_scenarios"`
	CredentialRefs   map[string]string `json:"credential_refs"`
	// Credentials is write-only: each value is stored in the secret store and replaced by a reference. It is never returned,
	// logged or audited.
	Credentials map[string]string `json:"credentials"`
	Enabled     bool              `json:"enabled"`
}

// CreateAPIBASTarget registers an assessment target. POST /api/apibas/targets
func (h *Handler) CreateAPIBASTarget(w http.ResponseWriter, r *http.Request) {
	actor, ok := apibasActor(r)
	if !ok {
		jsonError(w, "unauthenticated", http.StatusUnauthorized)
		return
	}
	var b apibasTargetBody
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&b); err != nil {
		jsonError(w, "invalid body", http.StatusBadRequest)
		return
	}
	if msg := h.validateAPIBASTarget(b); msg != "" {
		jsonError(w, msg, http.StatusBadRequest)
		return
	}
	refs := map[string]string{}
	for k, v := range b.CredentialRefs {
		refs[k] = v
	}
	for name := range b.Credentials {
		if _, dup := b.CredentialRefs[name]; dup {
			jsonError(w, "a credential name is given both as a reference and as a value", http.StatusBadRequest)
			return
		}
	}
	if len(b.Credentials) > 0 {
		if h.secrets == nil {
			jsonError(w, "the credential store is not available on this server", http.StatusServiceUnavailable)
			return
		}
		stored, serr := h.storeTargetCredentials(r.Context(), b.ID, b.Credentials)
		if serr != nil {
			jsonError(w, "credentials could not be stored", http.StatusInternalServerError)
			return
		}
		for name, ref := range stored {
			refs[name] = ref
		}
	}
	err := db.CreateAPIBASTarget(r.Context(), h.db, db.APIBASTarget{
		ID: b.ID, Name: b.Name, BaseURL: b.BaseURL, Environment: b.Environment, AllowedHosts: b.AllowedHosts, AllowedPaths: b.AllowedPaths,
		AllowedScenarios: b.AllowedScenarios, CredentialRefs: refs, Enabled: b.Enabled, CreatedBy: actor,
	})
	if errors.Is(err, db.ErrAPIBASTargetExists) {
		jsonError(w, "a target with this id is already registered", http.StatusConflict)
		return
	}
	if err != nil {
		jsonError(w, "could not register target", http.StatusInternalServerError)
		return
	}
	_ = h.auditDurable(r.Context(), actor, "apibas.target.create", "apibas-target:"+b.ID, map[string]any{
		"environment": b.Environment, "base_url": b.BaseURL, "allowed_hosts": b.AllowedHosts, "allowed_paths": b.AllowedPaths,
		"allowed_scenarios": b.AllowedScenarios, "enabled": b.Enabled, "credential_names": credentialNames(refs),
	}, "success")
	apibasRespond(w, http.StatusCreated, map[string]any{"id": b.ID})
}

// storeTargetCredentials writes each value to the secret store under a reference derived from the target id and the sorted
// position of the name, and returns name to reference. The reference grammar allows only letters and underscores in the column,
// so the column is "secret_" plus a letter for the position rather than the name itself.
func (h *Handler) storeTargetCredentials(ctx context.Context, targetID string, values map[string]string) (map[string]string, error) {
	names := make([]string, 0, len(values))
	for n := range values {
		names = append(names, n)
	}
	slices.Sort(names)
	out := make(map[string]string, len(names))
	for i, n := range names {
		if n == "" || values[n] == "" || i >= 26 {
			return nil, errors.New("credential name or value is empty, or there are too many credentials")
		}
		ref, err := secretstore.MakeRef("apibas_targets", targetID, "secret_"+string(rune('a'+i)))
		if err != nil {
			return nil, err
		}
		if err := h.secrets.Put(ctx, ref, values[n]); err != nil {
			return nil, err
		}
		out[n] = ref
	}
	return out, nil
}

// credentialNames lists the credential names of a target for audit. Names only, never references to values or the values.
func credentialNames(refs map[string]string) []string {
	out := make([]string, 0, len(refs))
	for n := range refs {
		out = append(out, n)
	}
	slices.Sort(out)
	return out
}

// validateAPIBASTarget returns a reason for refusing the registration, or "".
func (h *Handler) validateAPIBASTarget(b apibasTargetBody) string {
	if !apibasTargetIDRE.MatchString(b.ID) || b.Name == "" {
		return "id must be 2 to 63 lowercase letters, digits, '_' or '-', and a name is required"
	}
	switch b.Environment {
	case "lab", "staging", "production":
	default:
		return "environment must be lab, staging or production"
	}
	u, err := url.Parse(b.BaseURL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return "base_url must be an absolute http or https URL"
	}
	if !slices.Contains(b.AllowedHosts, u.Host) {
		return "the base_url host must be listed in allowed_hosts"
	}
	for _, p := range b.AllowedPaths {
		if !scope.ValidPrefix(p) {
			return "allowed_paths must be rooted path prefixes with no query, no dot segments and not just \"/\": " + p
		}
	}
	if b.Environment != "lab" && len(b.AllowedPaths) == 0 {
		return "allowed_paths must list at least one path prefix for a staging or production target"
	}
	if len(b.AllowedScenarios) == 0 {
		return "allowed_scenarios must name at least one scenario"
	}
	all, err := loadAPIBASCatalog()
	if err != nil {
		return "scenario catalog unavailable"
	}
	known := map[string]bool{}
	for _, s := range all {
		known[s.ID] = true
	}
	for _, id := range b.AllowedScenarios {
		if !known[id] {
			return "unknown scenario " + id
		}
	}
	for name, ref := range b.CredentialRefs {
		if name == "" || !secretstore.ValidRef(ref) {
			return "credential_refs must map names to secret-store references, never values"
		}
	}
	return ""
}

type apibasJobBody struct {
	Key         string   `json:"key"`
	TargetID    string   `json:"target_id"`
	Fixture     string   `json:"fixture"`
	ScenarioIDs []string `json:"scenario_ids"`
}

// SubmitAPIBASJob queues an assessment and starts it in the background. POST /api/apibas/jobs
func (h *Handler) SubmitAPIBASJob(w http.ResponseWriter, r *http.Request) {
	if h.apibasJobs == nil {
		jsonError(w, "API BAS job execution is not configured on this server", http.StatusServiceUnavailable)
		return
	}
	actor, ok := apibasActor(r)
	if !ok {
		jsonError(w, "unauthenticated", http.StatusUnauthorized)
		return
	}
	var b apibasJobBody
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&b); err != nil {
		jsonError(w, "invalid body", http.StatusBadRequest)
		return
	}
	job, created, err := h.apibasJobs.SubmitForTarget(r.Context(), apibasjobs.TargetRequest{
		Key: b.Key, RequestedBy: actor, TargetID: b.TargetID, Fixture: b.Fixture, ScenarioIDs: b.ScenarioIDs,
	})
	if err != nil {
		h.writeAPIBASSubmitError(w, r, actor, b, err)
		return
	}
	if !created {
		// A repeated key returns the existing job and starts nothing.
		respond(w, map[string]any{"id": job.ID, "status": job.Status, "created": false})
		return
	}
	// The start record is committed before anything runs. If it cannot be, the job is failed and never dispatched.
	if aerr := h.auditDurable(r.Context(), actor, "apibas.job.submit", "apibas-job:"+job.ID, map[string]any{
		"target_id": job.TargetID, "environment": job.Environment, "base_url": job.TargetBaseURL,
		"scenario_ids": job.ScenarioIDs, "fixture": job.Fixture, "job_key": job.JobKey,
	}, "success"); aerr != nil {
		bg := context.WithoutCancel(r.Context())
		if ok, _ := db.StartAPIBASJob(bg, h.db, job.ID); ok {
			_ = db.FinishAPIBASJob(bg, h.db, job.ID, "failed", "audit record could not be written", nil)
		}
		jsonError(w, "audit record could not be written; the job was not started", http.StatusInternalServerError)
		return
	}
	jobID := job.ID
	h.apibasAsync(func() { h.runAPIBASJob(actor, jobID) })
	apibasRespond(w, http.StatusAccepted, map[string]any{"id": job.ID, "status": job.Status, "created": true})
}

// runAPIBASJob executes one job and writes its closing audit record.
func (h *Handler) runAPIBASJob(actor, jobID string) {
	ctx := context.Background()
	_, derr := h.apibasJobs.Dispatch(ctx, jobID)
	job, err := db.GetAPIBASJob(ctx, h.db, jobID)
	if err != nil {
		return
	}
	outcome := "success"
	if job.Status != "completed" || derr != nil {
		outcome = "failure"
	}
	_ = h.auditDurable(ctx, actor, "apibas.job.finish", "apibas-job:"+jobID, map[string]any{
		"status": job.Status, "failure_reason": job.FailureReason, "target_id": job.TargetID,
		"started_at": job.StartedAt, "finished_at": job.FinishedAt,
	}, outcome)
}

func (h *Handler) writeAPIBASSubmitError(w http.ResponseWriter, r *http.Request, actor string, b apibasJobBody, err error) {
	code, msg := http.StatusBadRequest, "invalid request"
	switch {
	case errors.Is(err, db.ErrAPIBASTargetNotFound):
		code, msg = http.StatusNotFound, "target not found"
	case errors.Is(err, apibasjobs.ErrEnvironmentNotPermitted):
		code, msg = http.StatusForbidden, "this target's environment is not permitted for execution in this release"
	case errors.Is(err, apibasjobs.ErrScopeViolation):
		code, msg = http.StatusForbidden, "request is outside the target's registered scope"
	case errors.Is(err, apibasjobs.ErrTargetDisabled):
		code, msg = http.StatusConflict, "target is disabled"
	case errors.Is(err, db.ErrAPIBASTargetBusy):
		code, msg = http.StatusConflict, "target already has an active assessment"
	default:
		// Validation text from the request shape is safe to return; storage errors are not.
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			code, msg = http.StatusInternalServerError, "could not queue the job"
		} else {
			msg = err.Error()
		}
	}
	_ = h.auditDurable(r.Context(), actor, "apibas.job.refused", "apibas-target:"+b.TargetID, map[string]any{
		"reason": msg, "scenario_ids": b.ScenarioIDs, "job_key": b.Key,
	}, "denied")
	jsonError(w, msg, code)
}

// GetAPIBASJob returns one job with its stored reports. GET /api/apibas/jobs/{id}
func (h *Handler) GetAPIBASJob(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	job, err := db.GetAPIBASJob(r.Context(), h.db, id)
	if errors.Is(err, db.ErrAPIBASJobNotFound) {
		jsonError(w, "job not found", http.StatusNotFound)
		return
	}
	if err != nil {
		jsonError(w, "could not load job", http.StatusInternalServerError)
		return
	}
	reps, err := db.ListAPIBASJobReports(r.Context(), h.db, id)
	if err != nil {
		jsonError(w, "could not load job reports", http.StatusInternalServerError)
		return
	}
	out := make([]map[string]any, 0, len(reps))
	for _, rp := range reps {
		out = append(out, map[string]any{
			"scenario_id": rp.ScenarioID, "run_tag": rp.RunTag, "result": rp.Result,
			"exploitability": rp.Exploitability, "control": rp.Control, "detection": rp.Detection, "reason": rp.Reason,
		})
	}
	respond(w, map[string]any{
		"id": job.ID, "target_id": job.TargetID, "environment": job.Environment, "status": job.Status,
		"failure_reason": job.FailureReason, "requested_by": job.RequestedBy, "scenario_ids": job.ScenarioIDs,
		"created_at": job.CreatedAt, "started_at": job.StartedAt, "finished_at": job.FinishedAt, "reports": out,
	})
}

// CancelAPIBASJob stops a running job. POST /api/apibas/jobs/{id}/cancel
func (h *Handler) CancelAPIBASJob(w http.ResponseWriter, r *http.Request) {
	if h.apibasJobs == nil {
		jsonError(w, "API BAS job execution is not configured on this server", http.StatusServiceUnavailable)
		return
	}
	actor, ok := apibasActor(r)
	if !ok {
		jsonError(w, "unauthenticated", http.StatusUnauthorized)
		return
	}
	id := chi.URLParam(r, "id")
	if _, err := db.GetAPIBASJob(r.Context(), h.db, id); errors.Is(err, db.ErrAPIBASJobNotFound) {
		jsonError(w, "job not found", http.StatusNotFound)
		return
	}
	if !h.apibasJobs.Cancel(id) {
		jsonError(w, "job is not running on this server", http.StatusConflict)
		return
	}
	_ = h.auditDurable(r.Context(), actor, "apibas.job.cancel", "apibas-job:"+id, map[string]any{}, "success")
	apibasRespond(w, http.StatusAccepted, map[string]any{"id": id, "cancelling": true})
}
