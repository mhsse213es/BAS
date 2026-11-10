package jobs

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"time"

	"github.com/audspect/bas/internal/apibas/runnerproto"
	"github.com/audspect/bas/internal/db"
)

var (
	// ErrTargetDisabled means the target exists but is not enabled for execution.
	ErrTargetDisabled = errors.New("apibas: target is disabled")
	// ErrScopeViolation means the request names a scenario or host outside the target's registered scope.
	ErrScopeViolation = errors.New("apibas: request is outside the target's registered scope")
	// ErrApprovalInvalid means an approval is missing, unapproved, self-approved, or bound to a different configuration.
	ErrApprovalInvalid = errors.New("apibas: approval is not valid for this assessment")
)

// TargetRequest is what a caller may choose. Everything else (URL, environment, hosts, credentials) comes from the registered
// target, so a request cannot point the runner at a host the operator did not register.
type TargetRequest struct {
	Key         string
	RequestedBy string
	TargetID    string
	Fixture     string
	ScenarioIDs []string
	// ApprovalID names the approval a production assessment uses. Ignored for lab and staging.
	ApprovalID string
	// Bound makes this a customer-bound job: its scenarios and fixture come from the plan, not the catalogue, and Fixture and
	// ScenarioIDs are derived from it. The plan is stored with the job.
	Bound *runnerproto.BoundPlan
}

// SubmitForTarget validates a request against its registered target and records a queued job. It enforces, in this order:
// the target exists and is enabled; its environment is permitted for execution (production never is in this release); the
// target's base URL host is in its registered allowed hosts; every scenario is in its registered allowed scenarios; and no
// other assessment is active on the target. A repeated Key returns the existing job with created=false.
func (s *Service) SubmitForTarget(ctx context.Context, r TargetRequest) (db.APIBASJob, bool, error) {
	job, created, err := s.submitForTarget(ctx, r)
	if err != nil || !created || r.Bound == nil {
		return job, created, err
	}
	// The plan is saved before the caller dispatches. If it cannot be, the job is failed so it can never run without it.
	raw, merr := json.Marshal(r.Bound)
	if merr == nil {
		merr = db.SaveAPIBASJobPlan(ctx, s.pool, job.ID, r.Bound.InventoryVersion, raw)
	}
	if merr != nil {
		bg := context.WithoutCancel(ctx)
		if ok, _ := db.StartAPIBASJob(bg, s.pool, job.ID); ok {
			_ = db.FinishAPIBASJob(bg, s.pool, job.ID, "failed", "the bound plan could not be stored", nil)
		}
		return db.APIBASJob{}, false, errors.New("apibas jobs: the bound plan could not be stored")
	}
	return job, true, nil
}

func (s *Service) submitForTarget(ctx context.Context, r TargetRequest) (db.APIBASJob, bool, error) {
	if r.Key == "" || r.RequestedBy == "" || r.TargetID == "" {
		return db.APIBASJob{}, false, errors.New("apibas jobs: key, requester and target are required")
	}
	t, err := db.GetAPIBASTarget(ctx, s.pool, r.TargetID)
	if err != nil {
		return db.APIBASJob{}, false, err
	}
	if !t.Enabled {
		return db.APIBASJob{}, false, ErrTargetDisabled
	}
	production := t.Environment == "production"
	if t.Environment != "lab" && t.Environment != "staging" && !(production && s.cfg.AllowProduction) {
		return db.APIBASJob{}, false, ErrEnvironmentNotPermitted
	}
	u, err := url.Parse(t.BaseURL)
	if err != nil || !slices.Contains(t.AllowedHosts, u.Host) {
		return db.APIBASJob{}, false, fmt.Errorf("%w: target host is not in its allowed hosts", ErrScopeViolation)
	}
	if r.Bound != nil {
		fx, err := runnerproto.BoundFixture(*r.Bound)
		if err != nil {
			return db.APIBASJob{}, false, err
		}
		plan, ids, err := runnerproto.BoundScenarioIDs(*r.Bound)
		if err != nil {
			return db.APIBASJob{}, false, fmt.Errorf("apibas jobs: the test data does not bind: %w", err)
		}
		if plan.Writes {
			// A write that succeeds changes the customer's object. It is never attempted against production, and only where the
			// operator registered path prefixes to hold it.
			if t.Environment == "production" {
				return db.APIBASJob{}, false, fmt.Errorf("%w: write scenarios are not run against production", ErrEnvironmentNotPermitted)
			}
			if len(t.AllowedPaths) == 0 {
				return db.APIBASJob{}, false, fmt.Errorf("%w: write scenarios need the target to register allowed paths", ErrScopeViolation)
			}
		}
		r.Fixture, r.ScenarioIDs = fx, ids
		// Every identity must use a credential registered on the target. A job never reaches for a secret the operator did not
		// attach to this target.
		for _, idn := range r.Bound.Spec.Identities {
			if _, ok := t.CredentialRefs[idn.CredentialRef]; !ok {
				return db.APIBASJob{}, false, fmt.Errorf("%w: credential %q is not registered on this target", ErrScopeViolation, idn.CredentialRef)
			}
		}
	}
	if len(r.ScenarioIDs) == 0 {
		return db.APIBASJob{}, false, errors.New("apibas jobs: at least one scenario is required")
	}
	for _, id := range r.ScenarioIDs {
		// Bound scenarios are generated from the target's own inventory; the registered path scope bounds them instead.
		if r.Bound == nil && !slices.Contains(t.AllowedScenarios, id) {
			return db.APIBASJob{}, false, fmt.Errorf("%w: scenario %q is not allowed on this target", ErrScopeViolation, id)
		}
	}
	sp := Spec{
		Key: r.Key, RequestedBy: r.RequestedBy, TargetBaseURL: t.BaseURL, Environment: t.Environment,
		Fixture: r.Fixture, ScenarioIDs: r.ScenarioIDs, Credentials: t.CredentialRefs,
	}
	if err := s.validateSpec(sp); err != nil {
		return db.APIBASJob{}, false, err
	}
	job := db.APIBASJob{
		JobKey: r.Key, TargetID: t.ID, RequestedBy: r.RequestedBy, TargetBaseURL: t.BaseURL, Environment: t.Environment,
		Fixture: r.Fixture, ScenarioIDs: r.ScenarioIDs, CredentialRefs: t.CredentialRefs, AllowedHosts: t.AllowedHosts, AllowedPaths: t.AllowedPaths,
	}
	if !production {
		return db.CreateAPIBASJobExclusive(ctx, s.pool, job)
	}
	// A repeated key returns the existing job without needing, or spending, another approval.
	existing, found, err := db.FindAPIBASJobByKey(ctx, s.pool, r.Key)
	if err != nil {
		return db.APIBASJob{}, false, err
	}
	if found {
		return existing, false, nil
	}
	if r.ApprovalID == "" {
		return db.APIBASJob{}, false, ErrApprovalRequired
	}
	appr, err := db.GetAPIBASApproval(ctx, s.pool, r.ApprovalID)
	if errors.Is(err, db.ErrAPIBASApprovalNotFound) {
		return db.APIBASJob{}, false, fmt.Errorf("%w: approval not found", ErrApprovalInvalid)
	}
	if err != nil {
		return db.APIBASJob{}, false, err
	}
	bind := Binding(t.ID, t.Environment, r.Fixture, r.ScenarioIDs, t.AllowedHosts, t.AllowedPaths)
	if err := CheckApproval(appr, r.RequestedBy, t.ID, bind, time.Now()); err != nil {
		return db.APIBASJob{}, false, err
	}
	got, created, err := db.CreateAPIBASJobExclusiveWithApproval(ctx, s.pool, job, r.ApprovalID)
	if errors.Is(err, db.ErrAPIBASApprovalUnusable) {
		// Lost a race for the approval, or it expired or was revoked between the check and the insert.
		return db.APIBASJob{}, false, fmt.Errorf("%w: approval was just used, revoked or expired", ErrApprovalInvalid)
	}
	return got, created, err
}

// Binding is the hash an approval is bound to. It covers the target, environment, fixture, the sorted scenario set and the
// sorted allowed hosts and paths, so changing any of them yields a different hash and the old approval stops matching.
func Binding(targetID, environment, fixture string, scenarioIDs, allowedHosts, allowedPaths []string) string {
	sc := slices.Clone(scenarioIDs)
	slices.Sort(sc)
	ah := slices.Clone(allowedHosts)
	slices.Sort(ah)
	ap := slices.Clone(allowedPaths)
	slices.Sort(ap)
	doc, _ := json.Marshal(struct {
		Target, Environment, Fixture string
		Scenarios, Hosts, Paths      []string
	}{targetID, environment, fixture, sc, ah, ap})
	sum := sha256.Sum256(doc)
	return hex.EncodeToString(sum[:])
}

// CheckApproval reports whether a is a valid production approval for this requester and configuration. It is the rule
// production execution will use once enabled; it is tested now so enabling production needs no new model. An approval is valid
// only if it is approved, was requested by this requester, is bound to this target and configuration hash, and was approved by
// someone other than the requester.
func CheckApproval(a db.APIBASApproval, requester, targetID, bindingHash string, now time.Time) error {
	switch {
	case a.ApprovedBy == "":
		return fmt.Errorf("%w: not approved", ErrApprovalInvalid)
	case a.RevokedAt != nil:
		return fmt.Errorf("%w: revoked", ErrApprovalInvalid)
	case a.ConsumedAt != nil:
		return fmt.Errorf("%w: already used", ErrApprovalInvalid)
	case a.ExpiresAt == nil || !now.Before(*a.ExpiresAt):
		return fmt.Errorf("%w: expired", ErrApprovalInvalid)
	case a.ApprovedBy == requester:
		return fmt.Errorf("%w: the requester cannot approve their own run", ErrApprovalInvalid)
	case a.RequestedBy != requester:
		return fmt.Errorf("%w: approval belongs to a different requester", ErrApprovalInvalid)
	case a.TargetID != targetID:
		return fmt.Errorf("%w: approval is for a different target", ErrApprovalInvalid)
	case a.BindingHash != bindingHash:
		return fmt.Errorf("%w: the configuration changed after approval", ErrApprovalInvalid)
	}
	return nil
}
