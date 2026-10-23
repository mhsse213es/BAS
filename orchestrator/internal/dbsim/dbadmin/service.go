// Package dbadmin is the Admin-facing logic of database security simulation:
// the audited "DB client mode" switch and the target registry, including the
// read-only identity check that decides whether a target may ever run in client
// mode. It holds the decisions so the HTTP layer in internal/api stays thin and
// the logic is testable without a database or Docker: every dependency is a
// small interface.
//
// Authorisation is enforced here as well as by the route middleware (defence in
// depth): each method re-checks the caller's role against the same permission
// the route requires.
package dbadmin

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/audspect/bas/internal/auth"
	"github.com/audspect/bas/internal/dbsim"
)

// ErrForbidden means the caller's role lacks the permission for the action.
var ErrForbidden = errors.New("dbsim: forbidden")

// ErrIdentityCheckUnavailable means no way to run the check on an agent is
// configured. Nothing is recorded and the target stays unverified, so client
// mode stays unreachable for it (fail closed).
var ErrIdentityCheckUnavailable = errors.New("dbsim: read-only identity check dispatch is not configured")

// Actor is the authenticated caller. IP is the client address recorded in the
// audit row.
type Actor struct {
	ID   string
	Role auth.Role
	IP   string
}

// AuditEntry is one audit_logs row.
type AuditEntry struct {
	ActorID  string
	Action   string
	Resource string
	Detail   map[string]any
	Outcome  string
	IP       string
}

// SettingsStore persists the Admin switches. Every mutating method writes the
// state change AND the supplied audit row in ONE transaction: if the audit row
// cannot be written the state does not change and an error is returned.
type SettingsStore interface {
	// GetClientMode returns the raw stored value; found is false when never set.
	GetClientMode(ctx context.Context) (value string, found bool, err error)
	SetClientMode(ctx context.Context, enabled bool, by string, audit AuditEntry) error
}

// TargetStore persists the target registry.
//
// Mutations are atomic with their audit row (see SettingsStore).
type TargetStore interface {
	// Create stores a new record; dbsim.ErrTargetExists on a duplicate id.
	Create(ctx context.Context, r dbsim.TargetRecord, audit AuditEntry) error
	// Get returns the record; dbsim.ErrTargetNotFound when absent.
	Get(ctx context.Context, id string) (dbsim.TargetRecord, error)
	List(ctx context.Context) ([]dbsim.TargetRecord, error)
	// Delete removes the record; dbsim.ErrTargetNotFound when absent.
	Delete(ctx context.Context, id string, audit AuditEntry) error
	// SaveIdentityCheck records a check result for the exact record version the
	// probe was run against: the update is bound to that record's id, creation
	// time and connection/identity fields (TargetRecord.SameConfig), and returns
	// dbsim.ErrTargetChanged, recording nothing, if the stored record differs.
	SaveIdentityCheck(ctx context.Context, against dbsim.TargetRecord, st dbsim.IdentityCheckState, audit AuditEntry) error
}

// Auditor writes an audit-log row SYNCHRONOUSLY and reports failure. It is used
// for rows that do not accompany a state change (refusals, failures); state
// changes carry their row into the store's transaction instead.
type Auditor interface {
	Log(e AuditEntry) error
}

// CheckRunner runs the check_readonly_identity probe on an agent for an already
// authorised target and returns the probe result. Nothing implements it in the
// product yet (the dispatch path is the open product run API item): with a nil
// Runner the check reports ErrIdentityCheckUnavailable.
type CheckRunner interface {
	RunIdentityCheck(ctx context.Context, t dbsim.Target) (dbsim.DBProbeResult, error)
}

// Service is the Admin logic. Settings and Targets are required for the
// corresponding methods; a missing one makes them fail closed.
type Service struct {
	Settings SettingsStore
	Targets  TargetStore
	Audit    Auditor
	Runner   CheckRunner
	Now      func() time.Time
}

const (
	settingsReadTimeout = 5 * time.Second
	checkRunExpiry      = 2 * time.Minute
)

func (s *Service) now() time.Time {
	if s.Now != nil {
		return s.Now().UTC()
	}
	return time.Now().UTC()
}

func entry(a Actor, action, resource string, detail map[string]any, outcome string) AuditEntry {
	return AuditEntry{ActorID: a.ID, Action: action, Resource: resource, Detail: detail, Outcome: outcome, IP: a.IP}
}

// audit writes a row that does not accompany a state change (a refusal or a
// failure). It is best effort: the caller is already returning an error.
func (s *Service) audit(a Actor, action, resource string, detail map[string]any, outcome string) {
	if s.Audit != nil {
		_ = s.Audit.Log(entry(a, action, resource, detail, outcome))
	}
}

func allowed(a Actor, p auth.Permission) bool { return a.ID != "" && auth.HasPermission(a.Role, p) }

// ---- client mode setting ----------------------------------------------------

// ClientModeEnabled reports the DB client mode setting, FAIL CLOSED: a nil
// service, a missing store, a read error, a timeout or any value other than the
// exact stored "true" is OFF.
func (s *Service) ClientModeEnabled() bool {
	if s == nil || s.Settings == nil {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), settingsReadTimeout)
	defer cancel()
	v, found, err := s.Settings.GetClientMode(ctx)
	return dbsim.ClientModeFromSetting(v, found, err)
}

// Gate returns the ClientModeGate to inject into dbsim.Authorize / dbbuild.
func (s *Service) Gate() dbsim.ClientModeGate { return dbsim.ClientGateFunc(s.ClientModeEnabled) }

// SetClientMode enables or disables DB client mode. Admin only; always audited.
func (s *Service) SetClientMode(ctx context.Context, a Actor, enabled bool) error {
	action := "dbsim.client_mode_disabled"
	if enabled {
		action = "dbsim.client_mode_enabled"
	}
	const resource = "dbsim:client-mode"
	if !allowed(a, auth.CanSetDBSimClientMode) {
		s.audit(a, action, resource, map[string]any{"enabled": enabled}, "denied")
		return ErrForbidden
	}
	if s.Settings == nil {
		s.audit(a, action, resource, map[string]any{"enabled": enabled, "error": "settings store unavailable"}, "error")
		return errors.New("dbsim: settings store unavailable")
	}
	if err := s.Settings.SetClientMode(ctx, enabled, a.ID, entry(a, action, resource, map[string]any{"enabled": enabled}, "ok")); err != nil {
		s.audit(a, action, resource, map[string]any{"enabled": enabled, "error": "store write failed"}, "error")
		return fmt.Errorf("dbsim: set client mode: %w", err)
	}
	return nil
}

// ---- target registry --------------------------------------------------------

func trunc(v string, n int) string {
	if len(v) > n {
		return v[:n]
	}
	return v
}

// RegisterTarget validates and stores a target with its expected identity. Admin
// only; audited. The record starts unverified.
func (s *Service) RegisterTarget(ctx context.Context, a Actor, reg dbsim.TargetRegistration) (dbsim.TargetRecord, error) {
	const action = "dbsim.target_registered"
	resource := "dbsim-target:" + trunc(reg.ID, 64)
	if !allowed(a, auth.CanManageDBSimTargets) {
		s.audit(a, action, resource, nil, "denied")
		return dbsim.TargetRecord{}, ErrForbidden
	}
	norm, err := reg.Normalize()
	if err != nil {
		// The message names the failed rule, never the rejected value.
		s.audit(a, action, resource, map[string]any{"error": err.Error()}, "error")
		return dbsim.TargetRecord{}, err
	}
	if s.Targets == nil {
		return dbsim.TargetRecord{}, errors.New("dbsim: target store unavailable")
	}
	rec := dbsim.TargetRecord{TargetRegistration: norm, CreatedBy: a.ID, CreatedAt: s.now()}
	ok := entry(a, action, "dbsim-target:"+norm.ID, map[string]any{
		"engine": norm.Engine, "mode": string(norm.Mode), "host": norm.Host, "port": norm.Port,
		"dbServerHost": norm.DBServerHost, "credentialRef": norm.CredentialRef,
		"expectedIdentity": norm.ExpectedIdentity, "labConfirmed": norm.LabConfirmed,
	}, "ok")
	if err := s.Targets.Create(ctx, rec, ok); err != nil {
		s.audit(a, action, resource, map[string]any{"error": "store rejected the registration"}, "error")
		return dbsim.TargetRecord{}, err
	}
	return rec, nil
}

// ListTargets returns every registered target (Analyst and Admin).
func (s *Service) ListTargets(ctx context.Context, a Actor) ([]dbsim.TargetRecord, error) {
	if !allowed(a, auth.CanViewDBSim) {
		return nil, ErrForbidden
	}
	if s.Targets == nil {
		return nil, errors.New("dbsim: target store unavailable")
	}
	return s.Targets.List(ctx)
}

// GetTarget returns one target (Analyst and Admin).
func (s *Service) GetTarget(ctx context.Context, a Actor, id string) (dbsim.TargetRecord, error) {
	if !allowed(a, auth.CanViewDBSim) {
		return dbsim.TargetRecord{}, ErrForbidden
	}
	if s.Targets == nil {
		return dbsim.TargetRecord{}, errors.New("dbsim: target store unavailable")
	}
	return s.Targets.Get(ctx, id)
}

// DeleteTarget removes a target (Admin only; audited).
func (s *Service) DeleteTarget(ctx context.Context, a Actor, id string) error {
	const action = "dbsim.target_deleted"
	resource := "dbsim-target:" + trunc(id, 64)
	if !allowed(a, auth.CanManageDBSimTargets) {
		s.audit(a, action, resource, nil, "denied")
		return ErrForbidden
	}
	if s.Targets == nil {
		return errors.New("dbsim: target store unavailable")
	}
	if err := s.Targets.Delete(ctx, id, entry(a, action, resource, nil, "ok")); err != nil {
		s.audit(a, action, resource, map[string]any{"error": "delete failed"}, "error")
		return err
	}
	return nil
}

// RunIdentityCheck runs the read-only identity check for a registered target
// and records the verdict with who and when. Admin only; audited.
//
// A check that does not pass for ANY reason (the account can write, a capability
// could not be observed, the run failed) records a failed check, which also
// withdraws an earlier pass: a target is verified only by its latest check. With
// no Runner configured nothing is recorded (ErrIdentityCheckUnavailable) and the
// target simply stays as it was.
func (s *Service) RunIdentityCheck(ctx context.Context, a Actor, id string) (dbsim.IdentityCheckResult, dbsim.TargetRecord, error) {
	const action = "dbsim.target_identity_checked"
	resource := "dbsim-target:" + trunc(id, 64)
	if !allowed(a, auth.CanManageDBSimTargets) {
		s.audit(a, action, resource, nil, "denied")
		return dbsim.IdentityCheckResult{}, dbsim.TargetRecord{}, ErrForbidden
	}
	if s.Targets == nil {
		return dbsim.IdentityCheckResult{}, dbsim.TargetRecord{}, errors.New("dbsim: target store unavailable")
	}
	rec, err := s.Targets.Get(ctx, id)
	if err != nil {
		return dbsim.IdentityCheckResult{}, dbsim.TargetRecord{}, err
	}
	t := rec.ToTarget()
	now := s.now()
	if err := dbsim.AuthorizeIdentityCheck(t, now, now.Add(checkRunExpiry)); err != nil {
		s.audit(a, action, resource, map[string]any{"error": err.Error()}, "error")
		return dbsim.IdentityCheckResult{}, rec, err
	}
	if s.Runner == nil {
		s.audit(a, action, resource, map[string]any{"error": ErrIdentityCheckUnavailable.Error()}, "error")
		return dbsim.IdentityCheckResult{}, rec, ErrIdentityCheckUnavailable
	}
	// The result is stored against the record version the probe ran against and
	// atomically with its audit row.
	against := rec
	record := func(st dbsim.IdentityCheckState, e AuditEntry) error {
		if err := s.Targets.SaveIdentityCheck(ctx, against, st, e); err != nil {
			return err
		}
		rec.IdentityCheck = st
		return nil
	}
	pr, err := s.Runner.RunIdentityCheck(ctx, t)
	if err != nil {
		reasons := []string{"the check could not be run"}
		failed := entry(a, action, resource, map[string]any{"passed": false, "error": "check could not be run"}, "error")
		if serr := record(dbsim.IdentityCheckState{Checked: true, At: now, By: a.ID, Reasons: reasons}, failed); serr != nil {
			s.audit(a, action, resource, map[string]any{"error": "check failed and the result could not be stored"}, "error")
			return dbsim.IdentityCheckResult{}, rec, errors.Join(err, serr)
		}
		return dbsim.IdentityCheckResult{Reasons: reasons}, rec, fmt.Errorf("dbsim: identity check run: %w", err)
	}
	verdict := dbsim.EvaluateReadOnlyIdentity(rec.Engine, pr)
	done := entry(a, action, resource, map[string]any{"passed": verdict.Passed, "reasons": verdict.Reasons}, "ok")
	if err := record(dbsim.IdentityCheckState{Checked: true, Passed: verdict.Passed, At: now, By: a.ID, Reasons: verdict.Reasons}, done); err != nil {
		s.audit(a, action, resource, map[string]any{"error": "result could not be stored"}, "error")
		return dbsim.IdentityCheckResult{Reasons: []string{"the result could not be stored"}}, rec, err
	}
	return verdict, rec, nil
}
