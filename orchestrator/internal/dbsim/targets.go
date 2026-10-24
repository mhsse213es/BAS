package dbsim

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
)

// ErrTargetNotFound is returned by a TargetResolver for an unregistered id.
var ErrTargetNotFound = errors.New("dbsim: target not registered")

// TargetResolver is the only source of a target's connection details,
// identity, mode and trust flags (Host, Port, ExpectedIdentity, Mode,
// LabConfirmed, CredentialRef, ReadOnlyIdentityVerified). A scenario names a
// target by id only; nothing from scenario YAML or request input may populate
// these fields. The persistent registry arrives with the target-management
// task; MemoryResolver serves tests and lab configuration.
type TargetResolver interface {
	Resolve(ctx context.Context, id string) (Target, error)
}

// MemoryResolver is an in-memory TargetResolver.
type MemoryResolver struct {
	targets map[string]Target
}

// NewMemoryResolver registers the given targets by ID.
func NewMemoryResolver(ts ...Target) *MemoryResolver {
	m := &MemoryResolver{targets: make(map[string]Target, len(ts))}
	for _, t := range ts {
		m.targets[t.ID] = t
	}
	return m
}

// Resolve returns the registered target or ErrTargetNotFound.
func (m *MemoryResolver) Resolve(ctx context.Context, id string) (Target, error) {
	if err := ctx.Err(); err != nil {
		return Target{}, err
	}
	t, ok := m.targets[id]
	if !ok {
		return Target{}, fmt.Errorf("%w: %q", ErrTargetNotFound, id)
	}
	return t, nil
}

// Target is a pre-registered database target. ExpectedIdentity is the PG
// system_identifier / MySQL server_uuid recorded at registration.
type Target struct {
	ID                       string
	Engine                   string
	Host                     string
	Port                     int
	Database                 string
	TLSMode                  string
	CredentialRef            string // opaque "dbcred:<name>" reference, never a secret
	AgentID                  string // the agent next to the database; empty (legacy target) never runs
	Mode                     ExecMode
	ExpectedIdentity         string
	ReadOnlyIdentityVerified bool
	LabConfirmed             bool // operator confirmed this is a lab target
}

// ClientModeGate answers the one question the release gate (spec R8) asks of
// the platform settings: is the Admin "DB client mode" setting enabled? The
// implementation lives outside this package (the API layer reads the settings
// store) so internal/dbsim imports no API or database code. An implementation
// must answer false when the setting is missing or cannot be read.
type ClientModeGate interface {
	ClientModeEnabled() bool
}

// ClientGateFunc adapts a function to ClientModeGate.
type ClientGateFunc func() bool

// ClientModeEnabled implements ClientModeGate.
func (f ClientGateFunc) ClientModeEnabled() bool { return f() }

// StaticClientGate is a fixed gate (tests and fixed configuration).
func StaticClientGate(on bool) ClientModeGate { return ClientGateFunc(func() bool { return on }) }

// clientModeOn reads the gate fail closed: nil gate, or a gate that panics,
// is OFF.
func clientModeOn(g ClientModeGate) (on bool) {
	if g == nil {
		return false
	}
	defer func() {
		if recover() != nil {
			on = false
		}
	}()
	return g.ClientModeEnabled()
}

// AuthInput carries the per-dispatch inputs to Authorize.
type AuthInput struct {
	// ClientGate reports the Admin-enabled client mode setting (default off).
	// Nil means off: client mode is refused (fail closed).
	ClientGate       ClientModeGate
	MutationApproved bool // scenario-level approval for non-read_only probes
	// Fixture is true when the step names a fixture. A run that seeds a fixture
	// mutates the lab database, so it is gated as a mutation whatever the
	// probe's class is (R-AI).
	Fixture   bool
	RunExpiry time.Time // required; zero is refused
	Now       time.Time // zero means time.Now()
}

// Authorize is the orchestrator-side gate (spec section 8, R4, R6, R8). It
// runs before a probe is dispatched.
//
// The probe must exist in the registry (the only source of a probe's class)
// and the entry must agree with it. A run with no expiry, or one expiring at
// or before now, is refused. Every target needs a registered identity. Client
// mode (release gate R8) needs all of: the ClientGate setting on, a target
// registered with a PASSED read-only identity check, an expected identity
// supplied at registration (R6, never trust on first use) and a read_only
// probe. Lab mode runs read_only probes on identity alone; any other class
// also needs Target.LabConfirmed and AuthInput.MutationApproved.
func Authorize(t Target, def ProbeRegistryEntry, in AuthInput) error {
	if in.RunExpiry.IsZero() {
		return fmt.Errorf("dbsim: authorize: run has no expiry")
	}
	now := in.Now
	if now.IsZero() {
		now = time.Now()
	}
	if !now.Before(in.RunExpiry) {
		return fmt.Errorf("dbsim: authorize: run expired")
	}
	real, ok := LookupProbeEntry(def.ID)
	if !ok {
		return fmt.Errorf("dbsim: authorize: unknown probe %q", def.ID)
	}
	if real.Class != def.Class {
		return fmt.Errorf("dbsim: authorize: probe %q entry class %q disagrees with registry class %q",
			def.ID, def.Class, real.Class)
	}
	class := real.Class
	supported := false
	for _, e := range real.Engines {
		if e == t.Engine {
			supported = true
		}
	}
	if !supported {
		return fmt.Errorf("dbsim: authorize: probe %q does not support engine %q", def.ID, t.Engine)
	}
	if strings.TrimSpace(t.ExpectedIdentity) == "" {
		return fmt.Errorf("dbsim: authorize: target %q has no pre-registered identity", t.ID)
	}
	if !reAgentID.MatchString(t.AgentID) {
		return fmt.Errorf("dbsim: authorize: target %q is not bound to an agent (re-register it)", t.ID)
	}
	// A fixture-aware probe reads a per-run seeded fixture, which exists only in
	// lab mode: refused for any other mode whatever its class says.
	fixtureAware := real.FixtureParam != "" || real.RequiredFixture != ""
	if (fixtureAware || real.LabOnly) && t.Mode != ModeLab {
		return fmt.Errorf("dbsim: authorize: probe %q is lab-only (target mode %q)", def.ID, t.Mode)
	}
	switch t.Mode {
	case ModeLab:
		// A LabOnly probe (DB-11) is read_only but needs the same lab approvals.
		if class != ClassReadOnly || in.Fixture || fixtureAware || real.LabOnly {
			if !t.LabConfirmed {
				return fmt.Errorf("dbsim: authorize: %s probe %q requires a confirmed lab target", class, def.ID)
			}
			if !in.MutationApproved {
				return fmt.Errorf("dbsim: authorize: %s probe %q requires scenario mutation approval", class, def.ID)
			}
		}
	case ModeClient:
		if !clientModeOn(in.ClientGate) {
			return fmt.Errorf("dbsim: authorize: client mode is disabled")
		}
		if !t.ReadOnlyIdentityVerified {
			return fmt.Errorf("dbsim: authorize: client target %q read-only identity not verified", t.ID)
		}
		if class != ClassReadOnly || in.Fixture {
			return fmt.Errorf("dbsim: authorize: client mode refuses %s probe %q", class, def.ID)
		}
	default:
		return fmt.Errorf("dbsim: authorize: invalid mode %q", t.Mode)
	}
	return nil
}
