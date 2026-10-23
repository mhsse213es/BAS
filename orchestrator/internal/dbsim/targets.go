package dbsim

import (
	"context"
	"errors"
	"fmt"
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
	Mode                     ExecMode
	ExpectedIdentity         string
	ReadOnlyIdentityVerified bool
	LabConfirmed             bool // operator confirmed this is a lab target
}

// AuthInput carries the per-dispatch inputs to Authorize.
type AuthInput struct {
	ClientEnabled    bool      // Admin-enabled client mode (default off)
	MutationApproved bool      // scenario-level approval for non-read_only probes
	RunExpiry        time.Time // required; zero is refused
	Now              time.Time // zero means time.Now()
}

// Authorize is the orchestrator-side gate (spec section 8, R4, R6, R8). It
// runs before a probe is dispatched.
//
// The probe must exist in the registry (the only source of a probe's class)
// and the entry must agree with it. A run with no expiry, or one expiring at
// or before now, is refused. Every target needs a registered identity. Client
// mode needs ClientEnabled, a verified read-only identity and a read_only
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
	if t.ExpectedIdentity == "" {
		return fmt.Errorf("dbsim: authorize: target %q has no pre-registered identity", t.ID)
	}
	// A fixture-aware probe reads a per-run seeded fixture, which exists only in
	// lab mode: refused for any other mode whatever its class says.
	if real.FixtureParam != "" && t.Mode != ModeLab {
		return fmt.Errorf("dbsim: authorize: fixture-aware probe %q is lab-only (target mode %q)", def.ID, t.Mode)
	}
	switch t.Mode {
	case ModeLab:
		if class != ClassReadOnly {
			if !t.LabConfirmed {
				return fmt.Errorf("dbsim: authorize: %s probe %q requires a confirmed lab target", class, def.ID)
			}
			if !in.MutationApproved {
				return fmt.Errorf("dbsim: authorize: %s probe %q requires scenario mutation approval", class, def.ID)
			}
		}
	case ModeClient:
		if !in.ClientEnabled {
			return fmt.Errorf("dbsim: authorize: client mode is disabled")
		}
		if !t.ReadOnlyIdentityVerified {
			return fmt.Errorf("dbsim: authorize: client target %q read-only identity not verified", t.ID)
		}
		if class != ClassReadOnly {
			return fmt.Errorf("dbsim: authorize: client mode refuses %s probe %q", class, def.ID)
		}
	default:
		return fmt.Errorf("dbsim: authorize: invalid mode %q", t.Mode)
	}
	return nil
}
