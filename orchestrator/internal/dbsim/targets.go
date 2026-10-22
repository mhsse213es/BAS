package dbsim

import (
	"fmt"
	"time"
)

// Target is a pre-registered database target. ExpectedIdentity is the PG
// system_identifier / MySQL server_uuid recorded at registration.
type Target struct {
	ID                       string
	Engine                   string
	Host                     string
	Port                     int
	Mode                     ExecMode
	ExpectedIdentity         string
	ReadOnlyIdentityVerified bool
}

// now is overridable in tests.
var now = time.Now

// Authorize is the orchestrator-side gate (spec section 8, R4, R6, R8). It
// runs before a probe is dispatched.
//
// The probe's class is taken from the registry for def.ID, never from the
// scenario label; an entry that disagrees with the registry is refused. Client
// mode requires clientEnabled, a pre-registered identity (no trust on first
// use), a verified read-only identity, and a read_only probe. A run with no
// expiry, or an expired one, is refused.
func Authorize(t Target, def ProbeRegistryEntry, clientEnabled bool, runExpiry time.Time) error {
	if runExpiry.IsZero() {
		return fmt.Errorf("dbsim: authorize: run has no expiry")
	}
	if !now().Before(runExpiry) {
		return fmt.Errorf("dbsim: authorize: run expired")
	}
	class := def.Class
	if real, ok := LookupProbeEntry(def.ID); ok {
		if real.Class != def.Class {
			return fmt.Errorf("dbsim: authorize: probe %q entry class %q disagrees with registry class %q",
				def.ID, def.Class, real.Class)
		}
		class = real.Class
	}
	supported := false
	for _, e := range def.Engines {
		if e == t.Engine {
			supported = true
		}
	}
	if !supported {
		return fmt.Errorf("dbsim: authorize: probe %q does not support engine %q", def.ID, t.Engine)
	}
	switch t.Mode {
	case ModeLab:
	case ModeClient:
		if !clientEnabled {
			return fmt.Errorf("dbsim: authorize: client mode is disabled")
		}
		if t.ExpectedIdentity == "" {
			return fmt.Errorf("dbsim: authorize: client target %q has no pre-registered identity", t.ID)
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
