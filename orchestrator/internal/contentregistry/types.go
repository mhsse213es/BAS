// Package contentregistry is the system of record for executable threat
// content and its lifecycle (TCF Phase 1). See
// docs/superpowers/specs/2026-10-04-tcf-phase1-content-registry-design.md.
package contentregistry

import (
	"errors"
	"fmt"
)

type Origin string

const (
	OriginVendor Origin = "VENDOR"
	OriginLocal  Origin = "LOCAL"
)

type Trust string

const (
	TrustVendorSigned Trust = "VENDOR_SIGNED"
	TrustLocalTrusted Trust = "LOCAL_TRUSTED"
	TrustUntrusted    Trust = "UNTRUSTED"
)

type Lifecycle string

const (
	LifecycleDraft          Lifecycle = "DRAFT"
	LifecycleValidating     Lifecycle = "VALIDATING"
	LifecycleValidated      Lifecycle = "VALIDATED"
	LifecycleApproved       Lifecycle = "APPROVED"
	LifecyclePublished      Lifecycle = "PUBLISHED"
	LifecyclePublishedLocal Lifecycle = "PUBLISHED_LOCAL"
	LifecycleRetired        Lifecycle = "RETIRED"
	LifecycleRejected       Lifecycle = "REJECTED"
)

type IntakeSource string

const (
	SourceBuiltin IntakeSource = "builtin"
	SourceCustom  IntakeSource = "custom"
	SourceIntel   IntakeSource = "intel"
)

// scenario_runs.execution_kind values (spec §4.8 + plan amendment 1).
const (
	KindContent               = "content"
	KindRemediation           = "remediation"
	KindTechniqueVerification = "technique_verification"
	KindVariant               = "variant"
	KindAdhocAdversary        = "adhoc_adversary"
	KindLegacy                = "legacy"
)

const (
	ActorIntake     = "intake"
	ActorGenerator  = "generator:connector"
	ActorMigration  = "migration:pre-registry"
	MigrationReason = "historical authorization: authored via operator UI before approval tracking existed; not reviewed during migration"
)

var (
	ErrOriginCollision = errors.New("content id already registered with a different origin")
	ErrVersionNotFound = errors.New("content version not found")
)

// ErrNotExecutable is the runtime gate's denial. Its Error() text is what
// operators see (409 body, scheduled-job failure, campaign skip reason).
type ErrNotExecutable struct {
	ContentID string
	Reason    string
}

func (e *ErrNotExecutable) Error() string {
	return fmt.Sprintf("content not executable: %s: %s", e.ContentID, e.Reason)
}

type ErrIllegalTransition struct {
	From, To Lifecycle
	Reason   string
}

func (e *ErrIllegalTransition) Error() string {
	return fmt.Sprintf("illegal lifecycle transition %s -> %s: %s", e.From, e.To, e.Reason)
}
