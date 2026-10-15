package regobligation

import "time"

// ObligationType distinguishes mandatory obligations from guidance,
// contractual, and recommended ones -- network.txt §3 requires this
// distinction be enforced, not merely documented.
type ObligationType string

const (
	ObligationMandatory   ObligationType = "mandatory"
	ObligationGuidance    ObligationType = "guidance"
	ObligationContractual ObligationType = "contractual"
	ObligationRecommended ObligationType = "recommended"
)

const MaxControlMappingsPerObligation = 50

// ControlMapping names what Network BAS capability would evidence this
// obligation. CapabilityName is a plain string tag (e.g.
// "zoneisolation.isolation-check") -- never an imported type, since this
// package has zero Go dependency on any Phase 1-6B package.
type ControlMapping struct {
	CanonicalID    string `json:"canonicalId"`
	ControlName    string `json:"controlName"`
	CapabilityName string `json:"capabilityName"`
	Note           string `json:"note,omitempty"`
}

// Obligation is one regulatory requirement -- catalog metadata,
// individually CRUD'd and versioned, never bundled into a batch
// "import" the way otsafety/zoneisolation imports are, since
// obligations evolve independently of each other.
type Obligation struct {
	ID              string           `json:"id,omitempty"`
	Jurisdiction    string           `json:"jurisdiction"`
	Regulator       string           `json:"regulator"`
	Sector          string           `json:"sector,omitempty"`
	EntityType      string           `json:"entityType,omitempty"`
	Title           string           `json:"title"`
	Description     string           `json:"description,omitempty"`
	ObligationType  ObligationType   `json:"obligationType"`
	SourceReference string           `json:"sourceReference"`
	EffectiveDate   time.Time        `json:"effectiveDate"`
	Version         string           `json:"version"`
	ControlMappings []ControlMapping `json:"controlMappings"`
	CreatedBy       string           `json:"createdBy,omitempty"`
	CreatedAt       time.Time        `json:"createdAt,omitempty"`
}

type SnapshotStatus string

const (
	SnapshotCaptured   SnapshotStatus = "captured"
	SnapshotIncomplete SnapshotStatus = "incomplete"
)

const CurrentSnapshotSchemaVersion = "1"

// EvidenceSnapshot is an immutable, point-in-time capture of a Network
// BAS check's output, submitted by an operator who already ran that
// check themselves. It is explicitly NOT a persisted execution run of
// the check itself -- isolation-checks, remote-access-path checks,
// network-path checks, and cloud-path checks are all deliberately
// ephemeral (computed fresh, never persisted) -- this snapshot exists
// so this phase has something durable and auditable to point at,
// without this package calling into any of them itself.
//
// Labeled a captured assessment, never implying the underlying check
// was independently rerun or that the snapshot proves the CURRENT state
// of anything -- only the state at CapturedAt.
type EvidenceSnapshot struct {
	ID                  string            `json:"id,omitempty"`
	SchemaVersion       string            `json:"schemaVersion,omitempty"`
	ObligationID        string            `json:"obligationId"`
	ControlMappingID    string            `json:"controlMappingId"`
	ObligationVersion   string            `json:"obligationVersion,omitempty"`
	CapabilityName      string            `json:"capabilityName"`
	ImportReferences    map[string]string `json:"importReferences,omitempty"`
	QueryParameters     map[string]any    `json:"queryParameters,omitempty"`
	CapturedOutcome     string            `json:"capturedOutcome,omitempty"`
	CapturedConfidence  string            `json:"capturedConfidence,omitempty"`
	CapturedLimitations string            `json:"capturedLimitations,omitempty"`
	Status              SnapshotStatus    `json:"status"`
	IncompleteReason    string            `json:"incompleteReason,omitempty"`
	CapturedBy          string            `json:"capturedBy,omitempty"`
	CapturedAt          time.Time         `json:"capturedAt,omitempty"`
	Note                string            `json:"note,omitempty"`
}
