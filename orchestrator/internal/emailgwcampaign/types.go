// Package emailgwcampaign holds the pure types for a Level-1 EmailGW
// Mastery campaign: a named, ordered sequence of stages where stage
// N+1 dispatches only when stage N's own real recorded VerdictDetail
// satisfies a declared gate. See
// docs/superpowers/specs/2026-10-16-emailgw-mastery-campaign-stage-execution-design.md
// for the full design and the rejected alternative (reusing
// internal/exercise's PlanStep engine, blocked by a hard import
// cycle and by that package's unrelated phishing-awareness domain).
//
// Like internal/emailgwrun, this package holds only types and static
// templates -- the orchestration logic that calls into
// emailgwefficacy/db lives in internal/api, for the same import-cycle
// reason internal/emailgwrun's own executor does. Deliberately imports
// NEITHER emailgwefficacy NOR exercise: internal/db imports this
// package (for the email_gw_campaigns/email_gw_campaign_stages store),
// and emailgwefficacy already imports exercise (for
// SpoofableSMTPInjector) -- importing emailgwefficacy here would
// recreate exactly the db -> ... -> exercise -> (test-only) testutil
// -> db cycle internal/emailgwrun's own executor placement already
// works around. GateCondition.PermittedVerdicts therefore holds raw
// strings matching emailgwefficacy.EmailGWVerdict's own string values
// (e.g. "confirmed-failure"), not that type itself; EvidenceDetail
// (which does need to decode an EfficacyResult) lives in internal/api
// instead, where that import is already safe.
package emailgwcampaign

import "time"

// CampaignStatus is an email_gw_campaigns.status value.
type CampaignStatus string

const (
	CampaignRunning    CampaignStatus = "running"
	CampaignCompleted  CampaignStatus = "completed"
	CampaignPartial    CampaignStatus = "partial"
	CampaignFailed     CampaignStatus = "failed"
	CampaignCancelling CampaignStatus = "cancelling"
	CampaignCancelled  CampaignStatus = "cancelled"
)

// StageStatus is an email_gw_campaign_stages.status value.
//
// StageCompleted means this stage genuinely executed (StageKindInjected:
// its underlying email_gw_runs row reached a terminal status) or
// genuinely derived a result (StageKindDerived: it read an upstream
// stage's own dimension) -- never "passed". The real verdict lives on
// the stage's own run (when non-nil) or, for a derived stage, on the
// upstream run it read from. StageBlockedByPrerequisite is the
// non-fabrication guarantee: a stage in this state has RunID == nil,
// always -- there is nothing to query, nothing that could be mistaken
// for an executed result.
type StageStatus string

const (
	StagePending               StageStatus = "pending"
	StageDispatched            StageStatus = "dispatched"
	StageCompleted             StageStatus = "completed"
	StageBlockedByPrerequisite StageStatus = "blocked_by_prerequisite"
	StageFailed                StageStatus = "failed"
	StageCancelled             StageStatus = "cancelled"
)

// StageKind distinguishes a stage that dispatches a real, independent
// emailgwrun from one that only reads a dimension an earlier stage's
// own run already collected.
type StageKind string

const (
	StageKindInjected StageKind = "injected"
	StageKindDerived  StageKind = "derived"
)

// Dimension names one of EfficacyResult's three independently-scored
// dimensions -- the only vocabulary a gate or a derived stage may
// reference.
type Dimension string

const (
	DimensionPrevention Dimension = "prevention"
	DimensionDetection  Dimension = "detection"
	DimensionResponse   Dimension = "response"
)

// GateCondition decides, from an upstream stage's own real recorded
// VerdictDetail for UpstreamDimension, whether a downstream stage may
// dispatch. Any verdict not in PermittedVerdicts blocks -- including
// VerdictInconclusive and the case where the upstream stage never ran
// at all -- each via its own distinct, explicitly reasoned branch (see
// EvaluateGate), never a single undifferentiated check.
type GateCondition struct {
	UpstreamStageKey  string    `json:"upstreamStageKey"`
	UpstreamDimension Dimension `json:"upstreamDimension"`
	// PermittedVerdicts holds raw strings matching
	// emailgwefficacy.EmailGWVerdict's own values -- see the package
	// comment for why this package can't import that type directly.
	PermittedVerdicts []string `json:"permittedVerdicts"`
}

// StageTemplate is one planned step in a CampaignTemplate.
type StageTemplate struct {
	Key   string    `json:"key"`
	Label string    `json:"label"`
	Kind  StageKind `json:"kind"`

	// StageKindInjected only: resolved via emailgwefficacy.ExpectationByID.
	ExpectationID string `json:"expectationId,omitempty"`

	// StageKindDerived only: which earlier stage's own dimension this
	// stage reads, with no new injection.
	ReadsFromStageKey string    `json:"readsFromStageKey,omitempty"`
	ReadsDimension    Dimension `json:"readsDimension,omitempty"`

	// Gate is nil for a campaign's first stage (nothing to gate on) and
	// for every derived stage (a derived stage's own fate cascades
	// directly from the stage it reads, not from a separately-evaluated
	// gate -- see the executor's own cascade logic).
	Gate *GateCondition `json:"gate,omitempty"`
}

// CampaignTemplate is a reusable, Go-defined campaign blueprint --
// static, like emailgwefficacy's own scenario registry, not
// DB-authored or user-editable in this pass.
type CampaignTemplate struct {
	ID     string          `json:"id"`
	Name   string          `json:"name"`
	Stages []StageTemplate `json:"stages"` // ordered; ordinal = index
}

// Campaign is one live run of a CampaignTemplate.
type Campaign struct {
	ID          string         `json:"id"`
	TemplateID  string         `json:"templateId"`
	Status      CampaignStatus `json:"status"`
	InitiatedBy string         `json:"initiatedBy,omitempty"`
	CreatedAt   time.Time      `json:"createdAt"`
	CompletedAt *time.Time     `json:"completedAt,omitempty"`
}

// CampaignStage is the runtime record of one StageTemplate within one
// Campaign. RunID is nil until a StageKindInjected stage actually
// dispatches, and permanently nil for StageBlockedByPrerequisite,
// StageCancelled, and every StageKindDerived stage (a derived stage
// has no run of its own -- ReadsFromRunID, resolved at read time from
// ReadsFromStageKey, is where its evidence lives).
type CampaignStage struct {
	ID            string      `json:"id"`
	CampaignID    string      `json:"campaignId"`
	Ordinal       int         `json:"ordinal"`
	StageKey      string      `json:"stageKey"`
	RunID         *string     `json:"runId,omitempty"`
	Status        StageStatus `json:"status"`
	BlockedReason string      `json:"blockedReason,omitempty"`
	CreatedAt     time.Time   `json:"createdAt"`
	CompletedAt   *time.Time  `json:"completedAt,omitempty"`
}
