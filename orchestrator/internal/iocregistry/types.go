package iocregistry

import "time"

type Type string

const (
	TypeFileHash    Type = "file_hash"
	TypeDomain      Type = "domain"
	TypeURL         Type = "url"
	TypeIP          Type = "ip"
	TypeRegistryKey Type = "registry_key"
	TypeMutex       Type = "mutex"
	TypeService     Type = "service"
	TypeProcess     Type = "process"
	TypeCommandLine Type = "command_line"
	TypeJA3         Type = "ja3"
	TypeUserAgent   Type = "user_agent"
	TypeEmail       Type = "email"
	TypeDNSRecord   Type = "dns_record"
	TypeCertificate Type = "certificate"
)

type Source string

const (
	SourceDetectionAlert Source = "detection_alert"
	SourceScenario       Source = "scenario"
	SourceVariant        Source = "variant"
	SourceManual         Source = "manual"
)

type Origin string

const (
	OriginBuiltIn    Origin = "built-in"
	OriginGenerated  Origin = "generated"
	OriginOpenAEV    Origin = "openaev"
	OriginMISP       Origin = "misp"
	OriginOpenCTI    Origin = "opencti"
	OriginManual     Origin = "manual"
	OriginThreatFeed Origin = "threat-feed"
	OriginCustomer   Origin = "customer"
)

// Status is the lifecycle state. Extraction from already-completed runs
// starts rows at Observed directly -- Draft/Generated/Assigned/Executed
// describe pre-execution stages that, for extracted data, already happened
// before this row existed.
type Status string

const (
	StatusDraft     Status = "draft"
	StatusGenerated Status = "generated"
	StatusAssigned  Status = "assigned"
	StatusExecuted  Status = "executed"
	StatusObserved  Status = "observed"
	StatusDetected  Status = "detected"
	StatusMissed    Status = "missed"
	StatusExpired   Status = "expired"
	StatusArchived  Status = "archived"
)

// IOC is the canonical model every producer (Detection Validation, Variant
// Engine, future Threat Intel imports, Purple Team, DLP validation, Attack
// Path) must emit -- never invent a parallel shape.
type IOC struct {
	ID    string
	Type  Type
	Value string

	Source Source
	Origin Origin

	FirstSeen time.Time
	LastSeen  time.Time

	ScenarioID string
	VariantID  string
	RunID      string
	AgentID    string

	Status   Status
	Metadata map[string]any
}
