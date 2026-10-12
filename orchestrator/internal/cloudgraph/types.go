package cloudgraph

import "time"

// PathState represents the authorization state of a cloud permission path
type PathState string

const (
	Candidate              PathState = "candidate"
	ConditionallyReachable PathState = "conditionally_reachable"
	PolicySupported        PathState = "policy_supported"
	Observed               PathState = "observed"
	Blocked                PathState = "blocked"
	Unknown                PathState = "unknown"
)

// AccountScope identifies the cloud account/subscription/project owning a resource
type AccountScope struct {
	Provider   string // "aws", "azure", "gcp"
	AccountID  string // AWS account ID, Azure subscription ID, GCP project ID
	TenantID   string // Azure tenant ID (if applicable)
	Region     string // Optional: geographic scope
}

// Provenance tracks where an observation came from and its freshness
type Provenance struct {
	Source        string        // "aws:iam-list-policies", "azure:graph-api", "cached-inventory"
	ObservedAt    time.Time     // When this was observed
	CollectionAge time.Duration // How stale is this observation
	Confidence    string        // "observed", "inferred", "cached"
	ErrorDetail   string        // If collection failed, what went wrong
}

// CloudResource represents a normalized cloud resource (S3 bucket, storage account, role, etc.)
type CloudResource struct {
	CanonicalID   string              // Provider ARN or resource path (not synthetic)
	Kind          string              // "s3-bucket", "storage-account", "iam-role", etc.
	AccountScope  *AccountScope       // Owner account/subscription/project
	DisplayName   string              // User-visible name
	Attributes    map[string]string   // Provider-specific metadata
	Provenance    *Provenance         // Discovery source, freshness, confidence
}

// CloudIdentity represents a cloud principal (IAM user, role, service principal, etc.)
type CloudIdentity struct {
	CanonicalID string            // Provider ARN or identity path
	Kind        string            // "iam-user", "iam-role", "service-principal", "managed-identity"
	AccountScope *AccountScope    // Owner account/subscription/project
	Attributes  map[string]string // MFA enabled, last-used, etc.
	Provenance  *Provenance       // Discovery source, freshness
}

// Condition represents a prerequisite or constraint on authorization (IP restriction, MFA, etc.)
type Condition struct {
	Type          string // "ip-address", "mfa-required", "time-based", etc.
	Value         string // Condition value
	EvaluatedAs   string // "satisfied", "unsatisfied", "unknown"
}

// CloudPermission represents an authorization edge from identity to resource
type CloudPermission struct {
	Source         *CloudIdentity    // Who has the permission
	Target         *CloudResource    // What they can access
	Action         string            // "sts:AssumeRole", "s3:GetObject", etc.
	Conditions     []*Condition      // Authorization conditions
	SourceType     string            // "identity-policy", "resource-policy", "org-scp", "role-trust"
	Attributes     map[string]string // Raw policy document and other evaluator inputs
	Provenance     *Provenance       // Collection source
}

// RequestContext provides request-time information (IP, principal, timestamp)
type RequestContext struct {
	PrincipalArn     string
	SourceIP         string
	Timestamp        time.Time
	MFAAuthenticated bool
}

// EvaluationResult represents authorization evaluation outcome
type EvaluationResult struct {
	State             PathState // Blocked, PolicySupported, ConditionallyReachable, Unknown
	AllowedBy         string    // "identity-policy", "resource-policy", "org-scp", "role-trust", "explicit-deny"
	BlockedBy         string    // "explicit-deny", "implicit-deny", "condition-unmet", "missing-permission"
	UnresolvedConds   []string  // ["ip-restriction", "mfa-required"] if ConditionallyReachable
	EvaluationMethod  string    // "iam-simulator", "hand-coded-rules", "synthetic"
	MatchedStatements []int     // Statement indices in policy that matched
	MatchedConditions []string  // Condition names that were satisfied
}

// CloudEvent represents an audit log entry (CloudTrail, Activity Log, etc.)
type CloudEvent struct {
	Principal    string    // IAM ARN or Entra principal
	Action       string    // API action (e.g., sts:AssumeRole, s3:GetObject)
	Resource     string    // Resource ARN
	Timestamp    time.Time // When the action occurred
	Result       string    // "Success", "Failure", "MFAChallenge"
	Source       string    // "cloudtrail", "activity-log", "s3-access-logs"
	SessionToken string    // Session ID for correlation
	SourceIP     string    // Caller IP
	UserAgent    string    // API caller
}

// EventSearchResult represents findings from a CloudTrail/audit log query
type EventSearchResult struct {
	EventsFound      []*CloudEvent
	SearchStatus     string        // "success", "partial", "unavailable"
	SearchError      string        // Error detail if unavailable
	WindowStart      time.Time     // Search window used
	WindowEnd        time.Time
	EventsSearched   int           // Total events examined
	MatchQuality     string        // "perfect", "partial", "delayed", "none"
	TelemetryDelay   time.Duration // Time from action to event logged
	MissingTelemetry []string      // ["mfa-challenge-events"] if partial
	Confidence       string        // "high", "medium", "low"
}
