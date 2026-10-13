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
	Provider  string `json:"provider"`           // "aws", "azure", "gcp"
	AccountID string `json:"accountId"`          // AWS account ID, Azure subscription ID, GCP project ID
	TenantID  string `json:"tenantId,omitempty"` // Azure tenant ID (if applicable)
	Region    string `json:"region,omitempty"`   // Optional: geographic scope
}

// Provenance tracks where an observation came from and its freshness
type Provenance struct {
	Source        string        `json:"source"`
	ObservedAt    time.Time     `json:"observedAt"`
	CollectionAge time.Duration `json:"collectionAge"`
	Confidence    string        `json:"confidence"`
	ErrorDetail   string        `json:"errorDetail,omitempty"`
}

// CloudResource represents a normalized cloud resource (S3 bucket, storage account, role, etc.)
type CloudResource struct {
	CanonicalID  string            `json:"canonicalId"`
	Kind         string            `json:"kind"`
	AccountScope *AccountScope     `json:"accountScope,omitempty"`
	DisplayName  string            `json:"displayName,omitempty"`
	Attributes   map[string]string `json:"attributes,omitempty"`
	Provenance   *Provenance       `json:"provenance,omitempty"`
}

// CloudIdentity represents a cloud principal (IAM user, role, service principal, etc.)
type CloudIdentity struct {
	CanonicalID  string            `json:"canonicalId"`
	Kind         string            `json:"kind"`
	AccountScope *AccountScope     `json:"accountScope,omitempty"`
	Attributes   map[string]string `json:"attributes,omitempty"`
	Provenance   *Provenance       `json:"provenance,omitempty"`
}

// Condition represents a prerequisite or constraint on authorization (IP restriction, MFA, etc.)
type Condition struct {
	Type        string `json:"type"`
	Value       string `json:"value"`
	EvaluatedAs string `json:"evaluatedAs"`
}

// CloudPermission represents an authorization edge from identity to resource
type CloudPermission struct {
	Source     *CloudIdentity    `json:"source"`
	Target     *CloudResource    `json:"target"`
	Action     string            `json:"action"`
	Conditions []*Condition      `json:"conditions,omitempty"`
	SourceType string            `json:"sourceType,omitempty"`
	Attributes map[string]string `json:"attributes,omitempty"`
	Provenance *Provenance       `json:"provenance,omitempty"`
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
	SearchStatus     string    // "success", "partial", "unavailable"
	SearchError      string    // Error detail if unavailable
	WindowStart      time.Time // Search window used
	WindowEnd        time.Time
	EventsSearched   int           // Total events examined
	MatchQuality     string        // "perfect", "partial", "delayed", "none"
	TelemetryDelay   time.Duration // Time from action to event logged
	MissingTelemetry []string      // ["mfa-challenge-events"] if partial
	Confidence       string        // "high", "medium", "low"
}
