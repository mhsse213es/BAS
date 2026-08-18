package main

// EnrollRequest matches agent/types.go's EnrollRequest exactly -- this is
// the orchestrator's existing, unmodified /api/agents/enroll contract.
// PostureCatalog is intentionally omitted (nil): Phase 1 ships no posture
// checks, and the server already treats an absent/empty catalog as normal.
type EnrollRequest struct {
	AgentID      string `json:"agentId"`
	Hostname     string `json:"hostname"`
	IPAddress    string `json:"ipAddress"`
	OSVersion    string `json:"osVersion"`
	Username     string `json:"username"`
	EnvLabel     string `json:"envLabel"`
	BinaryHash   string `json:"binaryHash,omitempty"`
	AgentVersion string `json:"agentVersion,omitempty"`
}

type EnrollResponse struct {
	AgentID string     `json:"agentId"`
	State   string     `json:"state"`
	Policy  PolicyConf `json:"policy"`
	Trusted bool       `json:"trusted"`
}

type PolicyConf struct {
	LogLevel          string   `json:"logLevel"`
	AllowedScenarios  []string `json:"allowedScenarios"`
	ExecutionWindow   string   `json:"executionWindow"`
	MaxConcurrentRuns int      `json:"maxConcurrentRuns"`
	HeartbeatInterval int      `json:"heartbeatIntervalS"`
}

// Heartbeat matches agent/types.go's Heartbeat -- fields Phase 1 doesn't
// populate yet (SecurityProducts, CurrentJobID, JobProgress) are left at
// their zero value; all are `omitempty` server-side so this is a normal,
// well-formed heartbeat, not a degraded one.
type Heartbeat struct {
	AgentID      string `json:"agentId"`
	Hostname     string `json:"hostname"`
	IPAddress    string `json:"ipAddress"`
	OSVersion    string `json:"osVersion"`
	Username     string `json:"username"`
	Status       string `json:"status"`
	EnvLabel     string `json:"envLabel"`
	BinaryHash   string `json:"binaryHash,omitempty"`
	AgentVersion string `json:"agentVersion,omitempty"`
}

type HeartbeatResponse struct {
	State  string     `json:"state"`
	Policy PolicyConf `json:"policy"`
}
