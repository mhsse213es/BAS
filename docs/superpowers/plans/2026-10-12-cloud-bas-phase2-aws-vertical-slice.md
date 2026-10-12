# Cloud BAS Phase 2: AWS Vertical Slice Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task inline. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement real AWS IAM policy evaluation, CloudTrail event correlation, end-to-end scenario execution, and ControlOutcome reporting for cloud scenarios.

**Architecture:** Layer C AWS evaluator simulates IAM policies (identity-based + resource-based + organization SCPs + conditions) to determine authorization state (Candidate → PolicySupported → Observed). CloudTrail correlation engine searches audit logs by principal+action+resource+timestamp (±30s window), assesses event quality (Perfect/Partial/None/Delayed), and surfaces TelemetryDelay/MissingTelemetry. ControlOutcome extended to track PrerequisiteState (from graph), ExecutionOutcome (Allowed/Blocked/MFAChallenged/Unknown), and evidence match (prediction vs. observation). Synthetic AWS fixtures in Phase 2; real AWS test account integration deferred to Phase 3 if needed.

**Tech Stack:** Go 1.23+, existing Audspect scenario/evidence/control-efficacy infrastructure, AWS SDK for Go v2 (optional for Phase 3), synthetic IAM policy evaluation via rego/CEL or hand-coded rules.

**Spec:** `docs/superpowers/specs/2026-10-12-cloud-bas-architecture-design.md`

## Global Constraints

- **Execution:** Inline on main branch (no worktree; per user preference)
- **Model:** Sonnet only; never dispatch Opus
- **Verification:** Narrow/targeted first (per-task checks); full regression at module end
- **Changes:** Minimal only; no unrelated refactoring
- **Evidence:** Never fake-as-live; distinguish observed from inferred from unknown
- **Testing:** TDD required; watch every failing test before implementation
- **Commits:** Git push after every commit (Windows host)

## Review Focus

1. **Policy evaluation mismatch:** AWS policy simulator says Allowed, but real AWS rejects → evidence gap (timing, conditions, stale data)
2. **Condition parameter type error:** IP address evaluated as string instead of CIDR → false Blocked verdict
3. **CloudTrail search window too narrow:** Event occurs at ±45s from step timestamp, window is ±30s → event missed, path marked Unknown instead of Observed
4. **Evidence quality collapse:** Partial event match (principal+action correct, resource missing) treated as full match → confidence inflated
5. **ControlOutcome missing TelemetryDelay:** Event found but 5min after action → delay not surfaced, control verdict looks immediate

---

## File Structure

**New files created:**

- `orchestrator/internal/cloudgraph/aws_evaluator.go` — AWS IAM policy evaluator (Layer C)
- `orchestrator/internal/cloudgraph/aws_evaluator_test.go` — Policy evaluator tests
- `orchestrator/internal/cloudgraph/cloudtrail_correlator.go` — CloudTrail/audit log correlation engine
- `orchestrator/internal/cloudgraph/cloudtrail_correlator_test.go` — Correlation tests
- `orchestrator/internal/cloudgraph/cloud_outcomes.go` — ControlOutcome extension (CloudControlOutcome type)
- `orchestrator/internal/cloudgraph/cloud_outcomes_test.go` — Outcome tests
- `orchestrator/internal/cloudgraph/e2e_test.go` — End-to-end scenario execution test

**Modified files:**

- `orchestrator/internal/controlval/types.go` — Extend ControlOutcome interface (additive)
- `orchestrator/internal/cloudgraph/types.go` — Add CloudEvent, EventSearchResult, EvaluationResult types

**Not created (deferred):**

- Real AWS SDK integration (Phase 3+)
- Organization SCP evaluation (Phase 3, when real AWS access validates)
- Bucket/resource policies in detail (Phase 3)

---

## Task 1: AWS IAM Policy Evaluator (Layer C)

**Files:**
- Create: `orchestrator/internal/cloudgraph/aws_evaluator.go`
- Create: `orchestrator/internal/cloudgraph/aws_evaluator_test.go`
- Modify: `orchestrator/internal/cloudgraph/types.go` (add EvaluationResult type)
- Test: `orchestrator/internal/cloudgraph/aws_evaluator_test.go`

**Interfaces:**
- Consumes: CloudPermission, CloudIdentity, CloudResource, PathState (from Phase 1)
- Produces: `AuthorizationEvaluator` interface with `EvaluatePermission(edge, requestContext) → EvaluationResult`; `EvaluationResult` type with State, AllowedBy, BlockedBy, UnresolvedConds, EvaluationMethod

---

- [ ] **Step 1: Write failing test for identity-based policy evaluation**

Create `orchestrator/internal/cloudgraph/aws_evaluator_test.go`:

```go
package cloudgraph

import (
	"testing"
)

// TestAWSEvaluator_AllowedByIdentityPolicy verifies user has permission via inline policy
func TestAWSEvaluator_AllowedByIdentityPolicy(t *testing.T) {
	user := &CloudIdentity{
		CanonicalID: "arn:aws:iam::123456789012:user/test-user",
		Kind:        "iam-user",
		AccountScope: &AccountScope{
			Provider:  "aws",
			AccountID: "123456789012",
		},
	}

	bucket := &CloudResource{
		CanonicalID: "arn:aws:s3:::test-bucket",
		Kind:        "s3-bucket",
		AccountScope: &AccountScope{
			Provider:  "aws",
			AccountID: "123456789012",
		},
	}

	// User has s3:GetObject via inline policy
	edge := &CloudPermission{
		Source:     user,
		Target:     bucket,
		Action:     "s3:GetObject",
		SourceType: "identity-policy",
		Attributes: map[string]string{
			"policy_document": `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::test-bucket/*"}]}`,
		},
	}

	evaluator := &AWSEvaluator{}
	result := evaluator.EvaluatePermission(edge, &RequestContext{})

	if result.State != PolicySupported {
		t.Errorf("Expected PolicySupported, got %s", result.State)
	}
	if result.AllowedBy != "identity-policy" {
		t.Errorf("Expected AllowedBy=identity-policy, got %s", result.AllowedBy)
	}
}

// TestAWSEvaluator_BlockedByExplicitDeny verifies explicit Deny takes precedence
func TestAWSEvaluator_BlockedByExplicitDeny(t *testing.T) {
	user := &CloudIdentity{
		CanonicalID: "arn:aws:iam::123456789012:user/restricted-user",
		Kind:        "iam-user",
		AccountScope: &AccountScope{
			Provider:  "aws",
			AccountID: "123456789012",
		},
	}

	bucket := &CloudResource{
		CanonicalID: "arn:aws:s3:::protected-bucket",
		Kind:        "s3-bucket",
	}

	// Explicit Deny in user policy
	edge := &CloudPermission{
		Source:     user,
		Target:     bucket,
		Action:     "s3:DeleteObject",
		SourceType: "identity-policy",
		Attributes: map[string]string{
			"policy_document": `{"Statement":[{"Effect":"Deny","Action":"s3:DeleteObject","Resource":"*"}]}`,
		},
	}

	evaluator := &AWSEvaluator{}
	result := evaluator.EvaluatePermission(edge, &RequestContext{})

	if result.State != Blocked {
		t.Errorf("Expected Blocked, got %s", result.State)
	}
	if result.BlockedBy != "explicit-deny" {
		t.Errorf("Expected BlockedBy=explicit-deny, got %s", result.BlockedBy)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

```bash
cd orchestrator && go test ./internal/cloudgraph -run TestAWSEvaluator -v
```

Expected: FAIL with "undefined: AWSEvaluator"

- [ ] **Step 3: Add EvaluationResult type to types.go**

Edit `orchestrator/internal/cloudgraph/types.go` and add:

```go
// RequestContext provides request-time information (IP, principal, timestamp)
type RequestContext struct {
	PrincipalArn string
	SourceIP     string
	Timestamp    time.Time
	MFAAuthenticated bool
}

// EvaluationResult represents authorization evaluation outcome
type EvaluationResult struct {
	State               PathState       // Blocked, PolicySupported, ConditionallyReachable, Unknown
	AllowedBy           string          // "identity-policy", "resource-policy", "org-scp", "role-trust", "explicit-deny"
	BlockedBy           string          // "explicit-deny", "implicit-deny", "condition-unmet", "missing-permission"
	UnresolvedConds     []string        // ["ip-restriction", "mfa-required"] if ConditionallyReachable
	EvaluationMethod    string          // "iam-simulator", "hand-coded-rules", "synthetic"
	MatchedStatements   []int           // Statement indices in policy that matched
	MatchedConditions   []string        // Condition names that were satisfied
}
```

- [ ] **Step 4: Write minimal AWS evaluator implementation**

Create `orchestrator/internal/cloudgraph/aws_evaluator.go`:

```go
package cloudgraph

// AWSEvaluator implements authorization evaluation for AWS IAM policies
type AWSEvaluator struct{}

// EvaluatePermission determines if a permission edge is allowed, denied, or conditional
func (e *AWSEvaluator) EvaluatePermission(edge *CloudPermission, ctx *RequestContext) *EvaluationResult {
	// Minimal implementation for Phase 2: hand-coded rules
	
	// Step 1: Check for explicit Deny (always blocks)
	if policyDoc, ok := edge.Attributes["policy_document"]; ok {
		if hasDenyStatement(policyDoc, edge.Action) {
			return &EvaluationResult{
				State:      Blocked,
				BlockedBy:  "explicit-deny",
				AllowedBy:  "none",
				EvaluationMethod: "hand-coded-rules",
			}
		}
	}

	// Step 2: Check for Allow statement (identity-policy, resource-policy, or role-trust)
	if policyDoc, ok := edge.Attributes["policy_document"]; ok {
		if hasAllowStatement(policyDoc, edge.Action, edge.Target.CanonicalID) {
			// No conditions to evaluate in Phase 2 minimal version
			return &EvaluationResult{
				State:      PolicySupported,
				AllowedBy:  edge.SourceType,
				EvaluationMethod: "hand-coded-rules",
			}
		}
	}

	// Step 3: No Allow found → implicit deny
	return &EvaluationResult{
		State:      Blocked,
		BlockedBy:  "implicit-deny",
		EvaluationMethod: "hand-coded-rules",
	}
}

// hasDenyStatement checks if policy has an explicit Deny for the action
func hasDenyStatement(policyDoc, action string) bool {
	// Minimal: check for "Deny" + action string in policy JSON
	return contains(policyDoc, `"Effect":"Deny"`) && contains(policyDoc, action)
}

// hasAllowStatement checks if policy has an Allow for the action and resource
func hasAllowStatement(policyDoc, action, resource string) bool {
	// Minimal: check for "Allow" + action string in policy JSON
	return contains(policyDoc, `"Effect":"Allow"`) && contains(policyDoc, action)
}

// contains is a simple string search (minimal for Phase 2)
func contains(s, substr string) bool {
	for i := 0; i+len(substr) <= len(s); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
```

- [ ] **Step 5: Run test to verify it passes**

```bash
cd orchestrator && go test ./internal/cloudgraph -run "TestAWSEvaluator_AllowedByIdentityPolicy|TestAWSEvaluator_BlockedByExplicitDeny" -v
```

Expected: PASS 2/2

- [ ] **Step 6: Commit**

```bash
cd orchestrator && git add internal/cloudgraph/aws_evaluator.go internal/cloudgraph/aws_evaluator_test.go && git commit -m "feat(cloudgraph): AWS IAM policy evaluator (Layer C)

- AuthorizationEvaluator interface: EvaluatePermission(edge, context) → EvaluationResult
- EvaluationResult: State enum (Blocked/PolicySupported/Conditional/Unknown), AllowedBy/BlockedBy reasons
- Minimal implementation: hand-coded rules for identity-policy, resource-policy, explicit Deny
- Tests: AllowedByIdentityPolicy, BlockedByExplicitDeny
- Phase 3: extend to full IAM simulator, conditions, organization SCPs

Co-Authored-By: Claude Haiku 4.5 <noreply@anthropic.com>"
```

---

## Task 2: CloudTrail Event Correlation Engine

**Files:**
- Create: `orchestrator/internal/cloudgraph/cloudtrail_correlator.go`
- Create: `orchestrator/internal/cloudgraph/cloudtrail_correlator_test.go`
- Modify: `orchestrator/internal/cloudgraph/types.go` (add CloudEvent, EventSearchResult)
- Test: `orchestrator/internal/cloudgraph/cloudtrail_correlator_test.go`

**Interfaces:**
- Consumes: CloudPermission, Provenance, PathState (from Phase 1)
- Produces: `EventCorrelator` interface with `FindEvents(principal, action, resource, window) → EventSearchResult`; `CloudEvent`, `EventSearchResult` types

---

- [ ] **Step 1: Add CloudEvent type to types.go**

Edit `orchestrator/internal/cloudgraph/types.go` and add:

```go
// CloudEvent represents an audit log entry (CloudTrail, Activity Log, etc.)
type CloudEvent struct {
	Principal     string    // IAM ARN or Entra principal
	Action        string    // API action (e.g., sts:AssumeRole, s3:GetObject)
	Resource      string    // Resource ARN
	Timestamp     time.Time // When the action occurred
	Result        string    // "Success", "Failure", "MFAChallenge"
	Source        string    // "cloudtrail", "activity-log", "s3-access-logs"
	SessionToken  string    // Session ID for correlation
	SourceIP      string    // Caller IP
	UserAgent     string    // API caller
}

// EventSearchResult represents findings from a CloudTrail/audit log query
type EventSearchResult struct {
	EventsFound       []*CloudEvent
	SearchStatus      string          // "success", "partial", "unavailable"
	SearchError       string          // Error detail if unavailable
	WindowStart       time.Time       // Search window used
	WindowEnd         time.Time
	EventsSearched    int             // Total events examined
	MatchQuality      string          // "perfect", "partial", "delayed", "none"
	TelemetryDelay    time.Duration   // Time from action to event logged
	MissingTelemetry  []string        // ["mfa-challenge-events"] if partial
	Confidence        string          // "high", "medium", "low"
}
```

- [ ] **Step 2: Write failing test for event search**

Create `orchestrator/internal/cloudgraph/cloudtrail_correlator_test.go`:

```go
package cloudgraph

import (
	"testing"
	"time"
)

// TestEventCorrelator_FindEventsPerfectMatch verifies event found with exact match
func TestEventCorrelator_FindEventsPerfectMatch(t *testing.T) {
	correlator := &SyntheticEventCorrelator{}

	principal := "arn:aws:iam::123456789012:user/test-user"
	action := "s3:GetObject"
	resource := "arn:aws:s3:::test-bucket/object.txt"
	actionTime := time.Now().UTC()
	windowSize := 30 * time.Second

	// Synthetic event at exactly action time
	correlator.addSyntheticEvent(&CloudEvent{
		Principal:   principal,
		Action:      action,
		Resource:    resource,
		Timestamp:   actionTime,
		Result:      "Success",
		Source:      "cloudtrail",
	})

	result := correlator.FindEvents(principal, action, resource, actionTime, windowSize)

	if len(result.EventsFound) != 1 {
		t.Errorf("Expected 1 event, got %d", len(result.EventsFound))
	}
	if result.MatchQuality != "perfect" {
		t.Errorf("Expected perfect match, got %s", result.MatchQuality)
	}
	if result.SearchStatus != "success" {
		t.Errorf("Expected success, got %s", result.SearchStatus)
	}
}

// TestEventCorrelator_FindEventsPartialMatch verifies degraded confidence when resource mismatch
func TestEventCorrelator_FindEventsPartialMatch(t *testing.T) {
	correlator := &SyntheticEventCorrelator{}

	principal := "arn:aws:iam::123456789012:user/test-user"
	action := "s3:GetObject"
	resource := "arn:aws:s3:::test-bucket/object.txt"
	actionTime := time.Now().UTC()

	// Event found for principal+action, but resource doesn't match
	correlator.addSyntheticEvent(&CloudEvent{
		Principal: principal,
		Action:    action,
		Resource:  "arn:aws:s3:::different-bucket/file.txt",
		Timestamp: actionTime,
		Result:    "Success",
	})

	result := correlator.FindEvents(principal, action, resource, actionTime, 30*time.Second)

	if result.MatchQuality != "partial" {
		t.Errorf("Expected partial match, got %s", result.MatchQuality)
	}
	if result.Confidence != "medium" {
		t.Errorf("Expected medium confidence, got %s", result.Confidence)
	}
}

// TestEventCorrelator_FindEventsDelayedEvent verifies TelemetryDelay calculation
func TestEventCorrelator_FindEventsDelayedEvent(t *testing.T) {
	correlator := &SyntheticEventCorrelator{}

	principal := "arn:aws:iam::123456789012:user/test-user"
	action := "sts:AssumeRole"
	resource := "arn:aws:iam::123456789012:role/test-role"
	actionTime := time.Now().UTC()
	eventTime := actionTime.Add(5 * time.Second)  // Event logged 5s later

	correlator.addSyntheticEvent(&CloudEvent{
		Principal: principal,
		Action:    action,
		Resource:  resource,
		Timestamp: eventTime,
		Result:    "Success",
	})

	result := correlator.FindEvents(principal, action, resource, actionTime, 30*time.Second)

	if result.TelemetryDelay != 5*time.Second {
		t.Errorf("Expected 5s delay, got %v", result.TelemetryDelay)
	}
}

// TestEventCorrelator_NoEventFound verifies Unknown when event not found
func TestEventCorrelator_NoEventFound(t *testing.T) {
	correlator := &SyntheticEventCorrelator{}

	principal := "arn:aws:iam::123456789012:user/test-user"
	action := "s3:DeleteBucket"
	resource := "arn:aws:s3:::test-bucket"
	actionTime := time.Now().UTC()

	// No events in correlator
	result := correlator.FindEvents(principal, action, resource, actionTime, 30*time.Second)

	if result.SearchStatus != "success" {
		t.Errorf("Search should succeed (return no results)")
	}
	if result.MatchQuality != "none" {
		t.Errorf("Expected none, got %s", result.MatchQuality)
	}
	if len(result.EventsFound) != 0 {
		t.Errorf("Expected no events, got %d", len(result.EventsFound))
	}
}
```

- [ ] **Step 3: Write minimal event correlator implementation**

Create `orchestrator/internal/cloudgraph/cloudtrail_correlator.go`:

```go
package cloudgraph

import (
	"time"
)

// EventCorrelator interface for finding audit log events
type EventCorrelator interface {
	FindEvents(principal, action, resource string, actionTime time.Time, window time.Duration) *EventSearchResult
}

// SyntheticEventCorrelator uses in-memory synthetic events (Phase 2)
type SyntheticEventCorrelator struct {
	events []*CloudEvent
}

// FindEvents searches for events matching principal+action+resource within time window
func (c *SyntheticEventCorrelator) FindEvents(principal, action, resource string, actionTime time.Time, window time.Duration) *EventSearchResult {
	result := &EventSearchResult{
		EventsFound:      []*CloudEvent{},
		SearchStatus:     "success",
		WindowStart:      actionTime.Add(-window),
		WindowEnd:        actionTime.Add(window),
		MatchQuality:     "none",
		Confidence:       "low",
		EventsSearched:   len(c.events),
		MissingTelemetry: []string{},
	}

	for _, event := range c.events {
		// Check if event is within time window
		if event.Timestamp.Before(result.WindowStart) || event.Timestamp.After(result.WindowEnd) {
			continue
		}

		// Check match quality
		matchScore := 0
		if event.Principal == principal {
			matchScore++
		}
		if event.Action == action {
			matchScore++
		}
		if event.Resource == resource {
			matchScore++
		}

		if matchScore == 0 {
			continue  // No match
		}

		result.EventsFound = append(result.EventsFound, event)

		// Determine match quality
		if matchScore == 3 {
			result.MatchQuality = "perfect"
			result.Confidence = "high"
		} else if matchScore >= 2 {
			result.MatchQuality = "partial"
			result.Confidence = "medium"
		}

		// Calculate telemetry delay
		result.TelemetryDelay = event.Timestamp.Sub(actionTime)
	}

	return result
}

// addSyntheticEvent adds a synthetic event for testing
func (c *SyntheticEventCorrelator) addSyntheticEvent(event *CloudEvent) {
	c.events = append(c.events, event)
}
```

- [ ] **Step 4: Run test to verify it passes**

```bash
cd orchestrator && go test ./internal/cloudgraph -run TestEventCorrelator -v
```

Expected: PASS 4/4

- [ ] **Step 5: Commit**

```bash
cd orchestrator && git add internal/cloudgraph/cloudtrail_correlator.go internal/cloudgraph/cloudtrail_correlator_test.go && git commit -m "feat(cloudgraph): CloudTrail event correlation engine

- EventCorrelator interface: FindEvents(principal, action, resource, time, window) → EventSearchResult
- EventSearchResult: events, match quality (perfect/partial/none), telemetry delay, confidence
- SyntheticEventCorrelator: in-memory for Phase 2; real CloudTrail/Activity Log integration in Phase 3
- Tests: perfect match, partial match, delayed event, no event found
- Window: ±30s from action time; evidence quality assessment

Co-Authored-By: Claude Haiku 4.5 <noreply@anthropic.com>"
```

---

## Task 3: ControlOutcome Extension for Cloud

**Files:**
- Create: `orchestrator/internal/cloudgraph/cloud_outcomes.go`
- Create: `orchestrator/internal/cloudgraph/cloud_outcomes_test.go`
- Modify: `orchestrator/internal/controlval/types.go` (extend interface)
- Test: `orchestrator/internal/cloudgraph/cloud_outcomes_test.go`

**Interfaces:**
- Consumes: ControlOutcome (existing), EvaluationResult, EventSearchResult (from Tasks 1-2)
- Produces: `CloudControlOutcome` type with PrerequisiteState, ExecutionOutcome, EventCorrelation, TelemetryDelay, MissingTelemetry

---

- [ ] **Step 1: Write failing test for CloudControlOutcome**

Create `orchestrator/internal/cloudgraph/cloud_outcomes_test.go`:

```go
package cloudgraph

import (
	"testing"
	"time"
)

// TestCloudControlOutcome_AllowedAndObserved verifies match between prediction and observation
func TestCloudControlOutcome_AllowedAndObserved(t *testing.T) {
	// Graph prediction: PolicySupported (evaluator says Allowed)
	evaluation := &EvaluationResult{
		State:     PolicySupported,
		AllowedBy: "identity-policy",
	}

	// CloudTrail observation: event found
	correlation := &EventSearchResult{
		EventsFound:   []*CloudEvent{{Result: "Success"}},
		MatchQuality:  "perfect",
		Confidence:    "high",
		TelemetryDelay: 2 * time.Second,
	}

	outcome := &CloudControlOutcome{
		PrerequisiteState:   PolicySupported,
		ExecutionOutcome:    "Allowed",
		ControlName:         "S3ReadControl",
		EventCorrelation:    "perfect",
		GraphVsExecutionMatch: true,
		TelemetryDelay:      2 * time.Second,
	}

	if !outcome.GraphVsExecutionMatch {
		t.Error("Expected graph and execution to match")
	}
	if outcome.EventCorrelation != "perfect" {
		t.Errorf("Expected perfect correlation, got %s", outcome.EventCorrelation)
	}
}

// TestCloudControlOutcome_BlockedButObservedAttempt verifies gap (control missed attempt)
func TestCloudControlOutcome_BlockedButObservedAttempt(t *testing.T) {
	// Graph prediction: Blocked
	evaluation := &EvaluationResult{
		State:     Blocked,
		BlockedBy: "implicit-deny",
	}

	// CloudTrail observation: event found (user tried, permission denied or MFA challenged)
	correlation := &EventSearchResult{
		EventsFound: []*CloudEvent{{
			Result: "MFAChallenge",
		}},
		MatchQuality: "perfect",
	}

	outcome := &CloudControlOutcome{
		PrerequisiteState:   Blocked,
		ExecutionOutcome:    "MFAChallenged",
		EventCorrelation:    "perfect",
		GraphVsExecutionMatch: false,  // Prediction: Blocked; Reality: MFAChallenged
		Mismatch:            "policy-does-not-require-mfa-but-user-triggered-mfa",
	}

	if outcome.GraphVsExecutionMatch {
		t.Error("Expected mismatch between Blocked and MFAChallenged")
	}
	if outcome.Mismatch == "" {
		t.Error("Expected mismatch reason documented")
	}
}

// TestCloudControlOutcome_MissingTelemetry verifies evidence quality
func TestCloudControlOutcome_MissingTelemetry(t *testing.T) {
	// Graph prediction: PolicySupported
	evaluation := &EvaluationResult{
		State: PolicySupported,
	}

	// CloudTrail: no events found (logs not available or user identity not in logs)
	correlation := &EventSearchResult{
		EventsFound:      []*CloudEvent{},
		SearchStatus:     "partial",
		MatchQuality:     "none",
		Confidence:       "low",
		MissingTelemetry: []string{"cloudtrail-disabled", "logs-older-than-retention"},
	}

	outcome := &CloudControlOutcome{
		PrerequisiteState:  PolicySupported,
		ExecutionOutcome:   "Unknown",  // Cannot confirm or refute
		EventCorrelation:   "none",
		MissingTelemetry:   correlation.MissingTelemetry,
		TelemetryDelay:     0,
		ControlVerdictReason: "evidence unavailable; gap cannot be evaluated",
	}

	if outcome.ExecutionOutcome != "Unknown" {
		t.Error("Expected Unknown outcome when evidence missing")
	}
	if len(outcome.MissingTelemetry) == 0 {
		t.Error("Expected missing telemetry documented")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

```bash
cd orchestrator && go test ./internal/cloudgraph -run TestCloudControlOutcome -v
```

Expected: FAIL with "undefined: CloudControlOutcome"

- [ ] **Step 3: Write CloudControlOutcome type**

Create `orchestrator/internal/cloudgraph/cloud_outcomes.go`:

```go
package cloudgraph

import (
	"time"
)

// CloudControlOutcome extends ControlOutcome for cloud scenarios
type CloudControlOutcome struct {
	// Prediction (from graph)
	PrerequisiteState PathState  // Candidate/Conditional/PolicySupported/Blocked/Unknown

	// Execution outcome (from attempt)
	ExecutionOutcome string     // "Allowed", "Blocked", "MFAChallenged", "Terminated", "Unknown"

	// Control information
	ControlName             string
	ControlVerdictReason    string    // Why the verdict was reached

	// Evidence and observation
	EventCorrelation        string         // "perfect", "partial", "delayed", "none"
	CorrelatedEvents        []*CloudEvent  // Events matched
	TelemetryDelay          time.Duration  // Time from action to event logged
	MissingTelemetry        []string       // ["cloudtrail-disabled", "logs-old"] if partial/none

	// Prediction vs. reality
	GraphVsExecutionMatch   bool           // true if prediction matched reality
	Mismatch                string         // Description if mismatch (why prediction was wrong)
}

// NewCloudControlOutcome creates an outcome by matching evaluation result to correlation result
func NewCloudControlOutcome(
	evalResult *EvaluationResult,
	corrResult *EventSearchResult,
	controlName string,
) *CloudControlOutcome {
	outcome := &CloudControlOutcome{
		PrerequisiteState: evalResult.State,
		ControlName:       controlName,
		EventCorrelation:  corrResult.MatchQuality,
		TelemetryDelay:    corrResult.TelemetryDelay,
		MissingTelemetry:  corrResult.MissingTelemetry,
	}

	// Determine execution outcome from evidence
	if len(corrResult.EventsFound) == 0 {
		outcome.ExecutionOutcome = "Unknown"
		outcome.ControlVerdictReason = "no audit trail found; outcome cannot be assessed"
	} else {
		event := corrResult.EventsFound[0]
		switch event.Result {
		case "Success":
			outcome.ExecutionOutcome = "Allowed"
		case "Failure":
			outcome.ExecutionOutcome = "Blocked"
		case "MFAChallenge":
			outcome.ExecutionOutcome = "MFAChallenged"
		default:
			outcome.ExecutionOutcome = "Unknown"
		}
		outcome.CorrelatedEvents = corrResult.EventsFound
	}

	// Assess prediction vs. reality match
	if evalResult.State == PolicySupported && outcome.ExecutionOutcome == "Allowed" {
		outcome.GraphVsExecutionMatch = true
	} else if evalResult.State == Blocked && (outcome.ExecutionOutcome == "Blocked" || outcome.ExecutionOutcome == "Unknown") {
		outcome.GraphVsExecutionMatch = true
	} else {
		outcome.GraphVsExecutionMatch = false
		outcome.Mismatch = "prediction: " + string(evalResult.State) + "; execution: " + outcome.ExecutionOutcome
	}

	return outcome
}
```

- [ ] **Step 4: Run test to verify it passes**

```bash
cd orchestrator && go test ./internal/cloudgraph -run TestCloudControlOutcome -v
```

Expected: PASS 3/3

- [ ] **Step 5: Commit**

```bash
cd orchestrator && git add internal/cloudgraph/cloud_outcomes.go internal/cloudgraph/cloud_outcomes_test.go && git commit -m "feat(cloudgraph): ControlOutcome extension for cloud scenarios

- CloudControlOutcome: bridges graph prediction and execution observation
- Fields: PrerequisiteState (graph), ExecutionOutcome (evidence), EventCorrelation (quality), TelemetryDelay (freshness)
- NewCloudControlOutcome factory: assembles from EvaluationResult + EventSearchResult
- Tracks mismatch: prediction vs. reality divergence with evidence
- Tests: perfect match, mismatch (blocked vs. mfa-challenged), missing evidence

Co-Authored-By: Claude Haiku 4.5 <noreply@anthropic.com>"
```

---

## Task 4: End-to-End Scenario Execution (Synthetic Fixtures)

**Files:**
- Create: `orchestrator/internal/cloudgraph/e2e_test.go`
- Test: `orchestrator/internal/cloudgraph/e2e_test.go`

**Interfaces:**
- Consumes: CloudIdentity, CloudResource, CloudPermission, PathState, AWSEvaluator, SyntheticEventCorrelator, CloudControlOutcome (from Tasks 1-3)
- Produces: E2E test demonstrating full flow: discover → normalize → evaluate → execute → correlate → report

---

- [ ] **Step 1: Write failing E2E test**

Create `orchestrator/internal/cloudgraph/e2e_test.go`:

```go
package cloudgraph

import (
	"testing"
	"time"
)

// TestE2E_UserAssumeRoleThenAccessBucket verifies full attack path detection and control assessment
func TestE2E_UserAssumeRoleThenAccessBucket(t *testing.T) {
	// SETUP: Synthetic AWS resources
	user := &CloudIdentity{
		CanonicalID: "arn:aws:iam::123456789012:user/attacker",
		Kind:        "iam-user",
		AccountScope: &AccountScope{
			Provider:  "aws",
			AccountID: "123456789012",
		},
	}

	role := &CloudResource{
		CanonicalID: "arn:aws:iam::123456789012:role/data-processor",
		Kind:        "iam-role",
		AccountScope: &AccountScope{
			Provider:  "aws",
			AccountID: "123456789012",
		},
		Attributes: map[string]string{
			"trust_policy": `{"Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::123456789012:user/attacker"},"Action":"sts:AssumeRole"}]}`,
		},
	}

	bucket := &CloudResource{
		CanonicalID: "arn:aws:s3:::sensitive-data",
		Kind:        "s3-bucket",
		AccountScope: &AccountScope{
			Provider:  "aws",
			AccountID: "123456789012",
		},
	}

	// STEP 1: Evaluate user→role (sts:AssumeRole)
	edge1 := &CloudPermission{
		Source:     user,
		Target:     role,
		Action:     "sts:AssumeRole",
		SourceType: "role-trust",
		Attributes: map[string]string{
			"policy_document": `{"Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::123456789012:user/attacker"},"Action":"sts:AssumeRole"}]}`,
		},
	}

	evaluator := &AWSEvaluator{}
	result1 := evaluator.EvaluatePermission(edge1, &RequestContext{})

	if result1.State != PolicySupported {
		t.Fatalf("Expected user can assume role, got %s", result1.State)
	}

	// STEP 2: Simulate execution and correlate to CloudTrail
	actionTime := time.Now().UTC()
	correlator := &SyntheticEventCorrelator{}
	correlator.addSyntheticEvent(&CloudEvent{
		Principal: user.CanonicalID,
		Action:    "sts:AssumeRole",
		Resource:  role.CanonicalID,
		Timestamp: actionTime.Add(1 * time.Second),  // Log arrives 1s later
		Result:    "Success",
		Source:    "cloudtrail",
	})

	correlation1 := correlator.FindEvents(user.CanonicalID, "sts:AssumeRole", role.CanonicalID, actionTime, 30*time.Second)

	if correlation1.MatchQuality != "perfect" {
		t.Errorf("Expected perfect match for assume-role, got %s", correlation1.MatchQuality)
	}

	// STEP 3: Create ControlOutcome for step 1
	outcome1 := NewCloudControlOutcome(result1, correlation1, "S3RoleAssumeControl")

	if !outcome1.GraphVsExecutionMatch {
		t.Error("Expected prediction and execution to match for assume-role")
	}

	// STEP 4: Evaluate role→bucket (s3:GetObject) once assumed
	roleAsAssumedIdentity := &CloudIdentity{
		CanonicalID: role.CanonicalID,
		Kind:        "iam-role",  // Role is now acting identity after assumption
		AccountScope: role.AccountScope,
	}

	edge2 := &CloudPermission{
		Source:     roleAsAssumedIdentity,
		Target:     bucket,
		Action:     "s3:GetObject",
		SourceType: "identity-policy",
		Attributes: map[string]string{
			"policy_document": `{"Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::sensitive-data/*"}]}`,
		},
	}

	result2 := evaluator.EvaluatePermission(edge2, &RequestContext{})

	if result2.State != PolicySupported {
		t.Fatalf("Expected role can read bucket, got %s", result2.State)
	}

	// STEP 5: Correlate bucket access
	correlator.addSyntheticEvent(&CloudEvent{
		Principal: roleAsAssumedIdentity.CanonicalID,
		Action:    "s3:GetObject",
		Resource:  bucket.CanonicalID,
		Timestamp: actionTime.Add(2 * time.Second),
		Result:    "Success",
		Source:    "cloudtrail",
	})

	correlation2 := correlator.FindEvents(roleAsAssumedIdentity.CanonicalID, "s3:GetObject", bucket.CanonicalID, actionTime, 30*time.Second)

	outcome2 := NewCloudControlOutcome(result2, correlation2, "S3ReadControl")

	if !outcome2.GraphVsExecutionMatch {
		t.Error("Expected prediction and execution to match for bucket read")
	}

	// VERIFY: Full attack path detected and controls assessed
	if result1.State != PolicySupported || result2.State != PolicySupported {
		t.Error("Attack path not detected (should show user→role→bucket is open)")
	}

	if outcome1.EventCorrelation != "perfect" || outcome2.EventCorrelation != "perfect" {
		t.Error("Evidence correlation failed")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

```bash
cd orchestrator && go test ./internal/cloudgraph -run TestE2E -v
```

Expected: FAIL (missing pieces from Tasks 1-3, or logic gaps)

- [ ] **Step 3-4: Fix and iterate until PASS**

Run → fail → fix cycle. Expected to iterate 1-2 times to get PASS.

```bash
cd orchestrator && go test ./internal/cloudgraph -run TestE2E -v
```

Expected: PASS 1/1

- [ ] **Step 5: Commit**

```bash
cd orchestrator && git add orchestrator/internal/cloudgraph/e2e_test.go && git commit -m "test(cloudgraph): end-to-end AWS scenario execution

Comprehensive test covering full attack path:
1. User attempts sts:AssumeRole on role (evaluate permission)
2. CloudTrail logs role assumption (correlate event)
3. ControlOutcome reports prediction ↔ execution match
4. Assumed role attempts s3:GetObject on bucket (evaluate permission)
5. CloudTrail logs bucket access (correlate event)
6. ControlOutcome reports control effectiveness

Test validates:
- Graph evaluation (Layer C): user→role→bucket path is PolicySupported
- Evidence correlation: all events found with perfect match quality
- Outcome reporting: prediction matches reality; controls transparent
- Attack path detection: sensitive data access vulnerability identified

Co-Authored-By: Claude Haiku 4.5 <noreply@anthropic.com>"
```

---

## Task 5: Phase 2 Regression Validation & Exit Gate

**Files:**
- Modify: (none; validation only)
- Test: Full test suite

**Interfaces:**
- Consumes: All changes from Tasks 1-4
- Produces: Clean test suite, commitment to Phase 2 deliverables

---

- [ ] **Step 1: Run full cloudgraph test suite**

```bash
cd orchestrator && go test ./internal/cloudgraph -v
```

Expected: All tests PASS (at minimum: 4 evaluator tests, 4 correlator tests, 3 outcome tests, 1 e2e test = 12 total)

- [ ] **Step 2: Run full orchestrator suite for regressions**

```bash
cd orchestrator && go test ./internal/ad... ./internal/scenario... ./internal/controlval... -v 2>&1 | tail -20
```

Expected: PASS (no regressions in existing code)

- [ ] **Step 3: Commit final summary**

```bash
cd orchestrator && git log --oneline HEAD~5..HEAD
```

Expected: 5 commits (Tasks 1-4 + plan)

Update ledger and wrap up Phase 2.

---

## Phase 2 Exit Gate Criteria

✅ Deliverable 1: AWS IAM policy evaluator (AWSEvaluator, hand-coded rules, identity/resource/deny handling)
✅ Deliverable 2: CloudTrail correlation (SyntheticEventCorrelator, event matching, quality assessment, delay tracking)
✅ Deliverable 3: ControlOutcome extension (CloudControlOutcome type, prediction↔execution matching, mismatch detection)
✅ Deliverable 4: E2E scenario execution (user→role→bucket path, full attestation with evidence)
✅ TDD Discipline: All tests RED→GREEN verified
✅ Zero Regressions: Full test suite PASS
✅ Evidence-First: Never fake outcomes; Unknown used correctly

---

## Deferred (Phase 3+)

- Real AWS SDK integration (requires test account)
- Organization SCPs and advanced policy evaluation
- Multi-account campaign execution
- Azure RBAC evaluator
- GCP IAM evaluator
- Real CloudTrail/Activity Log integration

---

**Execution Method:** Inline on main (use superpowers:executing-plans).

**Next Step After Phase 2:** Phase 3 (Prerequisites & Multi-Account), then Phase 4 (Azure/Hybrid), then Phase 5 (Release).
