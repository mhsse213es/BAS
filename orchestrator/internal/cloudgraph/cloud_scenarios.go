package cloudgraph

import (
	"strings"
	"time"
)

// CloudScenarioStep is one control-plane or data-access action a scenario
// attempts against the target. Action is the provider-native permission name
// the evaluator reasons about (IAM action, Azure RBAC action, GCP permission).
type CloudScenarioStep struct {
	Name         string
	TechniqueTag string // MITRE ATT&CK technique the step represents
	Kind         string // "control-plane" or "data-access"
	Action       string
}

// CloudScenario is a named, provider-specific attack chain against one
// resource, gated by prerequisites. It is data, not a runner: ExecuteCloudScenario
// evaluates it against a discovered graph.
type CloudScenario struct {
	ID            string
	Name          string
	Provider      string
	Description   string
	Prerequisites []*CloudPrerequisite
	Steps         []*CloudScenarioStep
}

// BuiltinCloudScenarios returns the shipped cloud scenario content. Every
// scenario targets a single resource the caller names at run time (a vault,
// a bucket, a storage account); the identity under test is also supplied at
// run time. Nothing here carries credentials or account identifiers.
func BuiltinCloudScenarios() []*CloudScenario {
	return []*CloudScenario{
		{
			ID:          "backup-assurance-aws",
			Name:        "AWS Backup: destroy recovery points and plans",
			Provider:    "aws",
			Description: "Can an identity inhibit recovery by deleting recovery points, plans and the vault? Every step should be blocked for a protected backup vault.",
			Steps: []*CloudScenarioStep{
				{Name: "List recovery points", TechniqueTag: "T1490", Kind: "control-plane", Action: "backup:ListRecoveryPointsByBackupVault"},
				{Name: "Delete recovery point", TechniqueTag: "T1490", Kind: "control-plane", Action: "backup:DeleteRecoveryPoint"},
				{Name: "Delete backup plan", TechniqueTag: "T1490", Kind: "control-plane", Action: "backup:DeleteBackupPlan"},
				{Name: "Delete backup vault", TechniqueTag: "T1490", Kind: "control-plane", Action: "backup:DeleteBackupVault"},
			},
		},
		{
			ID:          "backup-assurance-azure",
			Name:        "Azure Recovery Services: destroy protected items and policies",
			Provider:    "azure",
			Description: "Can an identity inhibit recovery by deleting protected items or backup policies in a Recovery Services vault?",
			Steps: []*CloudScenarioStep{
				{Name: "List protected items", TechniqueTag: "T1490", Kind: "control-plane", Action: "Microsoft.RecoveryServices/vaults/backupFabrics/protectionContainers/protectedItems/read"},
				{Name: "Delete protected item", TechniqueTag: "T1490", Kind: "control-plane", Action: "Microsoft.RecoveryServices/vaults/backupFabrics/protectionContainers/protectedItems/delete"},
				{Name: "Delete backup policy", TechniqueTag: "T1490", Kind: "control-plane", Action: "Microsoft.RecoveryServices/vaults/backupPolicies/delete"},
			},
		},
		{
			ID:          "backup-assurance-gcp",
			Name:        "GCS retention: remove retention and delete objects",
			Provider:    "gcp",
			Description: "Can an identity weaken a bucket's retention or delete its objects, defeating object-level backup?",
			Steps: []*CloudScenarioStep{
				{Name: "Update bucket retention", TechniqueTag: "T1490", Kind: "control-plane", Action: "storage.buckets.update"},
				{Name: "Delete backup object", TechniqueTag: "T1490", Kind: "data-access", Action: "storage.objects.delete"},
			},
		},
		{
			ID:          "data-access-aws",
			Name:        "S3 data access and exposure",
			Provider:    "aws",
			Description: "Can an identity list, read, and then expose an S3 bucket by changing its policy?",
			Steps: []*CloudScenarioStep{
				{Name: "List bucket", TechniqueTag: "T1530", Kind: "data-access", Action: "s3:ListBucket"},
				{Name: "Read object", TechniqueTag: "T1530", Kind: "data-access", Action: "s3:GetObject"},
				{Name: "Change bucket policy", TechniqueTag: "T1537", Kind: "control-plane", Action: "s3:PutBucketPolicy"},
			},
		},
		{
			ID:          "data-access-gcp",
			Name:        "GCS data access and exposure",
			Provider:    "gcp",
			Description: "Can an identity list and read objects in a bucket, and change who can read it?",
			Steps: []*CloudScenarioStep{
				{Name: "List objects", TechniqueTag: "T1530", Kind: "data-access", Action: "storage.objects.list"},
				{Name: "Read object", TechniqueTag: "T1530", Kind: "data-access", Action: "storage.objects.get"},
				{Name: "Change bucket IAM", TechniqueTag: "T1537", Kind: "control-plane", Action: "storage.buckets.setIamPolicy"},
			},
		},
		{
			ID:          "data-access-azure",
			Name:        "Storage account data access and key retrieval",
			Provider:    "azure",
			Description: "Can an identity retrieve storage account keys and read blobs?",
			Steps: []*CloudScenarioStep{
				{Name: "List account keys", TechniqueTag: "T1552", Kind: "control-plane", Action: "Microsoft.Storage/storageAccounts/listKeys/action"},
				{Name: "Read blob", TechniqueTag: "T1530", Kind: "data-access", Action: "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read"},
			},
		},
	}
}

// CloudScenarioByID returns the builtin scenario with the given ID, or nil.
func CloudScenarioByID(id string) *CloudScenario {
	for _, s := range BuiltinCloudScenarios() {
		if s.ID == id {
			return s
		}
	}
	return nil
}

// CloudScenarioResult is the outcome of one scenario against one principal and
// resource. OverallVerdict is "not-attempted" when a prerequisite is missing,
// "inconclusive" when any step could not be assessed, and otherwise one of
// fully-blocked, partially-blocked or fully-open.
type CloudScenarioResult struct {
	ScenarioID     string
	Prerequisites  []*PrerequisiteResult
	Steps          []*CloudControlOutcome
	OverallVerdict string

	// stepEvaluations keeps the evaluator result behind each outcome so
	// ObserveCloudScenario can compare the prediction against audit evidence.
	stepEvaluations []*EvaluationResult
	stepEdges       []*CloudPermission
	stepNames       []string
}

// ExecuteCloudScenario evaluates scenario against graph for principal and
// resource. Prerequisites are resolved first; a missing one stops the scenario
// before any step is evaluated. Each step's edge comes from the discovered
// graph when present; when it is absent, the step is evaluated as a bare edge,
// which the evaluators treat as implicit deny. Evaluation stops at the first
// Blocked step, matching the ransomware executor's semantics, and a step the
// step gate refuses to dispatch is recorded as Unknown and also stops the chain.
func ExecuteCloudScenario(scenario *CloudScenario, graph *DiscoveredGraph, evaluator AuthorizationEvaluator, principal, resource string) *CloudScenarioResult {
	result := &CloudScenarioResult{ScenarioID: scenario.ID}

	prereqs := []*CloudPrerequisite{
		{Kind: "cloud_identity", Target: principal},
		{Kind: "cloud_resource", Target: resource},
	}
	prereqs = append(prereqs, scenario.Prerequisites...)
	resolver := &PrerequisiteResolver{}
	result.Prerequisites = resolver.Resolve(prereqs, graph)

	for _, p := range result.Prerequisites {
		if p.Status == "MISSING" {
			result.OverallVerdict = "not-attempted"
			return result
		}
	}
	for _, p := range result.Prerequisites {
		if p.Status == "UNKNOWN" {
			result.OverallVerdict = "inconclusive"
			return result
		}
	}

	source := &CloudIdentity{CanonicalID: principal}
	target := &CloudResource{CanonicalID: resource}
	gate := &StepGate{}

	for _, step := range scenario.Steps {
		edge := scenarioStepEdge(graph, source, target, step.Action)

		decision := gate.ShouldDispatch(edge, graph)
		if !decision.Allowed {
			result.Steps = append(result.Steps, &CloudControlOutcome{
				ControlName:          step.Name,
				ExecutionOutcome:     "Unknown",
				ControlVerdictReason: decision.Reason,
			})
			break
		}

		eval := evaluator.EvaluatePermission(edge, &RequestContext{})
		outcome := &CloudControlOutcome{
			PrerequisiteState:    eval.State,
			ControlName:          step.Name,
			ControlVerdictReason: "graph prediction; no execution evidence yet",
		}
		switch eval.State {
		case PolicySupported:
			outcome.ExecutionOutcome = "Allowed"
		case Blocked:
			outcome.ExecutionOutcome = "Blocked"
			outcome.ControlVerdictReason = "graph prediction: " + eval.BlockedBy
		default:
			outcome.ExecutionOutcome = "Unknown"
		}
		result.Steps = append(result.Steps, outcome)
		result.stepEvaluations = append(result.stepEvaluations, eval)
		result.stepEdges = append(result.stepEdges, edge)
		result.stepNames = append(result.stepNames, step.Name)

		if eval.State != PolicySupported {
			break
		}
	}

	result.OverallVerdict = scenarioVerdict(result.Steps)
	return result
}

// scenarioVerdict summarises step outcomes. Any Unknown makes the scenario
// inconclusive, because a step that could not be assessed cannot be counted as
// blocked or as open.
func scenarioVerdict(steps []*CloudControlOutcome) string {
	anyBlocked, anyAllowed, anyUnknown := false, false, false
	for _, s := range steps {
		switch s.ExecutionOutcome {
		case "Blocked":
			anyBlocked = true
		case "Allowed":
			anyAllowed = true
		default:
			anyUnknown = true
		}
	}
	switch {
	case anyUnknown:
		return "inconclusive"
	case anyBlocked && !anyAllowed:
		return "fully-blocked"
	case anyBlocked && anyAllowed:
		return "partially-blocked"
	default:
		return "fully-open"
	}
}

// scenarioStepEdge builds the edge a scenario step is evaluated on. It starts
// from the best discovered grant for the principal and action, and always
// evaluates against the resource the scenario targets. A grant on an ancestor
// scope (a subscription or project above the resource) is therefore checked
// against the resource, and Azure denial rules are applied to that resource.
// With no grant, the step is evaluated as a bare edge, which evaluators treat
// as implicit deny.
func scenarioStepEdge(graph *DiscoveredGraph, source *CloudIdentity, target *CloudResource, action string) *CloudPermission {
	grant := findScenarioGrant(graph, source.CanonicalID, action, target.CanonicalID)
	edge := &CloudPermission{Source: source, Target: target, Action: action}
	if grant != nil {
		edge.SourceType = grant.SourceType
		edge.Provenance = grant.Provenance
		edge.Attributes = map[string]string{}
		for k, v := range grant.Attributes {
			edge.Attributes[k] = v
		}
	}
	if oid := azureObjectID(source.CanonicalID); oid != "" && len(graph.Denials) > 0 {
		if d, ok := firstDenialFor(graph.Denials, oid, target.CanonicalID, action); ok {
			if edge.Attributes == nil {
				edge.Attributes = map[string]string{}
			}
			edge.Attributes["deny_assignment"] = "true"
			edge.Attributes["deny_scope"] = d.Scope
			edge.Attributes["deny_actions"] = action
		}
	}
	return edge
}

// findScenarioGrant returns the discovered grant to evaluate for a step. A
// literal action on the resource (or an ancestor scope, or a wildcard resource)
// wins; otherwise a pattern grant whose action covers the step. Pattern grants
// keep their attributes, so the evaluator checks the step's own action. The
// evaluator also checks that the grant's scope covers the resource.
func findScenarioGrant(graph *DiscoveredGraph, principal, action, resource string) *CloudPermission {
	var literalAny, patternAny *CloudPermission
	for _, p := range graph.Permissions {
		if p.Source.CanonicalID != principal {
			continue
		}
		covers := scenarioTargetCovers(p.Target.CanonicalID, resource)
		switch {
		case p.Action == action:
			if covers && p.Target.CanonicalID == resource {
				return p
			}
			if covers && literalAny == nil {
				literalAny = p
			}
		case strings.Contains(p.Action, "*") && globMatch(p.Action, action):
			if covers && patternAny == nil {
				patternAny = p
			}
		}
	}
	if literalAny != nil {
		return literalAny
	}
	return patternAny
}

// scenarioTargetCovers reports whether a grant's target covers resource: the
// wildcard, the resource itself, or (for hierarchical Azure and GCP scopes) an
// ancestor scope.
func scenarioTargetCovers(target, resource string) bool {
	if target == "*" || target == resource {
		return true
	}
	if strings.HasPrefix(target, "/subscriptions/") || strings.HasPrefix(target, "projects/") {
		return strings.HasPrefix(resource, target+"/")
	}
	return false
}

// ObserveCloudScenario compares each evaluated step's prediction with audit
// evidence from correlator, for an execution that happened at actionTime. The
// outcome of a step with no matching evidence becomes Unknown, never inferred
// from the prediction. Steps that were not evaluated are left untouched.
func ObserveCloudScenario(result *CloudScenarioResult, correlator EventCorrelator, principal, resource string, actionTime time.Time, window time.Duration) {
	for i, eval := range result.stepEvaluations {
		edge := result.stepEdges[i]
		corr := correlator.FindEvents(principal, edge.Action, resource, actionTime, window)
		result.Steps[i] = NewCloudControlOutcome(eval, corr, result.stepNames[i])
	}
	result.OverallVerdict = scenarioVerdict(result.Steps)
}
