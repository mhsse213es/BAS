package cloudgraph

import (
	"encoding/json"
	"strings"
)

// AWSEvaluator implements authorization evaluation for AWS IAM policies.
// Phase 2: hand-coded statement matching. Phase 3+: full IAM simulator with
// conditions, organization SCPs, and resource-policy intersection.
type AWSEvaluator struct{}

// EvaluatePermission determines if a permission edge is allowed, denied, or conditional.
// AWS evaluation order: explicit Deny always wins, then explicit Allow, else implicit deny.
func (e *AWSEvaluator) EvaluatePermission(edge *CloudPermission, ctx *RequestContext) *EvaluationResult {
	// Permissions boundary and SCPs narrow the identity policy. A blocked or
	// unreadable layer decides the result; a conditional layer caps a grant at
	// ConditionallyReachable.
	gate, gateState := awsEnforcementVerdict(edge)
	if gate != nil {
		return gate
	}
	if edge.SourceType == "resource-policy" {
		return e.resourcePolicyVerdict(edge, gateState)
	}
	var result *EvaluationResult
	if edge.SourceType == "identity-policy" {
		result = e.identityPolicyVerdict(edge, ctx)
	} else {
		result = e.identityVerdict(edge, ctx)
	}
	if result.State == PolicySupported && gateState == ConditionallyReachable {
		result.State = ConditionallyReachable
		result.UnresolvedConds = []string{awsGateCondition}
	}
	return result
}

// identityVerdict evaluates the identity policy attached to an edge, without
// the enforcement layers.
func (e *AWSEvaluator) identityVerdict(edge *CloudPermission, ctx *RequestContext) *EvaluationResult {
	policyDoc, hasPolicy := edge.Attributes["policy_document"]

	if hasPolicy && hasDenyStatement(policyDoc, edge.Action) {
		return &EvaluationResult{
			State:            Blocked,
			BlockedBy:        "explicit-deny",
			AllowedBy:        "none",
			EvaluationMethod: "hand-coded-rules",
		}
	}

	if hasPolicy && hasAllowStatement(policyDoc, edge.Action) && principalMatches(edge, policyDoc) {
		return &EvaluationResult{
			State:            PolicySupported,
			AllowedBy:        edge.SourceType,
			EvaluationMethod: "hand-coded-rules",
		}
	}

	return &EvaluationResult{
		State:            Blocked,
		BlockedBy:        "implicit-deny",
		EvaluationMethod: "hand-coded-rules",
	}
}

// hasDenyStatement checks if policy has an explicit Deny for the action
func hasDenyStatement(policyDoc, action string) bool {
	return statementMatches(policyDoc, "Deny", action)
}

// hasAllowStatement checks if policy has an Allow for the action
func hasAllowStatement(policyDoc, action string) bool {
	return statementMatches(policyDoc, "Allow", action)
}

// statementMatches reports whether a statement with the given effect names an
// action pattern that covers action. Each statement is matched on its own
// Action field, so "s3:GetObject" is never satisfied by "s3:GetObjectAcl", and
// "s3:*" is honoured. NotAction statements are not matched: they cover "all
// except", which this evaluator does not expand. A document that does not parse
// falls back to the earlier substring check, so a malformed document cannot
// change a result silently in either direction.
func statementMatches(policyDoc, effect, action string) bool {
	stmts, err := parseStatements(policyDoc)
	if err != nil {
		return strings.Contains(policyDoc, `"Effect":"`+effect+`"`) && strings.Contains(policyDoc, action)
	}
	for _, st := range stmts {
		if st.Effect != effect || len(st.NotAction) > 0 {
			continue
		}
		for _, pattern := range stringOrList(st.Action) {
			if globMatch(pattern, action) {
				return true
			}
		}
	}
	return false
}

// principalMatches verifies that role-trust policies name the requesting identity as Principal.
// Non-trust policies (identity-policy, resource-policy) have no Principal clause to check here.
func principalMatches(edge *CloudPermission, policyDoc string) bool {
	if edge.SourceType != "role-trust" {
		return true
	}
	return strings.Contains(policyDoc, edge.Source.CanonicalID)
}

// identityPolicyVerdict evaluates an identity-policy edge at statement level. A
// Deny that carries a Condition no longer blocks outright: it may not apply, so
// the grant is conditionally reachable. An Allow with a Condition is conditional
// for the same reason. Conditions are not evaluated.
func (e *AWSEvaluator) identityPolicyVerdict(edge *CloudPermission, ctx *RequestContext) *EvaluationResult {
	if _, ok := edge.Attributes["policy_document"]; !ok || edge.Target == nil {
		return e.identityVerdict(edge, ctx)
	}
	// Every identity policy is considered together: an explicit Deny in one
	// document overrides an Allow in another.
	docs := []string{edge.Attributes["policy_document"]}
	if raw, ok := edge.Attributes["identity_docs"]; ok {
		if err := json.Unmarshal([]byte(raw), &docs); err != nil {
			return &EvaluationResult{State: Unknown, BlockedBy: "identity-documents-unreadable", EvaluationMethod: "hand-coded-rules"}
		}
	}
	state, reason := identityDecision(docs, edge.Action, edge.Target.CanonicalID)
	switch state {
	case Unknown:
		return &EvaluationResult{State: Unknown, BlockedBy: reason, EvaluationMethod: "hand-coded-rules"}
	case Blocked:
		return &EvaluationResult{State: Blocked, BlockedBy: reason, AllowedBy: "none", EvaluationMethod: "hand-coded-rules"}
	}
	res := &EvaluationResult{State: PolicySupported, AllowedBy: edge.SourceType, EvaluationMethod: "hand-coded-rules"}
	if state == ConditionallyReachable || edge.Attributes["identity_condition"] == "true" {
		res.State = ConditionallyReachable
		res.UnresolvedConds = []string{awsGateCondition}
	}
	return res
}

// identityDecision evaluates an identity's policy documents for one action on one
// target. Allows match by action: discovery already scopes each identity edge to
// its statement's resource, and this matching has always worked that way. Denies
// match on action and resource, across every document, since an explicit Deny in
// any policy overrides an Allow in any other. A conditional Deny yields
// ConditionallyReachable, because the condition may not hold.
func identityDecision(docs []string, action, target string) (PathState, string) {
	var allow, allowCond, denyCond bool
	for _, doc := range docs {
		stmts, err := parseStatements(doc)
		if err != nil {
			return Unknown, "unparseable-identity-document"
		}
		for _, st := range stmts {
			switch st.Effect {
			case "Deny":
				if !awsStatementCovers(st, action) || !awsResourceCovers(st, target) {
					continue
				}
				if len(st.Condition) > 0 {
					denyCond = true
					continue
				}
				return Blocked, "explicit-deny"
			case "Allow":
				if !awsStatementCovers(st, action) {
					continue
				}
				if len(st.Condition) > 0 {
					allowCond = true
				} else {
					allow = true
				}
			}
		}
	}
	switch {
	case denyCond:
		return ConditionallyReachable, awsGateCondition
	case allow:
		return PolicySupported, ""
	case allowCond:
		return ConditionallyReachable, awsGateCondition
	default:
		return Blocked, "implicit-deny"
	}
}
