package cloudgraph

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/organizations"
	orgtypes "github.com/aws/aws-sdk-go-v2/service/organizations/types"
)

// Enforcement layers that narrow what an identity policy grants. Without them
// discovery over-reports: a grant blocked by a permissions boundary or a
// service control policy looks usable. Each layer is attached to every
// permission edge it constrains, and AWSEvaluator applies it.
//
// Evaluation follows IAM: an explicit Deny in any layer blocks; a permissions
// boundary must allow the action; every SCP level must allow the action.
// Conditions are not evaluated. A conditional Deny or Allow yields
// ConditionallyReachable, never a clean result.

// AWSOrgAPI is the Organizations surface used to read SCPs. *organizations.Client
// satisfies it; tests supply fakes.
type AWSOrgAPI interface {
	ListParents(ctx context.Context, params *organizations.ListParentsInput, optFns ...func(*organizations.Options)) (*organizations.ListParentsOutput, error)
	ListPoliciesForTarget(ctx context.Context, params *organizations.ListPoliciesForTargetInput, optFns ...func(*organizations.Options)) (*organizations.ListPoliciesForTargetOutput, error)
	DescribePolicy(ctx context.Context, params *organizations.DescribePolicyInput, optFns ...func(*organizations.Options)) (*organizations.DescribePolicyOutput, error)
}

// awsGateCondition names the reason a gate result is conditional.
const awsGateCondition = "enforcement-condition"

// awsStatementCovers reports whether a statement's Action or NotAction field
// covers action. A NotAction statement covers everything its list does not
// name, which is how guardrails such as "Deny NotAction [s3:GetObject]" are
// written. Before this, those statements were skipped, which over-reported.
func awsStatementCovers(st awsStatement, action string) bool {
	if len(st.NotAction) > 0 {
		for _, p := range stringOrList(st.NotAction) {
			if globMatch(p, action) {
				return false
			}
		}
		return true
	}
	for _, p := range stringOrList(st.Action) {
		if globMatch(p, action) {
			return true
		}
	}
	return false
}

// awsGate evaluates one enforcement layer (a permissions boundary, or one SCP
// level) for an action over its documents. It returns Blocked with the reason,
// ConditionallyReachable, PolicySupported, or Unknown when a document cannot be
// read. An unreadable document is never treated as allowing.
func awsGate(docs []string, action, target string) (PathState, string) {
	var allow, allowCond, denyCond bool
	for _, doc := range docs {
		stmts, err := parseStatements(doc)
		if err != nil {
			return Unknown, "unparseable-enforcement-document"
		}
		for _, st := range stmts {
			if !awsStatementCovers(st, action) || !awsResourceCovers(st, target) {
				continue
			}
			conditional := len(st.Condition) > 0
			switch st.Effect {
			case "Deny":
				if !conditional {
					return Blocked, "explicit-deny"
				}
				denyCond = true
			case "Allow":
				if conditional {
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

// awsEnforcementVerdict applies the boundary and SCP attached to an edge. It
// returns nil when both pass unconditionally, Blocked with the layer that blocked,
// or a conditional or unknown state that the caller must carry forward.
func awsEnforcementVerdict(edge *CloudPermission) (*EvaluationResult, PathState) {
	if edge.Attributes["resource_policy_unreadable"] == "true" {
		return &EvaluationResult{State: Unknown, BlockedBy: "resource-policy-unreadable", EvaluationMethod: "hand-coded-rules"}, Unknown
	}
	resourceConditional := false
	if doc, ok := edge.Attributes["resource_policy_document"]; ok {
		state, reason := awsResourcePolicyGate(doc, edge)
		switch state {
		case Blocked:
			return &EvaluationResult{State: Blocked, BlockedBy: "resource-policy:" + reason, EvaluationMethod: "hand-coded-rules"}, Blocked
		case Unknown:
			return &EvaluationResult{State: Unknown, BlockedBy: reason, EvaluationMethod: "hand-coded-rules"}, Unknown
		case ConditionallyReachable:
			resourceConditional = true
		}
	}
	sessionConditional := false
	if doc, ok := edge.Attributes["session_policy_document"]; ok {
		state, reason := awsGate([]string{doc}, edge.Action, edge.Target.CanonicalID)
		switch state {
		case Blocked:
			return &EvaluationResult{State: Blocked, BlockedBy: "session-policy:" + reason, EvaluationMethod: "hand-coded-rules"}, Blocked
		case Unknown:
			return &EvaluationResult{State: Unknown, BlockedBy: reason, EvaluationMethod: "hand-coded-rules"}, Unknown
		case ConditionallyReachable:
			sessionConditional = true
		}
	}
	if edge.Attributes["boundary_unresolved"] == "true" {
		return &EvaluationResult{State: Unknown, BlockedBy: "permissions-boundary-unreadable", EvaluationMethod: "hand-coded-rules"}, Unknown
	}
	conditional := false
	if doc, ok := edge.Attributes["boundary_document"]; ok {
		state, reason := awsGate([]string{doc}, edge.Action, edge.Target.CanonicalID)
		switch state {
		case Blocked:
			return &EvaluationResult{State: Blocked, BlockedBy: "permissions-boundary:" + reason, EvaluationMethod: "hand-coded-rules"}, Blocked
		case Unknown:
			return &EvaluationResult{State: Unknown, BlockedBy: reason, EvaluationMethod: "hand-coded-rules"}, Unknown
		case ConditionallyReachable:
			conditional = true
		}
	}
	if raw, ok := edge.Attributes["scp_levels"]; ok {
		var levels [][]string
		if err := json.Unmarshal([]byte(raw), &levels); err != nil {
			return &EvaluationResult{State: Unknown, BlockedBy: "scp-levels-unreadable", EvaluationMethod: "hand-coded-rules"}, Unknown
		}
		// An explicit Deny at any level blocks, so every level is checked for
		// Deny before any level's Allow is required.
		for _, level := range levels {
			state, reason := awsGate(level, edge.Action, edge.Target.CanonicalID)
			if state == Blocked && reason == "explicit-deny" {
				return &EvaluationResult{State: Blocked, BlockedBy: "scp-deny", EvaluationMethod: "hand-coded-rules"}, Blocked
			}
		}
		for _, level := range levels {
			state, reason := awsGate(level, edge.Action, edge.Target.CanonicalID)
			switch state {
			case Blocked:
				return &EvaluationResult{State: Blocked, BlockedBy: "scp:" + reason, EvaluationMethod: "hand-coded-rules"}, Blocked
			case Unknown:
				return &EvaluationResult{State: Unknown, BlockedBy: reason, EvaluationMethod: "hand-coded-rules"}, Unknown
			case ConditionallyReachable:
				conditional = true
			}
		}
	}
	if conditional || resourceConditional || sessionConditional {
		return nil, ConditionallyReachable
	}
	return nil, PolicySupported
}

// awsLevelsJSON serializes SCP levels for an edge attribute.
func awsLevelsJSON(levels [][]string) (string, error) {
	b, err := json.Marshal(levels)
	if err != nil {
		return "", fmt.Errorf("aws discovery: encoding SCP levels: %w", err)
	}
	return string(b), nil
}

// scpLevels returns the SCP documents in force for the account, one slice per
// level, from the account outward: the account, each parent OU, then the root.
// Each level is checked on its own, because IAM requires an Allow at every
// level. If the account is not in an organization, it returns (nil, false, nil)
// and SCPs do not apply.
func (c *AWSDiscoveryClient) scpLevels(ctx context.Context) ([][]string, bool, error) {
	if c.org == nil {
		return nil, false, fmt.Errorf("aws discovery: no Organizations client; SCPs cannot be read")
	}
	targets := []string{c.accountID}
	cur := c.accountID
	for hop := 0; ; hop++ {
		if hop >= 10 {
			return nil, false, fmt.Errorf("aws discovery: organization hierarchy deeper than 10 levels")
		}
		out, err := c.org.ListParents(ctx, &organizations.ListParentsInput{ChildId: &cur})
		if err != nil {
			var notInUse *orgtypes.AWSOrganizationsNotInUseException
			if errors.As(err, &notInUse) {
				return nil, false, nil
			}
			return nil, false, fmt.Errorf("aws discovery: listing organization parents (needs organizations:ListParents): %w", err)
		}
		if len(out.Parents) != 1 {
			return nil, false, fmt.Errorf("aws discovery: expected one parent for %s, got %d", cur, len(out.Parents))
		}
		parent := out.Parents[0]
		targets = append(targets, aws.ToString(parent.Id))
		if parent.Type == orgtypes.ParentTypeRoot {
			break
		}
		cur = aws.ToString(parent.Id)
	}

	cache := map[string]string{}
	var levels [][]string
	for _, target := range targets {
		var docs []string
		var marker *string
		for pages := 0; ; pages++ {
			if pages >= c.maxPages {
				return nil, false, fmt.Errorf("aws discovery: more than %d pages of SCPs for %s", c.maxPages, target)
			}
			out, err := c.org.ListPoliciesForTarget(ctx, &organizations.ListPoliciesForTargetInput{
				TargetId:  &target,
				Filter:    orgtypes.PolicyTypeServiceControlPolicy,
				NextToken: marker,
			})
			if err != nil {
				return nil, false, fmt.Errorf("aws discovery: listing SCPs for %s (needs organizations:ListPoliciesForTarget): %w", target, err)
			}
			for _, p := range out.Policies {
				id := aws.ToString(p.Id)
				doc, ok := cache[id]
				if !ok {
					d, err := c.org.DescribePolicy(ctx, &organizations.DescribePolicyInput{PolicyId: &id})
					if err != nil {
						return nil, false, fmt.Errorf("aws discovery: reading SCP %s (needs organizations:DescribePolicy): %w", id, err)
					}
					doc, err = awsDecodePolicy(aws.ToString(d.Policy.Content))
					if err != nil {
						return nil, false, fmt.Errorf("aws discovery: SCP %s is not a readable document: %w", id, err)
					}
					cache[id] = doc
				}
				docs = append(docs, doc)
			}
			if out.NextToken == nil || *out.NextToken == "" {
				break
			}
			marker = out.NextToken
		}
		levels = append(levels, docs)
	}
	return levels, true, nil
}

// awsResourcePolicyGate applies a bucket policy to an edge. Only Deny statements
// matter here. An Allow in a resource policy grants nothing in this model:
// same-account access comes from the identity's own policies, and cross-account
// access is counted as unresolved trust elsewhere, not modelled.
func awsResourcePolicyGate(doc string, edge *CloudPermission) (PathState, string) {
	stmts, err := parseStatements(doc)
	if err != nil {
		return Unknown, "unparseable-resource-policy"
	}
	denyCond := false
	for _, st := range stmts {
		if st.Effect != "Deny" {
			continue
		}
		if !awsResourceCovers(st, edge.Target.CanonicalID) ||
			!awsPrincipalCovers(st, edge.Source.CanonicalID) ||
			!awsStatementCovers(st, edge.Action) {
			continue
		}
		if len(st.Condition) > 0 {
			denyCond = true
			continue
		}
		return Blocked, "explicit-deny"
	}
	if denyCond {
		return ConditionallyReachable, awsGateCondition
	}
	return PolicySupported, ""
}

// awsResourceCovers reports whether a statement's Resource or NotResource field
// covers the target. A statement with neither covers the whole bucket policy's
// bucket.
func awsResourceCovers(st awsStatement, target string) bool {
	if len(st.NotResource) > 0 {
		for _, p := range stringOrList(st.NotResource) {
			if globMatch(p, target) {
				return false
			}
		}
		return true
	}
	resources := stringOrList(st.Resource)
	if len(resources) == 0 {
		return true
	}
	for _, p := range resources {
		if globMatch(p, target) {
			return true
		}
	}
	return false
}

// awsPrincipalCovers reports whether a resource-policy statement applies to the
// source identity, through Principal or NotPrincipal.
func awsPrincipalCovers(st awsStatement, source string) bool {
	if len(st.NotPrincipal) > 0 {
		return !awsPrincipalNamed(st.NotPrincipal, source)
	}
	if len(st.Principal) == 0 {
		return false
	}
	return awsPrincipalNamed(st.Principal, source)
}

// awsPrincipalNamed reports whether a Principal clause names source, directly or
// through its account root (arn:aws:iam::ACCOUNT:root names every principal of
// that account).
func awsPrincipalNamed(raw json.RawMessage, source string) bool {
	arns, wildcard := awsPrincipalARNs(raw)
	if wildcard {
		return true
	}
	parts := strings.SplitN(source, ":", 6)
	if len(parts) < 6 {
		return false
	}
	root := strings.Join(parts[:5], ":") + ":root"
	for _, arn := range arns {
		if arn == source || arn == root {
			return true
		}
	}
	return false
}

// maxSessionPolicyChars is the length limit AWS places on a session policy passed
// to AssumeRole.
const maxSessionPolicyChars = 2048

// NormalizeAWSSessionPolicy checks a session policy and returns it compact. A
// session policy is a document of Allow and Deny statements. One that is too
// long, unreadable, empty, or has any other effect is refused, rather than
// applied in part.
func NormalizeAWSSessionPolicy(raw string) (string, error) {
	if len(raw) > maxSessionPolicyChars {
		return "", fmt.Errorf("session policy is %d characters; AWS limits it to %d", len(raw), maxSessionPolicyChars)
	}
	doc, err := awsDecodePolicy(raw)
	if err != nil {
		return "", fmt.Errorf("session policy is not a readable policy document: %w", err)
	}
	stmts, err := parseStatements(doc)
	if err != nil {
		return "", fmt.Errorf("session policy statements are not readable: %w", err)
	}
	if len(stmts) == 0 {
		return "", errors.New("session policy has no statements")
	}
	for _, st := range stmts {
		if st.Effect != "Allow" && st.Effect != "Deny" {
			return "", fmt.Errorf("session policy statement has effect %q; expected Allow or Deny", st.Effect)
		}
	}
	return doc, nil
}
