package cloudgraph

import (
	"sort"
	"strings"
)

// Bucket policy grants. An Allow in a bucket policy grants access that the
// identity policies of this account never show, so discovery adds those grants:
//
//   - a principal in this account, named in the policy: a clean grant. Same-account
//     access may come from either the identity policy or the resource policy.
//   - this account's root: every identity in the account gets the grant.
//   - a principal in another account: conditional. That account's identity policy
//     must also allow the action, and discovery cannot read it.
//   - "*": public. Conditional, and marked as public.
//
// NotPrincipal allows, NotAction allows, and service principals are counted and
// not expanded. Expanding them would be guessing.

const (
	crossAccountCondition = "cross-account-identity-policy"
	publicAccessCondition = "public-access"
	publicIdentityID      = "aws:anonymous"
)

// awsAccountOf returns the account ID in an ARN, or "" if it has none.
func awsAccountOf(arn string) string {
	parts := strings.SplitN(arn, ":", 6)
	if len(parts) < 5 {
		return ""
	}
	return parts[4]
}

// crossAccountGrants adds the identities and edges that bucket policies grant.
// docs maps bucket ARN to its decoded policy. It runs before the enforcement
// attachments, so denies in the same policy apply to these edges too.
func (c *AWSDiscoveryClient) crossAccountGrants(graph *DiscoveredGraph, docs map[string]string, stats *AWSDiscoveryStats) {
	identities := map[string]*CloudIdentity{}
	for _, id := range graph.Identities {
		identities[id.CanonicalID] = id
	}
	resources := map[string]*CloudResource{}
	for _, r := range graph.Resources {
		resources[r.CanonicalID] = r
	}
	acct := &AccountScope{Provider: "aws", AccountID: c.accountID, Region: c.region}
	provenance := &Provenance{Source: "aws:bucket-policy", Confidence: "observed"}

	identity := func(canonical, kind string) *CloudIdentity {
		if id, ok := identities[canonical]; ok {
			return id
		}
		id := &CloudIdentity{CanonicalID: canonical, Kind: kind, AccountScope: acct,
			Attributes: map[string]string{}, Provenance: provenance}
		identities[canonical] = id
		graph.Identities = append(graph.Identities, id)
		return id
	}
	resource := func(canonical string) *CloudResource {
		if r, ok := resources[canonical]; ok {
			return r
		}
		kind := "aws-resource"
		if strings.Contains(canonical, "*") {
			kind = "aws-resource-wildcard"
		}
		r := &CloudResource{CanonicalID: canonical, Kind: kind, AccountScope: acct, Provenance: provenance}
		resources[canonical] = r
		graph.Resources = append(graph.Resources, r)
		return r
	}

	bucketARNs := make([]string, 0, len(docs))
	for arn := range docs {
		bucketARNs = append(bucketARNs, arn)
	}
	sort.Strings(bucketARNs)

	seen := map[string]bool{}
	for _, bucket := range bucketARNs {
		doc := docs[bucket]
		stmts, err := parseStatements(doc)
		if err != nil {
			continue // the enforcement gate marks this bucket's edges Unknown
		}
		for _, st := range stmts {
			if st.Effect != "Allow" {
				continue
			}
			if len(st.NotPrincipal) > 0 {
				stats.NotPrincipalAllows++
				continue
			}
			if len(st.NotResource) > 0 || len(st.NotAction) > 0 {
				stats.NotActionStatements++
				continue
			}
			var sources []*CloudIdentity
			arns, wildcard := awsPrincipalARNs(st.Principal)
			if wildcard {
				sources = append(sources, identity(publicIdentityID, "public"))
				stats.PublicGrants++
			}
			for _, arn := range arns {
				switch {
				case awsAccountOf(arn) == c.accountID && strings.HasSuffix(arn, ":root"):
					// The account root names every principal in this account.
					for _, id := range append([]*CloudIdentity(nil), graph.Identities...) {
						if (id.Kind == "iam-user" || id.Kind == "iam-role") &&
							strings.HasPrefix(id.CanonicalID, "arn:aws:iam::"+c.accountID+":") {
							sources = append(sources, id)
						}
					}
				case awsAccountOf(arn) == c.accountID:
					if id, ok := identities[arn]; ok {
						sources = append(sources, id)
					} else {
						stats.UnresolvedTrust++
					}
				case strings.HasSuffix(arn, ":root"):
					sources = append(sources, identity(arn, "external-account-root"))
					stats.CrossAccountIdentities++
				default:
					sources = append(sources, identity(arn, "external-principal"))
					stats.CrossAccountIdentities++
				}
			}

			resArns := stringOrList(st.Resource)
			if len(resArns) == 0 {
				resArns = []string{bucket}
			}
			for _, source := range sources {
				for _, action := range stringOrList(st.Action) {
					for _, res := range resArns {
						key := source.CanonicalID + "|" + action + "|" + res + "|" + bucket
						if seen[key] {
							continue
						}
						seen[key] = true
						graph.Permissions = append(graph.Permissions, &CloudPermission{
							Source:     source,
							Target:     resource(res),
							Action:     action,
							SourceType: "resource-policy",
							Attributes: map[string]string{
								"policy_document":        doc,
								"resource_policy_source": bucket,
							},
							Provenance: provenance,
						})
						stats.ResourcePolicyEdges++
					}
				}
			}
		}
	}
}

// resourcePolicyVerdict decides an edge a bucket policy grants. The grant must
// be covered by an Allow in the policy. Public and cross-account grants are
// conditional, because the other side's policy is not read. A same-account
// grant is clean, unless an enforcement gate is conditional.
func (e *AWSEvaluator) resourcePolicyVerdict(edge *CloudPermission, gateState PathState) *EvaluationResult {
	stmts, err := parseStatements(edge.Attributes["policy_document"])
	if err != nil {
		return &EvaluationResult{State: Unknown, BlockedBy: "unparseable-resource-policy", EvaluationMethod: "hand-coded-rules"}
	}
	matched := false
	for _, st := range stmts {
		if st.Effect == "Allow" && awsStatementCovers(st, edge.Action) &&
			awsResourceCovers(st, edge.Target.CanonicalID) && awsPrincipalCovers(st, edge.Source.CanonicalID) {
			matched = true
			break
		}
	}
	if !matched {
		return &EvaluationResult{State: Blocked, BlockedBy: "implicit-deny", EvaluationMethod: "hand-coded-rules"}
	}

	switch edge.Source.Kind {
	case "public":
		return &EvaluationResult{State: ConditionallyReachable, UnresolvedConds: []string{publicAccessCondition},
			AllowedBy: "resource-policy", EvaluationMethod: "hand-coded-rules"}
	case "external-principal", "external-account-root":
		return &EvaluationResult{State: ConditionallyReachable, UnresolvedConds: []string{crossAccountCondition},
			AllowedBy: "resource-policy", EvaluationMethod: "hand-coded-rules"}
	}
	if gateState == ConditionallyReachable {
		return &EvaluationResult{State: ConditionallyReachable, UnresolvedConds: []string{awsGateCondition},
			AllowedBy: "resource-policy", EvaluationMethod: "hand-coded-rules"}
	}
	return &EvaluationResult{State: PolicySupported, AllowedBy: "resource-policy", EvaluationMethod: "hand-coded-rules"}
}
