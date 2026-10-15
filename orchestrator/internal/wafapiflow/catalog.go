package wafapiflow

import "fmt"

// AudspectWAFAPIFlowCatalog returns Audspect's real, current seed
// API/business-flow vector catalog: exactly one vector per
// APIFlowCategory, validated before being returned.
func AudspectWAFAPIFlowCatalog() ([]APIFlowVector, error) {
	type seed struct {
		id, name, preconditions, provenance string
		category                            APIFlowCategory
		severity                            Severity
		malicious, benign                   RequestTemplate
		standards                           StandardsMapping
	}
	seeds := []seed{
		{
			id: "APIFLOW-001", category: CategorySchemaConformance, name: "Negative-Quantity Schema Violation", severity: SeverityHigh,
			preconditions: "checkout API's OpenAPI schema declares quantity as a positive integer (minimum: 1)",
			malicious: RequestTemplate{Method: "POST", Path: "/api/checkout/items", PayloadLocation: "body:quantity", Payload: `{"itemId": "SKU-1001", "quantity": -1}`,
				Description: "submits a negative quantity for a checkout line item, where the schema declares quantity as a positive integer, attempting a negative-quantity refund/credit abuse"},
			benign: RequestTemplate{Method: "POST", Path: "/api/checkout/items", PayloadLocation: "body:quantity", Payload: `{"itemId": "SKU-1001", "quantity": 2}`,
				Description: "submits a valid positive quantity for the same checkout line item"},
			standards: StandardsMapping{CWEIDs: []string{"CWE-1284"}}, provenance: "manually authored from waf.txt Phase 5's named API-schemas category",
		},
		{
			id: "APIFLOW-002", category: CategoryAuthBoundary, name: "Wrong-Scope Token Boundary Bypass", severity: SeverityHigh,
			preconditions: "profile-update endpoint requires a bearer token carrying the write:profile scope",
			malicious: RequestTemplate{Method: "PATCH", Path: "/api/users/me/profile", PayloadLocation: "header:Authorization", Payload: "Bearer <token with scope=read:profile>",
				Description: "uses a validly-signed bearer token carrying only read:profile scope to call a write:profile-scoped endpoint, attempting a scope-boundary bypass"},
			benign: RequestTemplate{Method: "PATCH", Path: "/api/users/me/profile", PayloadLocation: "header:Authorization", Payload: "Bearer <token with scope=write:profile>",
				Description: "uses a bearer token actually carrying the write:profile scope the endpoint requires"},
			standards: StandardsMapping{CWEIDs: []string{"CWE-285"}}, provenance: "manually authored from waf.txt Phase 5's named authentication-boundaries category",
		},
		{
			id: "APIFLOW-003", category: CategorySensitiveWorkflow, name: "Password-Reset Token Replay", severity: SeverityCritical,
			preconditions: "password-reset tokens are declared single-use",
			malicious: RequestTemplate{Method: "POST", Path: "/api/password-reset/confirm", PayloadLocation: "body:token", Payload: `{"token": "<token already consumed by a completed reset>", "newPassword": "NewPass123!"}`,
				Description: "replays a password-reset token already consumed by a completed reset, attempting to set a new password a second time with the same single-use token"},
			benign: RequestTemplate{Method: "POST", Path: "/api/password-reset/confirm", PayloadLocation: "body:token", Payload: `{"token": "<freshly issued, not-yet-consumed token>", "newPassword": "NewPass123!"}`,
				Description: "uses a freshly issued, not-yet-consumed password-reset token for the identical set-new-password operation"},
			standards: StandardsMapping{CWEIDs: []string{"CWE-294"}}, provenance: "manually authored from waf.txt Phase 5's named sensitive-workflows category",
		},
		{
			id: "APIFLOW-004", category: CategoryGraphQLAbuse, name: "Unbounded GraphQL Query Depth", severity: SeverityHigh,
			preconditions: "GraphQL endpoint allows recursive field selections with no server-enforced depth limit",
			malicious: RequestTemplate{Method: "POST", Path: "/graphql", PayloadLocation: "body:query", Payload: "query { user(id: 1) { friends { friends { friends { /* ~50 levels deep */ } } } } }",
				Description: "submits a GraphQL query with ~50 levels of nested recursive field selections, attempting to exhaust backend resources via unbounded query depth"},
			benign: RequestTemplate{Method: "POST", Path: "/graphql", PayloadLocation: "body:query", Payload: "query { user(id: 1) { friends { id name } } }",
				Description: "submits the same query shape at a shallow, reasonable depth (2 levels) a legitimate client would send"},
			standards: StandardsMapping{CWEIDs: []string{"CWE-400"}}, provenance: "manually authored from waf.txt Phase 5's named GraphQL category",
		},
		{
			id: "APIFLOW-005", category: CategoryResourceControl, name: "Unbounded Bulk-Export Limit", severity: SeverityHigh,
			preconditions: "bulk-export endpoint accepts a caller-supplied limit query parameter with no server-enforced maximum",
			malicious: RequestTemplate{Method: "GET", Path: "/api/records/export", PayloadLocation: "query:limit", Payload: "?limit=999999999",
				Description: "requests the bulk-export endpoint with an unbounded limit parameter, attempting to exfiltrate the entire dataset in a single call"},
			benign: RequestTemplate{Method: "GET", Path: "/api/records/export", PayloadLocation: "query:limit", Payload: "?limit=100",
				Description: "requests the same export endpoint with a limit value within the endpoint's intended bound"},
			standards: StandardsMapping{CWEIDs: []string{"CWE-770"}}, provenance: "manually authored from waf.txt Phase 5's named resource-controls category",
		},
	}

	var out []APIFlowVector
	for _, sd := range seeds {
		benign := sd.benign
		v, err := NewAPIFlowVector(sd.id, 1, sd.category, sd.name, sd.severity, sd.preconditions, sd.malicious, &benign, "", sd.standards, sd.provenance)
		if err != nil {
			return nil, fmt.Errorf("loading seed API-flow catalog: %w", err)
		}
		out = append(out, v)
	}

	if err := ValidateAPIFlowCatalog(out); err != nil {
		return nil, fmt.Errorf("seed API-flow catalog failed validation: %w", err)
	}
	return out, nil
}
