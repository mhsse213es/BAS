# Azure Real Discovery Integration — Design Spec

**Date:** 2026-10-12
**Status:** Approved (conversational design), awaiting written-spec review
**Initiative:** Real Cloud Integration (the explicit "deferred" list from `docs/cloud-bas-capabilities-summary.md`) — first milestone

## Context

Cloud BAS Phases 1-5 (`orchestrator/internal/cloudgraph/`) are complete: 14 files, 66 tests, a full Layer A/B/C architecture (`CloudResource`/`CloudIdentity`/`CloudPermission`/`PathState`, `AWSEvaluator`/`AzureEvaluator`/`GCPEvaluator`, prerequisite resolution, multi-account execution, AD-cloud hybrid federation, a ransomware kill-chain pattern) — but **entirely against synthetic fixtures**. No AWS/Azure/GCP SDK call has ever been made; no real audit log has ever been queried. `docs/cloud-bas-capabilities-summary.md` states this plainly and lists what's deferred.

This spec covers the **first step** of closing that gap: real, read-only discovery against a real Azure tenant, proving that real Azure data normalizes correctly into the existing Phase 1 types and plugs into the existing Phase 4 `AzureEvaluator` without changes to that evaluator.

## Scope

**In scope:** Connect to a real Azure tenant via a service principal, enumerate identities (Entra users and service principals), resources (via Azure Resource Manager), and role assignments (role-based permissions), normalize all three into `CloudIdentity`/`CloudResource`/`CloudPermission`.

**Explicitly out of scope (deferred to later milestones):**
- Live policy evaluation against real role assignments (comparing `AzureEvaluator`'s prediction to Azure's actual behavior)
- Real attack-path execution (actually assuming roles, actually accessing resources)
- Real Activity Log correlation (the cloud-native equivalent of Phase 2's `SyntheticEventCorrelator`)
- AWS or GCP real integration (this spec is Azure-only; AWS/GCP follow the same pattern in later milestones once this one is proven)
- Wiring any of this into the live orchestrator scenario dispatcher

## Target Environment

- **Tenant:** `essen065.onmicrosoft.com` — a dedicated, empty, synthetic test tenant with no real production workloads, employee accounts, or customer data. Confirmed safe for real discovery now and real controlled attack-path validation later (a later milestone).
- **Auth:** Service principal with client secret (Entra app registration, to be created as a one-time admin action; tenant ID / client ID / client secret / target subscription ID supplied via environment variables).

## Architecture

### Reuse: `msauth.EntraTokenSource`

`orchestrator/internal/platform/msauth` already implements the OAuth client-credentials flow this integration needs — `NewEntraTokenSource(tenantID, clientID, clientSecret, scope string) *EntraTokenSource` with a `Token(ctx) (string, error)` method. It is currently used by `internal/vendors/defender/client.go` for Microsoft Graph calls. This integration reuses it unchanged for two scopes: `https://graph.microsoft.com/.default` (identities) and `https://management.azure.com/.default` (resources, role assignments) — the same tenant/app registration, two different resources, exactly the pattern `defender.Client` already uses for its two token sources (Graph alerts vs. Defender machine-actions).

### New files

`orchestrator/internal/cloudgraph/azure_discovery.go` + `azure_discovery_test.go` — flat files in the existing `cloudgraph` package, matching the one-file-per-concern convention already established by `aws_evaluator.go`/`azure_evaluator.go`/`gcp_evaluator.go`.

### Config & Client

```go
type AzureDiscoveryConfig struct {
    TenantID       string
    ClientID       string
    ClientSecret   string
    SubscriptionID string // ARM calls are scoped to one subscription
}

type AzureDiscoveryClient struct {
    GraphBaseURL   string // https://graph.microsoft.com/v1.0 (overridable for tests)
    ARMBaseURL     string // https://management.azure.com (overridable for tests)
    graphTokens    *msauth.EntraTokenSource // scope: https://graph.microsoft.com/.default
    armTokens      *msauth.EntraTokenSource // scope: https://management.azure.com/.default
    httpClient     *http.Client
    subscriptionID string
}

func NewAzureDiscoveryClient(cfg AzureDiscoveryConfig) *AzureDiscoveryClient
```

Two token sources because Graph and ARM are different resources under the same tenant/app registration, mirroring why `defender.Client` holds two (`tokens` for Graph alerts, `actionTokens` for the Defender machine-actions API).

### Discovery Methods

```go
func (c *AzureDiscoveryClient) DiscoverIdentities(ctx context.Context) ([]*CloudIdentity, *DiscoveryStats, error)
func (c *AzureDiscoveryClient) DiscoverResources(ctx context.Context) ([]*CloudResource, *DiscoveryStats, error)
func (c *AzureDiscoveryClient) DiscoverPermissions(ctx context.Context, identities []*CloudIdentity, resources []*CloudResource) ([]*CloudPermission, *DiscoveryStats, error)
```

`DiscoverPermissions` takes the already-discovered identities and resources because role assignments reference them by ID — it correlates rather than re-discovers.

```go
// DiscoveryStats reports what happened during one discovery call, including
// anything that couldn't be resolved -- never silently dropped.
type DiscoveryStats struct {
    ItemsFound           int
    UnresolvedPrincipals int // role assignments whose principalId matched no discovered identity
}
```

## Data Flow & Mapping

### DiscoverIdentities

Two Graph calls, paginated via `@odata.nextLink`:

| Graph endpoint | → | CloudIdentity field |
|---|---|---|
| `GET /users` | each user | `CanonicalID = "azure:user_" + user.id"`, `Kind = "entra-user"`, `Attributes["upn"] = userPrincipalName` |
| `GET /servicePrincipals` | each SP | `CanonicalID = "azure:sp_" + sp.id`, `Kind = "service-principal"`, `Attributes["app_id"] = appId` |

The `"azure:user_"`/`"azure:sp_"` prefix matches the convention Phase 4's hybrid-identity tests already used (`"azure:user_" + entraUserID`), so this is not a new convention.

### DiscoverResources

One ARM call, paginated via ARM's `nextLink`:

| ARM endpoint | → | CloudResource field |
|---|---|---|
| `GET /subscriptions/{sub}/resources?api-version=2021-04-01` | each resource | `CanonicalID = resource.id` (ARM's `id` is already the full hierarchical path, e.g. `/subscriptions/.../resourceGroups/.../storageAccounts/foo` — identical in shape to the Phase 4/5 test fixtures, no transformation needed), `Kind` derived from `resource.type` |

### DiscoverPermissions

Two ARM calls:

1. `GET /subscriptions/{sub}/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01` → each assignment has `principalId` (GUID), `scope` (ARM path), `roleDefinitionId`.
2. For each distinct `roleDefinitionId`: `GET {roleDefinitionId}?api-version=2022-04-01` → `permissions[].actions[]`. Cached per `roleDefinitionId` so a role used by many assignments is fetched once.

Mapping to `CloudPermission`:

- **Source:** the identity whose Graph object ID matches `principalId`. If no discovered identity matches (e.g. a built-in Azure service principal not enumerated by `DiscoverIdentities`), the assignment is skipped and counted in `DiscoveryStats.UnresolvedPrincipals` — never silently dropped without a trace.
- **Target:** a `CloudResource` for the assignment's `scope`. If `scope` matches a discovered resource's `CanonicalID` exactly, reuse it. Otherwise (scope is a subscription or resource group, not a specific resource) synthesize one: `CanonicalID = scope`, and `Kind` by exact path shape — `scope` matching `^/subscriptions/[^/]+$` → `"subscription"`; matching `^/subscriptions/[^/]+/resourceGroups/[^/]+$` → `"resource-group"`; anything else at this fallback level → `"unknown-scope"` (never guessed as one of the two known kinds when the shape doesn't match either pattern).
- **Action:** set to the sentinel `"*"`, meaning "see `role_actions`" — a role assignment grants a *set* of actions, not one specific action, so there is no single correct value here. `AzureEvaluator` already treats `role_actions` (an `Attributes` entry) as the thing it searches, not `Action` as the sole fact, so this sentinel does not require any change to the evaluator.
- **Attributes:** `role_scope = scope`, `role_actions = strings.Join(actions, ",")`, `role_definition_name = <role name>` (for human readability) — this is the exact attribute shape `AzureEvaluator.isRoleAssignmentMatch` (Phase 4) already expects. Real discovered data plugs directly into the Phase 4 evaluator with zero changes there, which is the key validation this milestone buys: if real Azure data normalizes into something the Phase-4-synthetic-fixture-built evaluator can sensibly evaluate, that proves Phase 4's attribute shape generalizes beyond its own test fixtures.
- **SourceType:** `"role-assignment"`.
- **Provenance:** `{Source: "azure:arm-role-assignments", Confidence: "observed"}` on every edge (and the equivalent `azure:graph-users"`/`"azure:graph-service-principals"`/`"azure:arm-resources"` sources on identities/resources) — reusing the Phase 1 `Provenance` type.

## Error Handling

- **Fail-fast:** any transport or auth error aborts the in-progress `Discover*` call and returns `(nil, nil, err)`. No partial results on failure — this milestone is about proving the pipeline is trustworthy, not about resilience, and returning partial data on failure risks a caller treating incomplete discovery as complete. Pagination resilience (collect-what-you-can-then-report on a late page failure) is a reasonable future improvement, not in this milestone's scope.
- **Unresolved principals are not errors** — see `DiscoveryStats.UnresolvedPrincipals` above. Expected and counted, not fatal.
- **Provenance on everything** — every discovered object carries a `Provenance` with `Confidence: "observed"` and a `Source` string naming exactly which API call produced it, consistent with how the rest of `cloudgraph` already treats evidence quality (never claim more certainty than was actually observed).

## Testing

**Two tiers:**

1. **Unit tests (run always, no credentials needed):** `httptest.Server` mocking Graph/ARM JSON responses, following the same approach `defender_test.go` already uses for Defender. Covers: identity normalization (both users and service principals), resource normalization, permission correlation (including the unresolved-principal case and the scope-as-synthetic-resource fallback), pagination following (`@odata.nextLink` and ARM `nextLink`), and the fail-fast error path on a simulated transport failure.

2. **Integration test (opt-in, real tenant):** one test file gated by a build tag (`//go:build integration`), reading `AZURE_TENANT_ID`/`AZURE_CLIENT_ID`/`AZURE_CLIENT_SECRET`/`AZURE_SUBSCRIPTION_ID` from the environment and calling the real `essen065.onmicrosoft.com` tenant. Skipped by default — `go test ./internal/cloudgraph` never touches it. Run explicitly (`go test -tags=integration ./internal/cloudgraph -run TestAzureDiscovery_Integration`) once the service principal exists. This is the only place "verified against the real tenant" can honestly be claimed, following the same discipline Phase 5's capabilities summary established: nothing is marked real until this test has actually been run and its output read by a human or an agent that reports it faithfully.

## Credentials Configuration

Service principal client ID / secret / tenant ID / target subscription ID, loaded from environment variables. The exact loading site (how these reach `AzureDiscoveryConfig` from the orchestrator's existing config/env-loading code, following whatever pattern already populates `defender.Config`) is an implementation-plan detail, confirmed by reading the actual config-loading code rather than guessed here.

## Risks & Mitigations

| Risk | Mitigation |
|------|-----------|
| Service principal doesn't exist yet when implementation starts | Unit tests (tier 1) require no credentials and can be written/run immediately; only the integration test (tier 2) is blocked on the app registration existing |
| Azure API pagination edge cases (empty pages, malformed `nextLink`) | Unit tests explicitly cover pagination following; fail-fast on malformed data rather than looping forever |
| Role assignment scope doesn't match any discovered resource | Explicitly handled via the synthetic-scope-resource fallback, not an error |
| This milestone's `Action = "*"` sentinel breaks `AzureEvaluator` logic | `AzureEvaluator.isRoleAssignmentMatch` never reads `edge.Action` from the stored edge when matching against a *query* edge's action — it reads the query edge's `Action` field to search `role_actions`. The sentinel only affects the *stored/discovered* edge's own `Action` field, which is informational here, not evaluated directly. Worth a focused unit test to pin this down explicitly during implementation. |

## Open Questions (deferred)

- Should discovered permissions expand into one `CloudPermission` per granted action (matching the exact shape `AzureEvaluator`'s synthetic fixtures used) instead of one per role assignment with a `"*"` sentinel? Deferred to the next milestone (live evaluation), once we see how awkward or natural the `"*"` sentinel is to work with in practice.
- AWS and GCP real-discovery equivalents — same pattern, different APIs (AWS: IAM + STS + Resource Groups Tagging API; GCP: Cloud Resource Manager + IAM API) — follow once this Azure milestone is validated end to end.

## Conclusion

This is the smallest safe real-integration step: read-only discovery against a dedicated empty test tenant, reusing an existing, already-proven auth helper (`msauth`), following an existing, already-proven client pattern (`defender.Client`), and normalizing into existing, already-tested types (`CloudIdentity`/`CloudResource`/`CloudPermission`) and an existing, already-tested evaluator (`AzureEvaluator`) without modifying that evaluator. Success criteria: the integration test (tier 2), run once against the real tenant, discovers at least one identity, one resource, and one role assignment, and the discovered `CloudPermission` evaluates sensibly through the unmodified `AzureEvaluator`.
