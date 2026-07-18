# Phase 7, Sub-project 2 (Identity & Access) — Part 1: RBAC Permission Expansion — Design

**Status:** approved
**Date:** 2026-07-18

## Context

Phase 7 (Enterprise Platform) was decomposed into 5 sub-projects: Multi-Tenancy (done, foundation-only — see `2026-07-18-phase7-multi-tenancy-design.md`), Identity & Access, API Rate Limiting, HA & Horizontal Scaling, Plugin Framework & Connector SDK.

Identity & Access itself bundles three independent pieces — SSO (SAML/OIDC), SCIM provisioning, and RBAC expansion. RBAC expansion was chosen to go first: it has no external dependency (SSO/SCIM both need an IdP integration), and it builds directly on the existing `Role`/`Permission` system and the tenant model Multi-Tenancy just shipped.

The current authorization model has two mechanisms operating side by side:
- **Coarse role gates** (`auth.RequireRole(...)`) applied to two big route groups in `routes.go` — one for Admin+Analyst (34 routes), one for Admin-only (51 routes). Every route in a group shares one all-or-nothing check.
- **Fine-grained permissions** (`auth.Permission` + `auth.RequirePermission(...)`) — but only for two feature areas: Detection Validation verification actions (`verification:verify`, `verification:evidence:upload`, `verification:evidence:delete`, `verification:review`, `verification:export`) and the CVE↔ATT&CK Relationship Store (`threatintel:curate`, `threatintel:review`).

This split means most of the platform's sensitive actions (user management, connector configuration, exercise authoring, scenario execution, etc.) are gated by role alone, with no way to grant or withhold access to one of those 85 actions independently of the other 84 in its group.

## Decision

**Extend every currently role-gated route to its own named `Permission`, with the default grant map reproducing today's exact behavior.** This is a mechanical migration, not a new access model: nothing any role can do today changes. What changes is the mechanism — every sensitive action becomes independently permission-gated, which is what a future custom-role or SSO-group-to-role-mapping feature will need to build on without another repo-wide sweep.

Scope boundaries, confirmed during brainstorming:
- **No new roles.** Still exactly Admin/Analyst/Viewer.
- **No per-tenant custom permission grants.** The grant map is global (same for every tenant), same as role behavior is today. Custom per-tenant roles are explicitly a *future* sub-project, not this one.
- **No UI changes.** `/api/me/permissions` already returns `auth.Permissions(role)` generically — the returned list simply grows. The one existing UI consumer (`wwwroot/index.html`'s verification tab) reads it as an open-ended array and is unaffected.
- **No new restrictions on previously-open routes.** Only routes currently behind `RequireRole` are converted. Routes open to any authenticated user (most GETs) stay that way — this migration doesn't add gates that didn't exist.
- **`auth.RequireRole` is deleted once both call sites are converted.** A grep across the repo confirms `routes.go:203` and `routes.go:308` are its only two callers; once gone, the function and its dedicated middleware test are dead code and get removed per this project's standing "no unused code" rule.

## Permission naming convention

`<domain>:<action>`, extending the existing pattern (`verification:verify`, `threatintel:curate`). Where a domain already separates read/write/config concerns in its route comments (e.g. "SIEM Correlation — connector management (Admin only)" vs. "SIEM Correlation — trigger and results (Analyst+)"), the permission name reflects that distinction directly.

## Full permission inventory

### Group A — currently `RequireRole(RoleAdmin, RoleAnalyst)`, 34 routes → granted to Admin + Analyst

| Method | Path | Handler | New Permission |
|---|---|---|---|
| POST | `/api/scan/{agentId}` | `TriggerScan` | `scan:trigger` |
| POST | `/api/attackpath/collect/{agentId}` | `DispatchAttackPathCollect` | `attackpath:collect` |
| POST | `/api/attackpath/jobs` | `CreateAttackPathJob` | `attackpath:jobs:create` |
| POST | `/api/attackpath/jobs/{id}/cancel` | `CancelAttackPathJob` | `attackpath:jobs:cancel` |
| POST | `/api/attackpath/jobs/{id}/retry` | `RetryAttackPathJob` | `attackpath:jobs:retry` |
| POST | `/api/attackpath/assets` | `SetAttackPathAsset` | `attackpath:assets:set` |
| POST | `/api/scenarios/{id}/run` | `RunScenario` | `scenarios:run` |
| POST | `/api/caldera/adversaries/{adversaryId}/run` | `RunCalderaAdversary` | `caldera:adversaries:run` |
| POST | `/api/adversary-templates/{id}/run` | `RunAdversaryTemplate` | `adversary-templates:run` |
| POST | `/api/scenarios/runs/{runId}/cancel` | `CancelRun` | `scenarios:runs:cancel` |
| POST | `/api/siem/correlate/{runId}` | `TriggerSIEMCorrelation` | `siem:correlate` |
| GET | `/api/siem/correlations/{runId}` | `GetSIEMCorrelations` | `siem:correlations:view` |
| POST | `/api/detectverify/run/{runId}` | `TriggerDetectionVerification` | `detectverify:run` |
| POST | `/api/campaigns` | `CreateCampaign` | `campaigns:create` |
| POST | `/api/campaigns/{id}/stop` | `StopCampaign` | `campaigns:stop` |
| POST | `/api/findings/{id}/status` | `SetFindingStatus` | `findings:set-status` |
| POST | `/api/ticketing/push` | `PushFindingToITSM` | `ticketing:push` |
| POST | `/api/ticketing/push/bulk` | `BulkPushToITSM` | `ticketing:push-bulk` |
| POST | `/api/scenarios` | `CreateScenario` | `scenarios:create` |
| POST | `/api/scenarios/upload` | `UploadScenario` | `scenarios:upload` |
| POST | `/api/scenarios/{id}/clone` | `CloneScenario` | `scenarios:clone` |
| PUT | `/api/scenarios/{id}` | `UpdateScenario` | `scenarios:update` |
| DELETE | `/api/scenarios/{id}` | `DeleteScenario` | `scenarios:delete` |
| POST | `/api/variants/generate` | `GenerateVariants` | `variants:generate` |
| POST | `/api/variants/run` | `RunVariants` | `variants:run` |
| GET | `/api/variants/run/{id}` | `GetVariantRun` | `variants:run:view` |
| GET | `/api/variants/coverage` | `GetVariantCoverage` | `variants:coverage:view` |
| GET | `/api/variants/stats` | `GetVariantStats` | `variants:stats:view` |
| GET | `/api/payload-families` | `GetPayloadFamilies` | `payload-families:list` |
| GET | `/api/payload-families/{techniqueId}` | `GetTechniqueFamilies` | `payload-families:view` |
| POST | `/api/exercises/executions/{id}/launch` | `LaunchExerciseExecution` | `exercises:executions:launch` |
| POST | `/api/exercises/executions/{id}/abort` | `AbortExerciseExecution` | `exercises:executions:abort` |
| POST | `/api/exercises/executions/{id}/steps/{stepId}/approve` | `ApproveExerciseStep` | `exercises:executions:approve-step` |
| POST | `/api/exercises/executions/{id}/evidence` | `InjectEvidence` | `exercises:executions:inject-evidence` |

### Group B — currently `RequireRole(RoleAdmin)`, 51 routes → granted to Admin only

| Method | Path | Handler | New Permission |
|---|---|---|---|
| PUT | `/api/agents/{agentId}/state` | `SetAgentState` | `agents:set-state` |
| GET | `/api/license` | `GetLicenseInfo` | `license:view` |
| GET | `/api/config/connection` | `GetConnectionConfig` | `config:view-connection` |
| GET | `/api/users` | `ListUsers` | `users:list` |
| POST | `/api/users` | `CreateUser` | `users:create` |
| PUT | `/api/users/{id}` | `UpdateUser` | `users:update` |
| DELETE | `/api/users/{id}` | `DeleteUser` | `users:delete` |
| POST | `/api/users/{id}/reset-password` | `ResetPassword` | `users:reset-password` |
| GET | `/api/caldera/status` | `GetCalderaStatus` | `caldera:status:view` |
| GET | `/api/connector/status` | `GetConnectorStatus` | `connector:status:view` |
| POST | `/api/connector/sync` | `TriggerConnectorSync` | `connector:sync` |
| DELETE | `/api/connector/scenarios/{id}` | `DeleteIntelScenario` | `connector:scenarios:delete` |
| POST | `/api/attackpath/schedule` | `SetAttackPathSchedule` | `attackpath:schedule:set` |
| GET | `/api/art/content/status` | `GetARTContentStatus` | `art-content:status:view` |
| POST | `/api/art/content/reseed` | `ReseedART` | `art-content:reseed` |
| GET | `/api/tamper-events` | `GetTamperEvents` | `tamper:events:view` |
| POST | `/api/tamper-events/{id}/acknowledge` | `AcknowledgeTamperEvent` | `tamper:events:acknowledge` |
| POST | `/api/tamper-events/acknowledge-all` | `AcknowledgeAllTamperEvents` | `tamper:events:acknowledge-all` |
| GET | `/api/audit-logs` | `GetAuditLogs` | `audit-logs:view` |
| GET | `/api/ticketing/configs` | `ListTicketingConfigs` | `ticketing:configs:list` |
| POST | `/api/ticketing/configs` | `CreateTicketingConfig` | `ticketing:configs:create` |
| PUT | `/api/ticketing/configs/{id}` | `UpdateTicketingConfig` | `ticketing:configs:update` |
| DELETE | `/api/ticketing/configs/{id}` | `DeleteTicketingConfig` | `ticketing:configs:delete` |
| POST | `/api/ticketing/configs/{id}/test` | `TestTicketingConfig` | `ticketing:configs:test` |
| POST | `/api/ticketing/probe` | `ProbeTicketingConfig` | `ticketing:probe` |
| POST | `/api/ticketing/probe/projects` | `ProbeListProjects` | `ticketing:probe-projects` |
| POST | `/api/ticketing/sync` | `TriggerTicketingSync` | `ticketing:sync` |
| POST | `/api/payload-families` | `CreatePayloadFamily` | `payload-families:create` |
| DELETE | `/api/payload-families/{id}` | `DeletePayloadFamily` | `payload-families:delete` |
| GET | `/api/siem/configs` | `ListSIEMConfigs` | `siem:configs:list` |
| POST | `/api/siem/configs` | `CreateSIEMConfig` | `siem:configs:create` |
| PUT | `/api/siem/configs/{id}` | `UpdateSIEMConfig` | `siem:configs:update` |
| DELETE | `/api/siem/configs/{id}` | `DeleteSIEMConfig` | `siem:configs:delete` |
| POST | `/api/siem/configs/{id}/test` | `TestSIEMConfig` | `siem:configs:test` |
| GET | `/api/detectverify/configs` | `ListDetectionConnectors` | `detectverify:configs:list` |
| POST | `/api/detectverify/configs` | `CreateDetectionConnector` | `detectverify:configs:create` |
| PUT | `/api/detectverify/configs/{id}` | `UpdateDetectionConnector` | `detectverify:configs:update` |
| DELETE | `/api/detectverify/configs/{id}` | `DeleteDetectionConnector` | `detectverify:configs:delete` |
| POST | `/api/detectverify/configs/{id}/test` | `TestDetectionConnector` | `detectverify:configs:test` |
| GET | `/api/openaev/config` | `GetOpenAEVConfig` | `openaev:config:view` |
| PUT | `/api/openaev/config` | `PutOpenAEVConfig` | `openaev:config:update` |
| POST | `/api/openaev/config/test` | `TestOpenAEVConfig` | `openaev:config:test` |
| POST | `/api/openaev/sync` | `SyncOpenAEV` | `openaev:sync` |
| POST | `/api/openaev/import` | `ImportOpenAEVBundle` | `openaev:import` |
| POST | `/api/openaev/scenarios/{id}/create-plan` | `CreateExercisePlanFromOpenAEV` | `openaev:scenarios:create-plan` |
| POST | `/api/exercises/plans` | `CreateExercisePlan` | `exercises:plans:create` |
| POST | `/api/exercises/plans/validate` | `ValidateExercisePlan` | `exercises:plans:validate` |
| PUT | `/api/exercises/plans/{id}` | `UpdateExercisePlan` | `exercises:plans:update` |
| DELETE | `/api/exercises/plans/{id}` | `DeleteExercisePlan` | `exercises:plans:delete` |
| POST | `/api/exercises/templates` | `CreateExerciseTemplate` | `exercises:templates:create` |
| POST | `/api/exercises/templates/{id}/instantiate` | `InstantiateExerciseTemplate` | `exercises:templates:instantiate` |

Total: 85 new `Permission` constants (34 in Group A + 51 in Group B). Combined with the 7 that already exist (`CanVerify`, `CanUploadEvidence`, `CanDeleteEvidence`, `CanReview`, `CanExport`, `CanCurateThreatIntel`, `CanReviewThreatIntel`), `Permissions(RoleAdmin)` will return 92 entries after this change.

## Mechanism

**`internal/auth/permissions.go`:**
- 85 new `Permission` constants, grouped by domain with a one-line comment per domain (not per constant — the table above is the per-constant reference).
- `rolePermissions[RoleAdmin]` gains all 85. `rolePermissions[RoleAnalyst]` gains the 34 from Group A. `rolePermissions[RoleViewer]` gains none — matches today exactly.
- `Permissions(role)`'s ordered constant slice grows to include all 91, so `/api/me/permissions` stays deterministic.

**`internal/api/routes.go`:**
- The two `r.Group(func(r chi.Router) { r.Use(auth.RequireRole(...)) ... })` blocks are removed. Each of their 85 routes becomes a standalone `r.With(auth.RequirePermission(auth.CanXxx)).Method(path, handler)` call, placed where the route currently sits (comments preserved).

**`internal/auth/middleware.go` + `middleware_test.go`:**
- `RequireRole` and its test are deleted (confirmed zero remaining callers after the `routes.go` migration).

**`internal/api/rbac_matrix_test.go`:**
- Every `routeCase` currently tagged `tierAnalystAdmin` or `tierAdminOnly` for one of these 85 routes is retagged `tierPermission` with its `perm` field set to the matching constant. No change to `tierAllows`'s `case tierPermission` branch — it already calls `auth.HasPermission(role, perm)`.
- New test: `TestPermissionGrants_MatchMigrationInventory` — a static table (mirroring this spec's two tables) asserting `rolePermissions[RoleAdmin]` contains all 85, `rolePermissions[RoleAnalyst]` contains exactly the 34 from Group A, and `rolePermissions[RoleViewer]` contains none of the 85. This is the regression guard against silent drift between this table and the actual grant map on any future edit.

## Testing strategy

1. `TestPermissionGrants_MatchMigrationInventory` (new, pure) proves the grant map matches this spec's inventory exactly.
2. `TestRBACMatrix_AuthorizationBoundary` (existing, Docker-backed) drives every route × every role through the real mounted router — since `tierAllows`'s `tierPermission` branch calls the same `HasPermission` the routes now use, this proves end-to-end that the boundary is byte-for-byte identical to pre-migration behavior for all 85 routes.
3. `TestRBACMatrix_NoDrift` (existing) continues to prove every route in `routes.go` has a matrix entry — catches any route accidentally left off during the retagging.
4. Full `internal/api` + `internal/auth` regression, then full repo `go test ./...`, `go build ./...`, `go vet ./...` — same closing rigor as every prior Phase 6/7 slice.

## Out of scope (deferred to later Identity & Access work or other sub-projects)
- Custom/configurable roles (tenant-defined role + permission sets).
- Object-level/cross-resource authorization (per-asset or per-agent access restriction below the role level) — this is the separate "authorization review" item already in the tech-debt backlog.
- SSO (SAML/OIDC) and SCIM provisioning — the other two pieces of Identity & Access, each needing its own brainstorm cycle.
- Authentication hardening (JWT lifetime, refresh tokens, MFA, etc.) — a separate backlog item, not part of RBAC expansion.
