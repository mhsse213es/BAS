# Cloud BAS — QA Test Runbook

Companion to [cloud-mastery-qa-log.md](cloud-mastery-qa-log.md). Everything below is unit-tested with fakes except the `live` group.

Run from the repo root (Git Bash):

```bash
bash scripts/cloud-qa.sh all        # every cloud group (Docker needed for db)
bash scripts/cloud-qa.sh <group>    # one group
```

| Group | Package | What it proves | Accounts needed |
|---|---|---|---|
| `retry` | cloudgraph | throttling/backoff, redaction, bounded retries | none |
| `aws` | cloudgraph | AWS discovery, policy matching, trust, backup vaults, permission boundaries, SCPs | none |
| `gcp` | cloudgraph | GCP bindings, roles, deny rules, folder and organization inheritance, retry transport | none |
| `azure` | cloudgraph | Azure discovery, wildcard roles, deny assignments, management group inheritance, preflight | none |
| `audit` | cloudgraph | CloudTrail, Activity Log and GCP audit parsing and matching | none |
| `scenario` | cloudgraph | scenario verdicts, gates, observation, wildcard grants | none |
| `db` | db | cloud_runs lifecycle for plan and scenario runs | Docker |
| `api` | api | discover and scenario validation, credential refusal, account mismatch | none |
| `live` | cloudgraph | **LIVE** Azure integration (build tag `integration`) | live tenant and env vars |

## Test names by group

### `retry`  (8 tests)

- `TestBackoff_BoundedByMaxDelay`
- `TestDoWithRetry_ContextCancelStopsWithoutRetry`
- `TestDoWithRetry_ExhaustedReturnsLastRetryableResponse`
- `TestDoWithRetry_ForbiddenIsNeverRetried`
- `TestDoWithRetry_RetriesThrottleThenSucceeds`
- `TestDoWithRetry_TransportErrorExhaustedReturnsError`
- `TestParseRetryAfter`
- `TestRedact`

### `aws`  (29 tests)

- `TestAWSDecodePolicy_CompactsAndRejectsGarbage`
- `TestAWSDiscover_EdgesAreEvaluableByAWSEvaluator`
- `TestAWSDiscover_ExplicitDenyBlocksAllow`
- `TestAWSDiscover_FailsFastOnBucketListError`
- `TestAWSDiscover_FailsFastOnIAMError`
- `TestAWSDiscover_GroupPolicyInheritedByUser`
- `TestAWSDiscover_IdentitiesAndResources`
- `TestAWSDiscover_MultiHopReachesBucketThroughRole`
- `TestAWSDiscover_NotResourceStatementEmitsNoWildcardEdge`
- `TestAWSDiscover_PaginatesAuthorizationDetails`
- `TestAWSDiscover_RoleTrustRequiresIdentityPolicyAllowingAssume`
- `TestAWSDiscover_URLEncodedDocumentDecoded`
- `TestAWSDiscover_UnresolvableTrustPrincipalsCounted`
- `TestAWSEnforcement_ConditionalSCPDenyIsConditional`
- `TestAWSEnforcement_LevelsRoundTripThroughEdgeAttribute`
- `TestAWSEnforcement_NotInOrganizationSkipsSCPsVisibly`
- `TestAWSEnforcement_OrganizationsAccessDeniedFailsPass`
- `TestAWSEnforcement_PermissionsBoundaryAllowingActionKeepsGrant`
- `TestAWSEnforcement_PermissionsBoundaryBlocksActionOutsideIt`
- `TestAWSEnforcement_SCPDenyAtOUBlocksEveryAccount`
- `TestAWSEnforcement_SCPLevelWithoutAllowBlocks`
- `TestAWSEnforcement_UnresolvedBoundaryIsUnknownNotGranted`
- `TestAWSEvaluator_ActionNameIsMatchedWholeNotAsSubstring`
- `TestAWSEvaluator_AllowedByIdentityPolicy`
- `TestAWSEvaluator_BlockedByExplicitDeny`
- `TestAWSEvaluator_ImplicitDenyWhenNoMatchingStatement`
- `TestAWSEvaluator_RoleTrustAllowsAssumeRole`
- `TestAWSEvaluator_ServiceWildcardSatisfiesConcreteAction`
- `TestAWSGate_ActionNotActionAndConditions`

### `gcp`  (10 tests)

- `TestGCPAncestors_FolderGrantReachesProjectWithProvenance`
- `TestGCPAncestors_OrganizationDenyBlocksFolderGrant`
- `TestGCPAncestors_UnrecognizedAncestorTypeFailsClosed`
- `TestGCPDenyPermissionNormalised`
- `TestGCPDenyPrincipalMapping`
- `TestGCPDiscover_BindingsBecomeEvaluableEdges`
- `TestGCPDiscover_ConditionalBindingProducesNoEdges`
- `TestGCPDiscover_DenyRuleBlocksMatchingEdge`
- `TestGCPDiscover_TransientFailureIsRetried`
- `TestGCPDiscover_UnreadableRoleFailsPass`

### `azure`  (37 tests)

- `TestAncestorManagementGroups_ForbiddenTreeNamesTheGap`
- `TestAncestorManagementGroups_SubscriptionNotVisibleFailsClosed`
- `TestAttachAzureDenies_EveryoneDenyReachesNonExcludedPrincipal`
- `TestAttachAzureDenies_ExcludedPrincipalNotDenied`
- `TestAttachAzureDenies_ScopedDenyBlocksOnlyItsScope`
- `TestAzureAnyPatternMatches_DenyPatterns`
- `TestAzureEvaluator_DenyAssignmentOverridesRoleAssignment`
- `TestAzureEvaluator_NoMatchingRoleReturnsImplicitDeny`
- `TestAzureEvaluator_ResourceGroupScopeDoesNotGrantSiblingResourceGroup`
- `TestAzureEvaluator_SubscriptionScopeRoleInheritsToResourceGroup`
- `TestAzurePreflight_AllGapsClosedPasses`
- `TestAzurePreflight_MissingAdminConsentNamedAsCause`
- `TestAzurePreflight_MissingSubscriptionNamedAsCause`
- `TestAzurePreflight_TokenFailureSkipsDependentChecks`
- `TestAzureWildcardNotActions_CarveOutHonoured`
- `TestAzureWildcardOwner_CoversConcreteStepsBelowSubscription`
- `TestAzureWildcardOwner_DenyAtResourceGroupBlocksResource`
- `TestAzureWildcardSuffix_ReadOnly`
- `TestDiscoverDenyAssignments_CountsAndExactScope`
- `TestDiscoverIdentities_FollowsGraphPagination`
- `TestDiscoverIdentities_GraphHTTPError_FailsFastNoPartialResults`
- `TestDiscoverIdentities_NormalizesUsersAndServicePrincipals`
- `TestDiscoverIdentities_RepeatedNextLinkReturnsErrorNotInfiniteLoop`
- `TestDiscoverPermissions_DiscoveredEdgeEvaluatesViaUnmodifiedAzureEvaluator`
- `TestDiscoverPermissions_ExcludesNotActionsAndIncludesDataActions`
- `TestDiscoverPermissions_MapsRoleAssignmentToOneEdgePerAction`
- `TestDiscoverPermissions_MultipleUnresolvedPrincipalsAllCounted`
- `TestDiscoverPermissions_RoleDefinitionFetchError_FailsFastNoPartialResults`
- `TestDiscoverPermissions_RoleDefinitionFetchedOnceAndCached`
- `TestDiscoverPermissions_ScopeFallbackSynthesizesResourceGroupResource`
- `TestDiscoverResources_FollowsARMPagination`
- `TestDiscoverResources_NormalizesARMResources`
- `TestInheritedAssignment_OtherSubscriptionGrantsIgnored`
- `TestInheritedDeny_BlocksSubscriptionAndDropsExactScopeOnly`
- `TestInheritedOwner_ReachesSubscriptionResource`
- `TestMgPathTo_ReturnsRootFirstPathToParent`
- `TestScopeKind_ClassifiesByExactShape`

### `audit`  (21 tests)

- `TestActivityLogSource_FilterCarriesTimeWindowAndCaller`
- `TestActivityLogSource_ForbiddenIsErrorNotEmpty`
- `TestActivityLogSource_NormalizesAndFollowsNextLink`
- `TestCloudTrailEventName`
- `TestCloudTrailSource_APIErrorSurfaces`
- `TestCloudTrailSource_FollowsNextTokenAndFiltersByEventName`
- `TestEventCorrelator_EventOutsideWindowIsExcluded`
- `TestEventCorrelator_FindEventsDelayedEvent`
- `TestEventCorrelator_FindEventsPartialMatch`
- `TestEventCorrelator_FindEventsPerfectMatch`
- `TestEventCorrelator_NoEventFound`
- `TestGCPAuditLogSource_NormalizesEntries`
- `TestGCPCanonicalResource`
- `TestGCPEmailFromCanonical`
- `TestLiveCorrelator_FetchErrorIsUnavailableNotZero`
- `TestLiveCorrelator_PerfectMatchScoresHigh`
- `TestLiveCorrelator_TruncatedSearchIsPartial`
- `TestParseCloudTrailEvent_ErrorCodeIsFailure`
- `TestParseCloudTrailEvent_FallsBackToSummaryFields`
- `TestParseCloudTrailEvent_NormalizesRecord`
- `TestParseCloudTrailEvent_OneEventPerResource`

### `scenario`  (13 tests)

- `TestAWSDiscoveryFeedsBackupScenario`
- `TestBuiltinCloudScenarios_WellFormed`
- `TestExecuteCloudScenario_FullyOpenWhenEveryStepAllowed`
- `TestExecuteCloudScenario_GateRefusesUnknownEdgeAsInconclusive`
- `TestExecuteCloudScenario_MissingIdentityNotAttempted`
- `TestExecuteCloudScenario_MissingVaultNotAttempted`
- `TestExecuteCloudScenario_NoPermissionsFullyBlockedAtFirstStep`
- `TestExecuteCloudScenario_PartialWhenEarlyStepsAllowed`
- `TestExecuteCloudScenario_WildcardGrantCoversConcreteSteps`
- `TestExecuteCloudScenario_WildcardResourceEdgeCoversVault`
- `TestGlobMatch`
- `TestObserveCloudScenario_EvidenceDecidesOutcome`
- `TestObserveCloudScenario_FailureEvidenceReadsAsBlocked`

### `db`  (6 tests)

- `TestExecuteCloudPlanRun_DiscoveredGraphDrivesPath`
- `TestExecuteCloudPlanRun_DiscoveryFailureMarksRowFailed`
- `TestExecuteCloudScenarioRun_DiscoveryErrorFailsRow`
- `TestExecuteCloudScenarioRun_LiveDiscoveryGivesPartialVerdict`
- `TestExecuteCloudScenarioRun_ObservedMissingEvidenceIsUnknown`
- `TestExecuteCloudScenarioRun_ProviderMismatchFailsRow`

### `api`  (7 tests)

- `TestAccountChecked_InnerErrorIsRedacted`
- `TestAccountChecked_MismatchFailsBeforeInventory`
- `TestCloudDiscovererFor_AzureNamesMissingVariableNotValue`
- `TestCloudDiscovererFor_AzureRejectsSubscriptionMismatch`
- `TestCloudDiscovererFor_UnknownProviderRejected`
- `TestValidateCloudPlanRunRequest_DiscoverAndEdgesMutuallyExclusive`
- `TestValidateCloudScenarioRunBody`

### `live` (not in `all`)

Gated by `//go:build integration`; reads tenant credentials from the environment. Run only after `Preflight` is all PASS. See O-1 in the QA log.

```bash
cd orchestrator
go test -tags=integration ./internal/cloudgraph -run TestAzureDiscovery_Integration -v
```
