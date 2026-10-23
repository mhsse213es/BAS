# Cloud BAS Mastery — Repository Reusability Audit

**Date:** 2026-10-12  
**Focus:** Architectural reuse of Audspect's existing AD/ransomware mastery work for cloud attack-path validation (AWS/Azure/GCP/Kubernetes/Microsoft 365).

**Kubernetes status:** in product scope (`docs/superpowers/specs/2026-10-12-cloud-bas-architecture-design.md`). Platforms: EKS, AKS, GKE, OpenShift and K3s (K3s added by user decision, 2026-10-22). Validated: kind (v1.32.2) and K3s (v1.32.2, single-node k3d cluster `k3d-bas-k3s`, 2026-10-22; single-node k3d only, not full K3s platform coverage): discovery complete with no gaps, 24 analysis decisions agree with `kubectl auth can-i`, aggregated ClusterRole check passes. Not validated: EKS, AKS, GKE, OpenShift, multi-node K3s. Incomplete workload chains (unlisted or forbidden owners, owner chains deeper than the limit) are covered by fixture tests. Implemented and validated on a local kind cluster only: read-only discovery (namespaces, pods, workload ownership through ReplicaSet/Deployment, StatefulSet, DaemonSet, Job and CronJob, service accounts, Roles, ClusterRoles, bindings, unresolved and incomplete paths reported as gaps) and configured-permission analysis (namespace scope, implicit groups, resourceNames, wildcards, aggregated ClusterRoles; cross-checked with kubectl auth can-i). Evidence boundaries: configured permission is not effective authorization (other authorizers and admission are not modelled) and not exploitability. Attack-path modelling: configured paths from a workload's service account through eight routes (bind or escalate on ClusterRoles to a secret-reading ClusterRole; impersonate serviceaccounts, create pods, or request a serviceaccounts/token to a secret-reading service account; exec into a pod running one; get nodes/proxy to a pod on any node running one) (`k8s_attackpath.go`). Cross-checked against kubectl auth can-i for the prerequisites (34/34 agree on kind). Configured permission only; an unknown prerequisite produces no path, and incomplete discovery is marked on each path. Not built yet: attack scenarios, and any state-changing test.

---

## 1. SCENARIO EXECUTION MODEL

**Question:** Can YAML scenarios work for cloud tests, or does cloud require a graph-based model?

### EXISTS

- **Scenario Engine** — `orchestrator/internal/scenario/engine.go` — Loads, verifies, and manages YAML scenario definitions from disk; registry integration for TCF Content Registry; signature verification via integrity.Verifier. Reusability: **HIGH**
  - Pure file-based loading (engine.go:100-150); no endpoint/agent coupling in parser
  - Provider registry (scenario/providers.go) already extensible; adding cloud providers is one RegisterProvider() call
  - Step framework supports flexible naming: frameworks include "art", "caldera", "sigma", "custom" (types.go:136)

- **Step Metadata Model** — `orchestrator/internal/scenario/types.go` — PrivSpec (privilege tier), YAMLPayload, Step struct with TechniqueID, Framework, TimeoutSec, CheckID, Risk, BlastRadius. Reusability: **MEDIUM**
  - PrivSpec uses minimum/preferred tiers (admin/user/system) but no concept of cloud-specific contexts (IAM roles, GCP service accounts, Azure RBAC)
  - CheckID field allows non-ATT&CK checks (BitLocker, posture checks) — **cloud can reuse this for IAM/policy checks**
  - MaxOutputBytes handles large evidence (installed-software inventory) — cloud audit logs may be orders of magnitude larger

- **Builder & Interpreter** — `orchestrator/internal/scenario/builder.go`, `interpreter.go` — Converts scenarios → executable steps; applies timeouts, payloads, deduplication. Reusability: **MEDIUM**
  - Builder is framework/executor-agnostic; routes to ART/Caldera/custom handlers
  - No endpoint-level execution logic in builder; orchestrator-side only
  - **Interpreter does not handle async prerequisites** (cloud requires IAM/resource state validation before step execution)

- **ExecutionPolicy & Constraints** — `orchestrator/internal/scenario/types.go:110-112` — Currently only MaxPrivilege. Reusability: **MEDIUM**
  - Deliberately designed as extension point ("future constraints without wire format change")
  - **Cloud needs:** AllowCrossAccount, AllowExternalTenants, RequiredIAMRoles, AssumeRoleARN, SourceNetwork, etc.

### MISSING

1. **Cloud-Specific Prerequisites Model** — Why it matters: Cloud scenarios must declare required IAM roles, resource existence, provider capabilities, account scope BEFORE dispatch
   - Complexity: **MEDIUM** (design: ~2 days; implement: ~5 days)
   - Compare to: AD mastery has adenv/adchain (predicates + reachability); ransomware has gate_not_confirmed pattern (dispatch.go:69-73)

2. **Cloud Step Mapping & Substitution** — Why it matters: Steps need to interpolate cloud identifiers (AWS account ID, Azure tenant ID, GCP project), resource ARNs, IAM role assumptions at dispatch time
   - Complexity: **MEDIUM** (design: ~3 days; similar to {{SINK_URL}} token substitution in handlers.go)

3. **Multi-Account/Subscription/Project Parallelization** — Why it matters: Campaign needs to run same scenario across 10 AWS accounts independently
   - Complexity: **HIGH** (design: orchestration + isolation boundaries; implement: campaign expansion + per-target dispatch)
   - Compare to: Campaign.Aggregate already merges child runs (campaign/campaign.go:100+); cross-account is a NEW dimension

4. **Cloud Resource Readiness Gate** — Why it matters: Wait for async resource provisioning (EC2 startup, Azure VM deployment) before scenario dispatch
   - Complexity: **MEDIUM** (design: ~2 days; requires backend polling infrastructure, not in current async model)

---

## 2. EVIDENCE COLLECTION & STORAGE

**Question:** Can rwevidence layer handle cloud provider events? Does CapabilityResult model support async/delayed evidence?

### EXISTS

- **rwevidence Package** — `orchestrator/internal/rwevidence/{types,dispatch,recovery,containment,detection,dataprotection}.go` — **Ransomware-specific capability-evidence engine** covering 5 dimensions (Prevention, Recovery, Detection, Containment, DataProtection) and 4 techniques (T1490, T1486, T1567.002, T1560.001). Reusability: **HIGH** (pattern, not code)
  - **Key abstraction:** CapabilityResult (types.go:34-46) — Capability, TechniqueID, Verdict, SkipReason, Reason, Provenance (CorrelationKey with RunID/Target/Action/TimeWindow)
  - **Observer interfaces:** RecoveryObserver (recovery.go:24), ContainmentObserver (containment.go:29), DetectionLookup (dispatch.go:86), DataProtectionLookup (dispatch.go:110) — each returns (tested bool, outcome bool, observerID, reason, err)
  - **Fake-backed only in this slice** — real adapters deferred; design is proven, not implementation

- **Evidence Correlation Model** — `orchestrator/internal/rwevidence/types.go:56-60` and `controlval.CorrelationKey` (internal/controlval/controlval.go:97-102) — Time-windowed, per-action evidence joining
  - AttemptKey: RunID, TechniqueID, Action (scenario.TaskID)
  - TimeWindow: Start, End (precise bounds for cloud audit-log queries)
  - **Cloud reusability: HIGH** — 3-tuple (RunID, technique, action) is provider-neutral; cloud logs can be keyed the same way

- **Verdict & SkipReason Taxonomy** — `orchestrator/internal/controlval/controlval.go:126-146` — PASS|FAIL|ERROR|SKIPPED + three skip reasons (insufficient_evidence, not_applicable, not_tested)
  - Used by rwevidence, admatrix, latmove, backupassurance — **unified across ALL validation engines**
  - Reusability: **HIGH** (cloud inherits same 4-verdict model + skip taxonomy)

- **BackupAssurance Observers** — `orchestrator/internal/backupassurance/observers.go` — 6 observer interfaces (DeletionProtection, Immutability, OfflineIsolation, PrivilegeSeparation, RestoreIntegrity, RPORTO) each returning (tested, outcome bool, observerID, reason, err)
  - Shows pattern of per-capability observers; proven fake-backed approach
  - Cloud can reuse exact same interface shape for IAM/policy observers

- **Async Evidence Storage** — `orchestrator/internal/db/rwevidence_store.go` — Persists CapabilityResults, Observations, test state to Postgres
  - **Design already separates execution from evidence collection** — step result persisted immediately; evidence lookups happen later (dispatch.go:EvaluateStep calls Recovery/Containment/Detection/DataProtection interfaces asynchronously)
  - Reusability: **HIGH** (storage is outcome-agnostic; schema can expand for cloud evidence types)

### MISSING

1. **Cloud Audit Log Ingestion Adapters** — Why it matters: Need real-time or batch connectors for AWS CloudTrail, Azure Activity Log, GCP Cloud Audit Logs
   - Complexity: **HIGH** (3+ vendor APIs; 5-7 days per adapter; field-testing required)
   - Pattern exists: detectverify connectors (internal/connector/generator.go, detectverify-related code) show vendor-integration model

2. **Async Polling Infrastructure for Delayed Evidence** — Why it matters: Cloud logs arrive 1-5 minutes after event; current model assumes immediate observation
   - Complexity: **MEDIUM** (design: evidence-readiness queue; implement: background jobs framework)
   - Exists partially: jobs.Store (internal/jobs) for batch remediation suggests a job queue is available

3. **Cloud IAM/Permission Evidence Types** — Why it matters: Need structured evidence for "role assumed", "policy evaluated", "STS token issued", not just yes/no outcomes
   - Complexity: **MEDIUM** (design: new CapabilityResult subtypes or extended Detail field; implement: mapper for 3+ cloud providers)

4. **Multi-Cloud Correlation** — Why it matters: Lateral-movement attempts cross AWS→Azure→Okta; need unified correlation key across cloud providers
   - Complexity: **MEDIUM-HIGH** (design: identity graph linking cloud principals; implement: provider-bridging logic)
   - Compare to: adcontrolval.bridge.go shows hybrid AD-vendor model; cloud needs cloud-to-cloud variant

5. **Evidence Truncation/Streaming** — Why it matters: Cloud audit logs can be 100KB+ per attempt; current MaxOutputBytes is bytes, not streaming
   - Complexity: **LOW** (extend SimulationResult.RawOutput with Truncated/OriginalOutputBytes already exist; reuse for cloud events)

---

## 3. CONTROL-EFFICACY ARCHITECTURE

**Question:** Does ControlOutcome model work for cloud controls? Can it represent cloud-specific outcomes?

### EXISTS

- **Outcome Enum & Evidence Model** — `orchestrator/internal/controlval/controlval.go:18-28` — Six outcomes: Allowed, Blocked, MFAChallenged, Terminated, Quarantined, Unknown
  - **Reusability: HIGH** — MFAChallenged already cloud-ready (Entra, Okta, AWS); Blocked/Terminated already cover most preventative controls

- **Observation & Expectation Model** — `orchestrator/internal/controlval/controlval.go:104-125` — Observation (outcome + confidence + evidence kind + source + timestamp); Expectation (expected outcome + policy basis + verified flag + min confidence)
  - **EvidenceKind distinction:** Observed vs Inferred (lines 45-48) — cloud can use same; AWS CloudTrail/Azure Logs are "Observed"; inferred from deny policies = "Inferred"
  - **CorrelationKey:** RunID, Target, Action, TimeWindow — provider-neutral
  - Reusability: **HIGH**

- **Confidence Grading** — `orchestrator/internal/controlval/controlval.go:52-87` — High/Medium/Low/None; with effectiveFloor (UNSET defaults to High, safe-fail)
  - Matches real cloud control outcomes (AWS CloudTrail shows "RequestParameters" with certainty; Azure Activity Log is event-based, lower fidelity)
  - Reusability: **HIGH**

- **Validation Result Grading** — `orchestrator/internal/controlval/controlval.go:148-200+` (truncated in read, but seen in other files) — Compares Observation to Expectation; yields Verdict + reason
  - No real provider in slice (FakeProvider only); design is test-backed
  - Reusability: **HIGH** (pattern proven; real adapters deferred)

- **AD Control-Efficacy Adapter** — `orchestrator/internal/adcontrolval/bridge.go` and `orchestrator/internal/adefficacy/{provider,dcsync}.go` — Shows how a REAL provider adapter wires into the validation engine
  - DCSync proof-of-concept: observes native AD replication rights; no vendor tool required
  - Reusability: **HIGH** (architectural pattern for cloud: observe cloud IAM native controls, not a third-party vendor)

- **Vendor Integration Pattern** — `orchestrator/internal/vendors/{defender,crowdstrike}/` — Shows how to build real provider clients
  - Defender: Auth (msauth), alert/response queries, caching strategy
  - CrowdStrike: Similar OAuth pattern
  - Reusability: **HIGH** (can model AWS IAM, Azure RBAC, GCP IAM as "providers" following this pattern)

### MISSING

1. **Cloud-Native Control Outcomes** — Why it matters: Need 5+ new outcomes beyond the current 6
   - Examples: DeniedByResourcePolicy, DeniedByServiceControlPolicy, AssumeRoleFailed, TokenRefused, MFABypass, ExternalIdMismatch, SessionBlocked
   - Complexity: **LOW** (add to Outcome enum; ~1 day)
   - Design note: Keep Allowed/Blocked split; add provider-specific detail in Observation.Detail field

2. **Multi-Cloud Provider Adapter Scaffolding** — Why it matters: Need to wire AWS IAM, Azure RBAC, GCP IAM, Okta, Entra as providers
   - Complexity: **HIGH** (3-5 days per provider; OAuth + resource API learning curve)
   - Pattern exists: Defender/CrowdStrike model shows the contract

3. **Cross-Provider Identity Correlation** — Why it matters: Attack path goes AWS→Azure (via STS assume role + Entra app); need unified identity graph
   - Complexity: **HIGH** (design: federation model; implement: identity normalization)
   - Exists partially: threatidentity package (internal/threatidentity) suggests an identity store; needs hybrid AD+cloud extension

4. **Prerequisite-Time Control Evaluation** — Why it matters: Some controls gate scenario dispatch (e.g., "scenario requires MFA policy enabled on tenant")
   - Complexity: **MEDIUM** (design: pre-dispatch expectation checks; implement: cloud-control-query layer)
   - Compare to: adgate/gate.go shows pre-execution authorization gates for AD

5. **SaaS-Native Evidence** — Why it matters: Microsoft 365 (Teams, SharePoint, Exchange) and Okta have NO cloud-audit-log equivalent for some attack paths
   - Complexity: **HIGH** (vendor-by-vendor; some require live API polling, not logs)

---

## 4. CAMPAIGN EXECUTION

**Question:** Can campaigns fan out across cloud accounts/subscriptions/projects with isolation?

### EXISTS

- **Campaign Model** — `orchestrator/internal/campaign/campaign.go` — ChildRun, Skip, Summary structures; DeriveStatus, Aggregate compute campaign state from child runs
  - **Status:** running | completed | partial | failed | empty | stopped
  - **Summary:** Targets, Dispatched, Skipped, Prevented, Detected, Missed, Errored, Paused
  - Reusability: **HIGH** (summary fields are provider-neutral; can accommodate multi-account rollup)

- **Isolation Model** — Campaigns dispatch to agents (one agent = one host). **Each child run is independent** (models/schema.go shows runs have agent_id, target machine, scenario_id, result set)
  - Cloud analogy: agent = one cloud account | target = one resource within that account
  - Reusability: **MEDIUM-HIGH** (structure exists; account-aware targeting needs new dispatch logic)

- **Skip Tracking** — campaign/campaign.go:26-29 — Skip records agent_id + reason (offline, busy, error)
  - Reusability: **HIGH** (accounts that failed to launch scenarios can be tracked the same way)

### MISSING

1. **Multi-Account Campaign Templating** — Why it matters: Operator specifies "run this scenario across 10 AWS accounts, 3 Azure subscriptions, 2 GCP projects" once; system expands to 15 child targets
   - Complexity: **MEDIUM** (design: campaign expansion rules; implement: cloud-provider-aware templating)
   - No current precedent: Audspect is on-prem AD + Windows/Linux endpoints; not multi-tenant/multi-account

2. **Cross-Account Isolation Enforcement** — Why it matters: Scenario run in Account A must not access resources in Account B (even if credentials leaked)
   - Complexity: **HIGH** (design: per-run STS session boundaries; implement: agent credential scoping)
   - Relevant pattern: adlabhyperv/isolation.go shows Hyper-V sandbox isolation; cloud needs IAM/network equivalent

3. **Account State Snapshots** — Why it matters: Scenarios need baseline IAM policies, resources, logs BEFORE campaign launch (for cleanup, evidence detection)
   - Complexity: **MEDIUM** (design: pre-campaign resource inventory; implement: cloud API calls)

4. **Conditional Dispatch by Account Metadata** — Why it matters: "Only run scenario if account has MFA policy AND EDR deployed"
   - Complexity: **MEDIUM** (reuses cloud-control queries from section 3; add dispatch gating)

---

## 5. PROVIDER ADAPTERS & OBSERVERS

**Question:** How are external providers integrated? What's the contract for a new provider?

### EXISTS

- **Provider Registry** — `orchestrator/internal/scenario/providers.go:16-56` — Provider struct: Key, DisplayName, Category (EDR|SIEM|DLP|AV|IDP|CASB|RULESET), DefaultDomain, Verifier
  - RegisterProvider(), LookupProvider(), KnownProviders()
  - **15 providers registered:** Defender, CrowdStrike, SentinelOne, Trellix, Sophos, Carbon Black, Cortex XDR, Purview DLP, Sentinel, Splunk, QRadar, Elastic, Sigma, Entra ID Protection, Defender for Identity
  - Reusability: **HIGH** (can add aws_cloudtrail, azure_activitylog, gcp_cloud_logging, okta_system_log, etc. as new providers)

- **Vendor Integration Pattern** — `orchestrator/internal/vendors/{defender,crowdstrike}/` — Shows Auth (OAuth), API clients, caching, error handling
  - Defender: msauth (Entra token source), graph API client, device cache
  - CrowdStrike: similar OAuth + API pattern
  - Reusability: **HIGH** (AWS SDK, Azure SDK, GCP client libraries follow identical patterns)

- **Observer Interfaces** — `orchestrator/internal/backupassurance/observers.go` — Standard shape: (tested bool, outcome bool, observerID, reason string, err error)
  - controlval.Provider interface (controlval/provider.go:10-12) — Observe(ctx, CorrelationKey) → (Observation, error)
  - RecoveryObserver (rwevidence/recovery.go:24), ContainmentObserver (rwevidence/containment.go:29), etc.
  - Reusability: **HIGH** (cloud observers follow same interface)

- **Fake Implementations** — FakeProvider (controlval/provider.go:26-56), FakeRecoveryObserver (rwevidence/recovery.go:31+), FakeContainmentObserver, FakeDeletionProtectionObserver, etc.
  - All keyed by action; uncaptured keys return zero-value (never guessed)
  - Reusability: **HIGH** (testing pattern; cloud adapters can be fake-backed first, real adapters later)

- **Connector Generator** — `orchestrator/internal/connector/generator.go` — Builds connector configs for external sources
  - Used for threat-intel (OTX), detection-verification (Splunk, Elastic), actions (response playbooks)
  - Reusability: **HIGH** (cloud observability sources follow same pattern)

### MISSING

1. **Cloud-Native Provider Adapters** — Why it matters: Need real implementations for AWS IAM, Azure RBAC, GCP IAM, Azure Activity Log, AWS CloudTrail, GCP Cloud Audit Logs
   - Complexity: **HIGH** (5-10 days per adapter; OAuth + SDK learning)
   - Pattern exists: Defender/CrowdStrike model is the template

2. **Cloud-to-Cloud Evidence Bridging** — Why it matters: Lateral-movement from AWS→Azure requires Entra token → assume role → Azure API; need cross-provider correlation
   - Complexity: **HIGH** (identity federation; STS/OAuth flow modeling)

3. **Provider Capability Discovery** — Why it matters: Know which cloud provider has which observability (AWS CloudTrail has RequestParameters, but not all events; Azure Activity Log is event-only; GCP has more detail in Cloud Logging)
   - Complexity: **MEDIUM** (design: provider-capability matrix; implement: per-provider detail-extraction logic)

4. **Evidence Retention Policy Wiring** — Why it matters: Cloud audit logs expire (AWS: 90 days default; Azure: 30 days; GCP: 30 days); need to know if evidence can be queried post-scenario
   - Complexity: **LOW** (design: provider metadata; implement: readiness checks)

---

## 6. AD MASTERY REUSE

**Question:** Can cloud-to-AD paths reuse AD mastery work? Can Entra/cloud identities link to on-premises AD?

### EXISTS

- **AD Environment Model** — `orchestrator/internal/adenv/types.go` — Full ontology: Forest, Identity (Users, Groups, ServiceAccounts, ComputerAccounts, PrivilegedAccounts), Machines (DCs, Servers, Workstations, AdminWorkstations), Authentication (Kerberos, NTLM, LDAP, SMB, RDP, WinRM), Delegation, Authorization, Policy, PKI
  - **Reusability: MEDIUM** — on-prem AD only; no cloud identity layer yet

- **Permission/Capability Graph** — `orchestrator/internal/adprimitive/{types,catalog}.go` + `orchestrator/internal/adchain/{search,resolver}.go` — Primitives model ACL abuse, trust exploitation, ADCS ESC; reachability planner builds attack paths
  - Prerequisite-satisfaction resolver (adchain/search.go:11-29) — iteratively applies primitives until target reached
  - **Reusability: HIGH** (architectural pattern; cloud can model IAM role assumption, resource access, policy trusts same way)

- **Control-Efficacy Adapter** — `orchestrator/internal/adefficacy/{provider,dcsync}.go` — Observes AD native controls (replication rights, DCSync); doesn't require third-party vendors
  - **Reusability: HIGH** (model for cloud: observe AWS IAM native controls, not just CloudTrail)

- **Hybrid AD Model (Partial)** — `orchestrator/internal/adenv/types.go:73-74` — Trust relationships include cross-forest; SIDFilteringDisabled field hints at Kerberos/SID handling
  - **Incomplete:** No Entra ID tenants, no hybrid identities, no cloud-to-AD trust modeling yet
  - Reusability: **LOW** (structure exists but not cloud-ready)

- **Attack Path Knowledge** — `orchestrator/internal/adprimitive/catalog.go` + real scenario corpus — 50+ AD exploitation primitives (Kerberoasting, DCSync, ADCS ESC1-8, GPO abuse, DelegationACLOverwrite, etc.)
  - **Reusability: HIGH** (many attacks have cloud equivalents: K/AS-REP roasting → AWS SigV4 signature forgery, delegation abuse → AssumeRole chaining, GPO abuse → policy evaluation manipulation)

### MISSING

1. **Entra ID + Hybrid Identity Model** — Why it matters: AD mastery assumes on-prem only; real hybrid environments link AD users to Entra ID tenants
   - Complexity: **HIGH** (design: identity federation model; implement: Entra + AD environ merger)

2. **Cloud-to-AD Attack Path Scenarios** — Why it matters: Real-world attacks often pivot AD → Azure → M365 or vice versa; existing scenarios are single-platform
   - Complexity: **HIGH** (design: multi-environment scenario DSL; implement: cross-platform orchestration)
   - Examples: Entra app→on-prem AD connector compromise, M365 breach→AD lateral movement

3. **Okta/External IdP Bridging** — Why it matters: Many orgs use Okta instead of Entra; need to model Okta→AWS/Azure trust
   - Complexity: **HIGH** (per-IdP integration; Okta/Ping/OneLogin each different API)

---

## 7. RANSOMWARE MASTERY REUSE

**Question:** Can cloud ransomware scenarios reuse existing ransomware work? Can backup/recovery validate cloud storage?

### EXISTS

- **Ransomware Evidence Engine** — `orchestrator/internal/rwevidence/` — 5 capabilities (Prevention, Recovery, Detection, Containment, DataProtection); 4 techniques (T1490, T1486, T1567.002, T1560.001)
  - **Reusability: HIGH** (pattern; extensible to cloud techniques)

- **Recovery/Backup Validation** — `orchestrator/internal/backupassurance/observers.go` — 6 observers: DeletionProtection, Immutability, OfflineIsolation, PrivilegeSeparation, RestoreIntegrity, RPORTO
  - **Reusability: HIGH** — can model cloud backups: S3 versioning (immutability), Azure Backup (isolation), GCP snapshots (recovery)

- **Technique Taxonomy** — `orchestrator/internal/rwtaxonomy/mapping.go` (referenced in grep results) — T1490 (Inhibit System Recovery), T1486 (Data Encrypted), T1567.002 (Exfiltration Over HTTPS), T1560.001 (Archive via Utility, i.e., ransomware wrapper)
  - **Reusability: MEDIUM** (Windows/Linux ransomware; cloud storage ransomware is a different category)

- **Kill Chain Scenarios** — Real scenarios (Black Basta, Medusa, Rhysida, Hunters International) show 9-11 step adversary emulation grounded in CISA advisories
  - **Reusability: HIGH** (pattern; cloud variants follow same structure)

### MISSING

1. **Cloud Ransomware Techniques** — Why it matters: S3 bucket encryption, Azure Disk Encryption, GCP Persistent Disk encryption, Cosmos DB ransomware, Lambda function abuse, Cloud Functions abuse
   - Complexity: **MEDIUM** (design: 5-10 new techniques; implement: per-cloud sample scenarios)
   - New techniques: T1491.001 (defacement via cloud console), T1565 (Data Destruction via cloud API), T1657 (Snapshot Deletion)

2. **Cloud Backup & Snapshot Recovery Validation** — Why it matters: Current backupassurance is Hyper-V/Windows backup focused; cloud has S3 versioning, Azure Backup, GCP snapshots
   - Complexity: **MEDIUM** (design: cloud backup observer interfaces; implement: per-cloud backup API clients)

3. **Cross-Region Replication Abuse** — Why it matters: S3 cross-region replication, Azure geo-replication, GCP cross-region snapshots are attack surfaces
   - Complexity: **MEDIUM** (design: replication-state observer; implement: cloud API queries)

4. **Data Exfiltration via Cloud Services** — Why it matters: S3 direct download, Azure Blob direct access, GCP Cloud Storage direct download, Cosmos DB bulk export
   - Complexity: **MEDIUM** (design: cloud-storage access control validation; implement: per-cloud IAM observer)

---

## 8. MISSING CLOUD-SPECIFIC COMPONENTS

### Component 1: Cloud Resource Normalization

**What:** Unified object model for AWS/Azure/GCP/Kubernetes resources  
**Why it matters:** Scenarios reference resources by ARN (AWS) | URI (Azure) | path (GCP) | name (K8s); need unified reference
**Complexity:** MEDIUM (design: 3 days; implement: 2 days per cloud)

**Closest existing pattern:**  
- adenv.Machine models hosts (hostname, SID, OS) — generic but on-prem only
- latmove.AttemptKey (RunID, Source, Destination, Technique) — provider-neutral structure

**Recommendation:** Create `orchestrator/internal/cloudenv/resource.go` with:
```go
type CloudProvider string // "aws" | "azure" | "gcp" | "kubernetes"
type ResourceType string  // "instance" | "storage" | "function" | "pod" | "identity"
type ResourceID struct {
    Provider  CloudProvider
    Type      ResourceType
    AccountID string // AWS account, Azure subscription, GCP project
    Region    string
    Name      string
    ARN/URI   string // canonical identifier
}
```

---

### Component 2: IAM/Permission Graph Builder

**What:** Build reachability graph from cloud IAM policies (AWS, Azure, GCP) like adchain does for AD
**Why it matters:** Answer "can this principal access this resource?" before scenario dispatch
**Complexity:** HIGH (5+ days per cloud; policy engine learning required)

**Closest existing pattern:**  
- adchain/search.go — Plan() finds multi-step paths; Reachable() computes closure
- adenv/types.go — Identity/Authorization/Policy model cloud can extend

**Recommendation:** Create `orchestrator/internal/cloudiam/` with:
- `ReachableResources(catalog, held, target)` — mirrors adchain.Plan()
- Catalog of cloud-IAM primitives (AssumeRoleChain, PolicyOverwrite, CredentialSteal, etc.)
- Per-cloud policy evaluators (AWS IAM policy simulator, Azure RBAC evaluator, GCP IAM getPolicy)

---

### Component 3: Cloud Audit Log Ingestion Adapters

**What:** Real-time or batch connectors for CloudTrail, Activity Log, Cloud Logging
**Why it matters:** Correlate scenario attempts with provider evidence
**Complexity:** HIGH (15+ days; 3+ vendor APIs; SIEM-style ingestion pipeline)

**Closest existing pattern:**  
- detectverify connectors (internal/connector) — vendor-API integration template
- rwevidence.DetectionLookup interface (dispatch.go:86) — evidence lookup contract

**Recommendation:** Create `orchestrator/internal/cloudaudit/` with:
- Connector interfaces (AWSCloudTrailConnector, AzureActivityLogConnector, GCPCloudLoggingConnector)
- Background poller jobs (using existing jobs.Store)
- Event normalization to CorrelationKey (RunID, resource, action, time window)

---

### Component 4: Prerequisite Resolver

**What:** Given available resources + policies, which scenarios CAN run?
**Why it matters:** Avoid dispatching scenarios to incompatible environments
**Complexity:** MEDIUM (design: 2 days; implement: 3 days)

**Closest existing pattern:**  
- admatrix.Simulate() checks reachability (matrix.go:94-101)
- adchain.ConditionResolver — evaluates predicates at dispatch time
- adgate/gate.go — authorization gates before execution

**Recommendation:** Create `orchestrator/internal/cloudprereq/` with:
- PrerequisiteChecker interface: CanRun(scenario, account, policies, resources) → (bool, []string violations)
- Per-scenario prerequisite declaration (extend Step YAML with cloud_requires: field)
- Checker implementations: AWSIAMChecker, AzureRBACChecker, GCPIAMChecker

---

### Component 5: Cloud-Native Evidence Types

**What:** Structured models for cloud-specific events (AssumeRole, policyEvaluation, tokenIssue, externalIdMismatch)
**Why it matters:** Evidence detail needs to reflect cloud-provider capabilities (AWS includes RequestParameters; Azure is event-only)
**Complexity:** LOW-MEDIUM (design: 2 days; implement: 1 day per cloud)

**Closest existing pattern:**  
- models.SimulationResult carries Events[] (Windows Event IDs) — same field for cloud IDs
- rwevidence.CapabilityResult.Reason — free-text; can extend with Detail field for structured evidence

**Recommendation:** Extend models/schema.go:
```go
type CloudEvent struct {
    Provider   string    // "aws_cloudtrail", "azure_activity_log", "gcp_cloud_logging"
    EventID    string    // "ConsoleLogin", "AssumeRole", "Put Object", etc.
    Timestamp  time.Time
    Principal  string    // ARN/OID/email
    Resource   string    // ARN/URI/path
    Action     string    // "sts:AssumeRole", "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/write"
    Status     string    // "Success", "Failure", "Unauthorized"
    RawJSON    json.RawMessage // full provider event for auditing
}
```

---

### Component 6: Multi-Cloud Identity Normalization

**What:** Map AWS IAM User/Role, Azure User/ServicePrincipal, GCP ServiceAccount, Okta user to a unified identity for correlation
**Why it matters:** Cross-cloud lateral movement needs identity linking (e.g., AWS→Entra app→Azure)
**Complexity:** HIGH (design: 4 days; implement: 5+ days; identity federation learning required)

**Closest existing pattern:**  
- threatidentity/override_test.go (found in grep) — suggests existing identity store
- adenv.Identity (types.go:77-98) — AD-only today

**Recommendation:** Extend threatidentity or create `orchestrator/internal/cloudidentity/` with:
- FederatedIdentity struct: AWS ARN + Azure OID + GCP email + Okta ID
- Mapper: per-cloud→unified identity
- Linker: detect Entra hybrid sync, AWS SSO sync, Okta provision

---

### Component 7: Cloud Resource Access Control Validation

**What:** Before scenario, confirm cloud account has required monitoring, compliance, permissions
**Why it matters:** Scenarios need EDR, audit logging, IAM policy enforcement to collect evidence
**Complexity:** MEDIUM (design: 2 days; implement: 3 days per cloud)

**Closest existing pattern:**  
- controlval.Provider — observes deployed control responses
- adefficacy.Provider — observes AD native control state

**Recommendation:** Create `orchestrator/internal/cloudcontrol/` with:
- PrerequisiteObserver interface: CheckRequired(ctx, resource, requirement) → (met bool, reason string, err error)
- Implementations: AWSCloudTrailRequired, AzureDiagnosticsRequired, GCPCloudAuditLogsRequired, MFAPolicyRequired, EDRDeployed, etc.

---

## SUMMARY TABLE

| Category | Reusable Foundation | Key Gap | Complexity | Recommendation |
|----------|-------------------|---------|-----------|-----------------|
| **Scenario Execution** | Step/Builder/Provider registry (HIGH) | Cloud prerequisite gate, multi-account templating, resource readiness polling | MEDIUM-HIGH | Extend ExecutionPolicy; add CloudPrerequisite struct; design account-aware campaign expansion |
| **Evidence Collection** | rwevidence pattern, CorrelationKey, Verdict taxonomy (HIGH) | Cloud audit log ingestion, async polling, multi-cloud identity correlation | HIGH | Create cloudaudit package; add CloudEvent type; extend threatidentity for federation |
| **Control Efficacy** | Outcome/Observation/Expectation model, Provider interface (HIGH) | Cloud-native outcomes (AssumeRoleFailed, ServiceControlPolicy deny), multi-cloud identity bridges | MEDIUM-HIGH | Add 5+ outcomes to enum; create cloudiam Provider adapters; wire AWS/Azure/GCP IAM as providers |
| **Campaign Execution** | Campaign.Aggregate, ChildRun isolation (HIGH) | Multi-account expansion, cross-account state snapshots, account-scoped dispatch | MEDIUM | Add AccountID to campaign targeting; implement account-expansion templating; pre-campaign inventory |
| **Provider Adapters** | Registry, Vendor integration pattern (HIGH) | Real AWS/Azure/GCP/Okta adapters, evidence bridging, provider-capability discovery | HIGH | Scaffold AWS SDK client (start with AssumeRole observation); Azure SDK; GCP SDK; per-cloud detail extractors |
| **AD Mastery Reuse** | Permission graph, attack-path primitives, hybrid-trust hints (MEDIUM) | Entra ID + hybrid identity model, cloud-to-AD scenarios, multi-tenant Okta | HIGH | Extend adenv with Entra tenant/hybrid user link; model cloud-to-AD trusts; cloud-native primitives |
| **Ransomware Mastery Reuse** | 5-capability framework, backup observers (HIGH) | Cloud ransomware techniques, cloud backup/snapshot validation, cross-region replication abuse | MEDIUM | Design T1491/T1565/T1657 cloud variants; extend backupassurance for S3/Azure Blob/GCP snapshots |
| **Cloud Resource Normalization** | NONE (new) | — | MEDIUM | Create cloudenv/resource.go with provider-agnostic ResourceID model |
| **IAM Permission Graph** | adchain reachability pattern (HIGH) | — | HIGH | Create cloudiam package; catalog cloud-IAM abuse primitives; policy evaluators per cloud |
| **Cloud Audit Ingestion** | connector/detectverify pattern (MEDIUM) | — | HIGH | Create cloudaudit package; AWS/Azure/GCP connectors; background poller jobs |
| **Prerequisite Resolver** | admatrix/adchain patterns (HIGH) | — | MEDIUM | Create cloudprereq package; CanRun checker; per-cloud implementations |
| **Cloud Evidence Types** | SimulationResult.Events (LOW) | — | LOW-MEDIUM | Extend models/schema.go; add CloudEvent struct; normalize per-cloud event formats |
| **Cloud Identity Normalization** | threatidentity hint (LOW) | — | HIGH | Extend threatidentity or create cloudidentity; FederatedIdentity mapper; cloud SSO sync detection |
| **Cloud Resource Access Control** | controlval/adefficacy pattern (HIGH) | — | MEDIUM | Create cloudcontrol package; PrerequisiteObserver interfaces; per-cloud checkers |

---

## CROSS-REFERENCES & ARCHITECTURAL NOTES

### Reusable Packages (Ready Now)
- **orchestrator/internal/scenario/providers.go** — Add cloud providers (aws_cloudtrail, azure_activitylog, gcp_cloudlogging, okta_systemlog)
- **orchestrator/internal/controlval/controlval.go** — Verdict/SkipReason taxonomy + Observation/Expectation model; extend Outcome enum
- **orchestrator/internal/rwevidence/types.go** — CapabilityResult + CorrelationKey; reuse for cloud capabilities
- **orchestrator/internal/campaign/campaign.go** — Summary/DeriveStatus; add Account/Subscription/Project dimensions
- **orchestrator/internal/backupassurance/observers.go** — Observer interface pattern; model cloud backup checkers

### Patterns to Replicate (Proven Design)
- **adchain/search.go** — Reachability + prerequisite satisfaction → create cloudiam/graph.go
- **admatrix/matrix.go** — Validation levels + environment requirements → create cloudmatrix/ for cloud-control validation
- **latmove/observation.go** — Correlation key + outcome classification → cloud lateral-movement evidence
- **vendors/{defender,crowdstrike}/** — OAuth + API client pattern → AWS/Azure/GCP SDK wrappers
- **connectorg/generator.go** — Config-driven connector instantiation → cloud audit ingestion

### Deferred (Needs Real Lab/Client)
- All real provider adapters (fake-backed first, proven in tests, real deployments deferred)
- Hybrid AD↔Entra identity federation (needs real tenant)
- Cross-cloud lateral movement (needs multi-cloud lab)
- Cloud ransomware family modeling (needs live malware samples, analyst review)

### Design Debt
- **ExecutionPolicy** (scenario/types.go:110) — only MaxPrivilege today; extend for cloud before first cloud scenario ships
- **No async resource provisioning gate** — scenarios can dispatch before resources exist; jobs infrastructure exists (jobs.Store) but not wired
- **Single-cloud assumption everywhere** — campaign, run, evidence correlation all assume single domain/tenant; needs account/subscription/project threading
- **Identity store (threatidentity)** — exists but undocumented in this audit; verify hybrid AD+cloud extensibility before building cloudidentity

---

## NEXT STEPS: RECOMMENDED EXECUTION ORDER

### Phase 1: Foundational Types & Adapters (Weeks 1-2)
1. Extend models/schema.go with CloudEvent, CloudResource, CloudProvider enums
2. Extend controlval: add 5+ cloud-specific Outcome values
3. Extend scenario/providers.go: register aws_*, azure_*, gcp_* providers
4. Create cloudenv/resource.go with provider-agnostic ResourceID

### Phase 2: Real Provider Adapters (Weeks 3-6, parallel)
1. Create cloudiam package: AWS SigV4, Azure RBAC, GCP IAM policy evaluation
2. Create cloudaudit package: AWS CloudTrail, Azure Activity Log, GCP Cloud Logging connectors
3. Scaffold vendor adapters (AWS SDK, Azure SDK, GCP SDK clients)

### Phase 3: Validation Engines (Weeks 7-9)
1. Extend scenario prereq gate: CloudPrerequisite + PrerequisiteResolver
2. Extend campaign for multi-account expansion + isolation
3. Create cloudcontrol: resource access + backup observer adapters

### Phase 4: Identity & Correlation (Weeks 10-12)
1. Extend threatidentity: hybrid AD↔Entra mapping
2. Create cloud-to-cloud identity correlation (AWS→Azure→Okta)
3. Wire multi-cloud lateral-movement scenarios

### Phase 5: Ransomware & Scenarios (Weeks 13-16)
1. Design cloud-ransomware techniques (T1491, T1565, T1657 variants)
2. Extend backupassurance for S3/Azure Blob/GCP snapshots
3. Author 3-5 cloud kill-chain scenarios (grounded in real advisories)

---

## FILE PATHS (CRITICAL REFERENCES)

**Type Definitions:**
- `/orchestrator/internal/scenario/types.go` — Step, ExecutionPolicy, PrivSpec
- `/orchestrator/internal/models/schema.go` — SimulationResult, CheckResult, AttackTechnique
- `/orchestrator/internal/controlval/controlval.go` — Outcome, Observation, Expectation, Verdict, SkipReason
- `/orchestrator/internal/rwevidence/types.go` — CapabilityResult, AttemptKey, Capability
- `/orchestrator/internal/adenv/types.go` — Environment, Forest, Identity, Machines, Authorization

**Execution & Orchestration:**
- `/orchestrator/internal/scenario/engine.go` — Scenario loading, registry wiring
- `/orchestrator/internal/scenario/builder.go` — Step building, deduplication
- `/orchestrator/internal/api/handlers.go` — Scenario dispatch entry point
- `/orchestrator/internal/campaign/campaign.go` — Campaign aggregation

**Evidence & Validation:**
- `/orchestrator/internal/rwevidence/dispatch.go` — EvaluateStep, observer coordination
- `/orchestrator/internal/controlval/provider.go` — Provider interface
- `/orchestrator/internal/backupassurance/observers.go` — Observer interface pattern
- `/orchestrator/internal/admatrix/matrix.go` — Validation levels, evidence model
- `/orchestrator/internal/latmove/observation.go` — Correlation key, attempt classification

**Integration Patterns:**
- `/orchestrator/internal/vendors/defender/client.go` — Provider client (OAuth, caching)
- `/orchestrator/internal/connector/generator.go` — Connector config wiring
- `/orchestrator/internal/threatidentity/` — Identity store (verify extensibility)
- `/orchestrator/internal/db/rwevidence_store.go` — Evidence persistence

**Design References (Ransomware Mastery):**
- `/orchestrator/internal/adchain/search.go` — Reachability + planning (Pattern: cloudiam)
- `/orchestrator/internal/adcontrolval/bridge.go` — Real provider adapter (Pattern: cloud providers)
- `/orchestrator/internal/adefficacy/provider.go` — Native control observation (Pattern: cloud IAM)

---

**Audit Completed:** 2026-10-12  
**Confidence:** HIGH — Based on full codebase walk-through, type definitions, real implementation patterns, test cases.

---

## ADDENDUM (2026-10-13): Reconciled against `orchestrator/internal/cloudgraph/`

This audit (dated 2026-10-12) was written **without knowledge of `orchestrator/internal/cloudgraph/`**, a package built the same day by a parallel thread of work (the "Cloud BAS Mastery" 5-phase initiative, spec `docs/superpowers/specs/2026-10-12-cloud-bas-architecture-design.md`, capabilities summary `docs/cloud-bas-capabilities-summary.md`). Several items this audit lists as **MISSING** or **NONE (new)** in Section 8 and the Summary Table **already exist**. Treat the corrections below as authoritative over the original text for the items named; everything else in this audit (vendor-adapter gaps, real audit-log ingestion, identity federation beyond AD↔one-cloud, Kubernetes/DevOps/SaaS domains, cloud-ransomware technique breadth) remains accurate and still open.

### Corrections to Section 8 / Summary Table

| Component the audit called MISSING/NONE | Actual state in `cloudgraph` (verified by reading the code, not inferred) | What's genuinely still missing |
|---|---|---|
| **Component 1: Cloud Resource Normalization** (`cloudenv/resource.go`, claimed "NONE (new)") | `types.go`: `CloudResource{CanonicalID, Kind, AccountScope, DisplayName, Attributes, Provenance}` + `CloudIdentity` + `CloudPermission` — provider-agnostic, `CanonicalID` preserves the provider-native ARN/URI/path unchanged (pinned by `TestCloudResource_CanonicalIDPreservesProvider`, covers AWS S3 ARN and Azure storage-account path shapes). This **is** the recommended `ResourceID` model, already built and tested. | Kubernetes/pod and function-level resource kinds are untouched — only AWS/Azure/GCP resource shapes have been exercised. |
| **Component 4: Prerequisite Resolver** (`cloudprereq/`, claimed "— (new)") | `prerequisite.go`: `DiscoveredGraph` + `PrerequisiteResolver` (OK/MISSING/DEGRADED/UNKNOWN, unrecognized kind → UNKNOWN, never silently OK) + `step_gate.go`: `StepGate` (blocks dispatch only on known-Blocked/Unknown edges). This **is** the `CanRun`-style checker the audit asked for. | No YAML-level `cloud_requires:` field wiring into real scenario dispatch yet — the resolver exists and is tested, but nothing in the live scenario engine calls it. |
| **"Multi-Account Campaign Templating"** (Section 4, claimed "No current precedent... not multi-tenant/multi-account") | `campaign_scope.go`: `CloudCampaignScope`/`CloudChildRun` (defaults: MaxConcurrency=3, TimeoutPerAccount=30min) + `multiaccount.go`: `RunMultiAccount`/`CloudAggregate` — bounded-concurrency fan-out across accounts, tested for isolation and concurrency-limit enforcement. This claim in the original audit is **flatly wrong** — multi-account campaign execution already exists. | Not wired into the live orchestrator's campaign dispatcher — `RunMultiAccount` is a standalone, fully-tested function nothing in production calls yet. Cross-account *correlation* (`CloudCampaignScope.CorrelateAcrossAccounts`) is a typed field with no implementation. |
| **Component 2: IAM/Permission Graph Builder** (`cloudiam/`, claimed entirely missing) | `aws_evaluator.go`/`azure_evaluator.go`/`gcp_evaluator.go`: each implements the `AuthorizationEvaluator` interface (`evaluator.go`) doing real hand-coded policy-statement evaluation (identity/resource policy, role-trust with principal verification, scope inheritance, deny precedence) — proven provider-agnostic via a capstone test using generic calling code against all three. This is the **single-edge evaluation** half of what the audit's `cloudiam.ReachableResources` asked for. | **Genuinely still missing**: multi-hop graph search *within* pure cloud (A can assume B can access C, chained) — the evaluators answer "does this one edge's policy allow this," not "find a path." `adchain`-style `Plan()`/`Reachable()` for pure intra-cloud chains does not exist (the AD-side equivalent is reused as-is via `hybrid_composition.go`, see below, but that's AD→cloud, not cloud→cloud). |
| **"Cloud-to-AD Attack Path Scenarios" / hybrid identity** (Section 6, claimed "Entra ID + Hybrid Identity Model... HIGH complexity, needs real tenant") | `federation.go`: `FederationEdge` (links an AD SID to a `CloudIdentity.CanonicalID`, rejects edges without `Provenance.Source` — never inferred from name/UPN matching) + `hybrid_composition.go`: `ComposeHybridPath` calls the **real, unmodified** `adchain.Reachable` for the AD-side verdict, crosses the federation edge only if fresh, then evaluates the cloud-side edge. This is a working, tested AD↔cloud reachability composition — not the "needs real tenant, HIGH complexity" blocker the audit describes. | Only Azure↔AD is modeled (matching the real Azure discovery milestone, see below). Okta/other IdP bridging is still untouched, as the audit says. |
| **Component 5: Cloud-Native Evidence Types** (claimed needs a new `CloudEvent` struct) | `types.go`: `CloudEvent{Principal, Action, Resource, Timestamp, Result, Source, SessionToken, SourceIP, UserAgent}` already exists, and is a superset of the audit's proposed struct (adds caller-IP/session/user-agent fields the audit didn't think to ask for). `cloudtrail_correlator.go`'s `SyntheticEventCorrelator`/`EventCorrelator` already implements match-quality scoring (perfect/partial/delayed/none), telemetry-delay calculation, and ±30s window-boundary handling against this type. | The matching **algorithm** is real and tested; it has only ever been run against hand-constructed synthetic `CloudEvent`s. Real CloudTrail/Activity Log/Cloud Audit Log ingestion into this type — i.e., actually populating it from a live API — does not exist. This is accurately captured by the audit's "Cloud Audit Log Ingestion Adapters" gap, which still stands. |
| **"Cloud Ransomware Techniques"** (Section 7, claimed fully missing) | `ransomware_scenario.go`: `RansomwareStep`/`CloudRansomwareScenario`/`ExecuteCloudRansomwareScenario` — one real 3-step cloud-storage kill chain (assume-privileged-role T1548 → discover-storage T1619 → encrypt-delete-objects T1486), fully-blocked/partially-blocked/fully-open verdict classification, chain-stops-at-first-block behavior tested. | Only one kill chain exists, and only for generic cloud storage. The audit's specific technique list (T1491.001 console defacement, T1565 data destruction via API, T1657 snapshot deletion, cross-region replication abuse) is still entirely unbuilt, as are AWS/GCP-specific variants. |

### What this changes about the recommended execution order

The audit's "NEXT STEPS: RECOMMENDED EXECUTION ORDER" (Phase 1: foundational types, Phase 2: real provider adapters, ...) assumed Phase 1 didn't exist. It does. **Phase 1 and significant parts of Phase 3 (validation engines) are done.** The real remaining work, in priority order given what's actually built:

1. **Real provider adapters** (the audit's Phase 2) — this is genuinely still almost entirely open. One exception: `orchestrator/internal/cloudgraph/azure_discovery.go` (built 2026-10-12/13, separate milestone, spec `docs/superpowers/specs/2026-10-12-azure-real-discovery-integration-design.md`) is a real, read-only Azure discovery client (Microsoft Graph + ARM, reusing `msauth`) — the first real step into this gap, currently **blocked on the test tenant** (no Azure subscription attached; signed-in account has no tenant-admin role to grant Graph API consent — both tenant/account gaps, not code gaps; see `docs/superpowers/plans/2026-10-12-azure-real-discovery-integration.md` and memory `project_azure_real_discovery_integration`). AWS/GCP real discovery following the same pattern is entirely unbuilt.
2. **Real cloud audit-log ingestion** (CloudTrail/Activity Log/Cloud Audit Logs) — still fully open, as the audit says; the correlation algorithm is ready to receive real data the moment an adapter exists.
3. **Wiring the already-built pieces into live dispatch** — `RunMultiAccount`, `ComposeHybridPath`, `ExecuteCloudRansomwareScenario`, and `PrerequisiteResolver`/`StepGate` are all standalone, fully-tested functions nothing in the production orchestrator calls yet. This is lower-risk, unblocked-by-external-access work that was NOT on the original audit's radar at all, since it didn't know these functions existed.
4. **Intra-cloud multi-hop reachability** (`cloudiam`-style `Plan()`/`Reachable()` within one cloud, not just AD→cloud) — the one piece of the audit's Component 2 that's still a real, unaddressed gap.
5. Everything else the original audit flagged as HIGH complexity / needs-real-lab (cross-cloud identity federation beyond AD↔Azure, Kubernetes, DevOps/supply chain, SaaS/M365, GCP depth, cloud-ransomware technique breadth) remains accurately described as open.

