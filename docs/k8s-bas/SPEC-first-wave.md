# Kubernetes BAS: specification and first wave (Phase 1)

Status: approved direction, specification draft. No new scenario is implemented by this document.

This document records the decisions below and defines the first ten executed Kubernetes scenarios. Everything here is planning until each scenario meets the acceptance criteria in section 6.

## 1. Decisions

| Topic | Decision |
|---|---|
| Catalogue | First wave: 10 scenarios. Long-term planning range: 35 to 45. Not a delivery commitment. |
| Existing four | Retained and counted toward the ten. Not duplicated. |
| Spec first | Specification before implementation, for all 12 domains. Phases follow section 9. |
| Production clusters | Targetable under **Safe** only, at first. Controlled is not enabled on production. |
| Lab clusters | Full authorized testing on designated lab clusters. |
| Customer non-production | Safe at first. Controlled with approval. Lab only if designated as lab. |
| Dry-run testing | First-class BAS execution, reported as admission evidence, never as runtime proof. |
| Runtime testing | Separate scenario class, requiring an executed workload or request, with its own profile. |
| MFA outcome | Excluded from Kubernetes. |
| Configured-state reports | Kept, but labelled as posture assessment. They do not count as executed scenarios. |

Production targeting and lab targeting are separated in the architecture and in authorization. A UI dropdown is not enough. The backend enforces the profile against the cluster's registered class, and a request for a higher profile than the cluster allows is refused before any API call.

## 2. Execution profiles

| Profile | Allowed operations | Cluster classes |
|---|---|---|
| Safe | Read-only API calls, `SubjectAccessReview` and `SelfSubjectAccessReview`, and server-side dry-run requests. Nothing persists. | Lab, customer non-production, customer production |
| Lab | Approved state-changing operations in designated namespaces, with cleanup and verification. | Lab only |
| Controlled | Approved operations for a customer, with explicit customer authorization, scenario-level approval, namespace and resource allowlists, operation and time limits, pre-execution state capture, a rollback procedure, an audit trail and an emergency cancel. | Customer non-production, with approval. Not production in this phase. |

No destructive or persistence scenario runs under any profile without specific written authorization for that scenario.

## 3. Cluster identity and registration

A cluster is never identified by a user-entered name alone. Registration captures:

- Display name, unique within Audspect.
- API server identity: the canonical server URL and the server certificate's SPKI hash.
- Kubernetes version, from `/version`.
- Cluster CA fingerprint.
- Connection status and the time it was last verified.
- Audspect registration identity: an ID assigned at registration.
- Cluster class: `lab`, `non-production` or `production`. Set by an administrator, never by the requester.

Two clusters with the same display name are refused at registration. Targets are chosen from the registry.

## 4. Outcome model

Kubernetes scenarios use four outcomes. The outcome describes what the control did, not whether the attack succeeded.

| Outcome | Meaning |
|---|---|
| Allowed | The API server accepted the request, through authorization and any applicable admission checks. |
| Blocked | Authorization or admission rejected the request. The rejecting layer is recorded. |
| Terminated | Execution was stopped by a cancel, a timeout or a safety limit, before a result was reached. |
| Unknown | The evidence cannot establish the result. |

Verdicts follow the existing model: PASS, FAIL, ERROR or SKIPPED.

- PASS means the security control produced the expected outcome.
- FAIL means it did not.
- ERROR means the scenario could not run correctly.
- SKIPPED means the scenario did not apply to the target.

A dry-run `Allowed` is not proof that a workload could run. A dry-run `Blocked` is not proof that the whole attack path is blocked. A test is never reported as successful because an API call returned HTTP 200.

Admission webhooks must declare `sideEffects: None` or `NoneOnDryRun` before a dry-run test can be trusted. A webhook that does not support dry-run makes the admission result `Unknown`, not `Allowed`.

## 5. Evidence

Every scenario records:

1. The requested operation: verb, resource, namespace, name, and the request body hash.
2. The API response: status code, and the `Status` reason when there is one.
3. The Kubernetes resource identity: UID and `resourceVersion` where applicable.
4. The admission response, when an admission layer was involved, including the webhook or Pod Security Admission mode that decided.
5. Before and after state for any mutation, and the state captured before execution.
6. Execution timestamp.
7. Cluster identity from section 3.
8. Evidence source (`api-response`, `admission-dry-run`, `sar`, `audit-log`) and confidence (`observed`, `inferred`).

Each scenario also records the six questions below, answered from that evidence:

1. What technique was attempted?
2. Was the API request accepted or denied?
3. Did the intended control prevent the action?
4. Was the workload or resource modified?
5. What evidence proves the result?
6. Which remediation prevents recurrence?

## 6. Acceptance criteria

A scenario counts as delivered only when all of these hold:

- An executable test exists and runs in its profile.
- A security assertion is written as a measurable statement, for example "a privileged pod in a `restricted` namespace is refused at admission with reason `violates PodSecurity`".
- The outcome mapping is explicit: which result is Allowed, Blocked, Terminated or Unknown, and which verdict follows.
- Evidence provenance is recorded as in section 5.
- Remediation text names the control to fix and the change to make.
- It has been executed and verified against a designated lab cluster.

A configured-state finding does not satisfy these criteria.

## 7. First wave: ten scenarios

Allocation follows the owner's recommendation. The existing four count toward it.

| # | Domain | Scenario | Profile | Status |
|---|---|---|---|---|
| 1 | Workload security | `pod-create-unprivileged` (existing) | Lab | Built |
| 2 | Configuration and control plane | `configmap-patch-labelled` (existing) | Lab | Built |
| 3 | Secrets and credentials | `synthetic-secret-read` (existing) | Lab | Built |
| 4 | Identity and RBAC | `sa-token-probe` (existing) | Lab | Built |
| 5 | Identity and RBAC | Impersonation check | Safe | To build |
| 6 | Identity and RBAC | RoleBinding escalation check | Safe | To build |
| 7 | Admission and policy | Privileged pod against a `restricted` namespace | Safe | To build |
| 8 | Admission and policy | Host namespace and hostPath pod against policy | Safe | To build |
| 9 | Network security | Cross-namespace pod-to-service reachability | Lab | To build |
| 10 | Network security | Reachability to the Kubernetes API from a workload namespace | Lab | To build |

The existing four run only under Lab. None of them has a Safe variant yet. Safe variants of their checks, where they exist, are separate scenarios.

### 7.1 Scenario specifications for the new six

**S5 Impersonation check** (Identity and RBAC, Safe)
- Technique: unauthorized service account impersonation.
- Operation: `SubjectAccessReview` for verb `impersonate`, resource `users` and `serviceaccounts`, as the probe subject.
- Assertion: the probe subject is denied `impersonate` on `serviceaccounts`.
- Outcome: Blocked if denied by RBAC; Allowed if granted. Verdict PASS if denied.
- Evidence: the SAR request and response, with `status.allowed` and `status.reason`.
- Remediation: remove the `impersonate` verb from any role bound to the probe subject, and list the bindings that grant it.

**S6 RoleBinding escalation check** (Identity and RBAC, Safe)
- Technique: RoleBinding manipulation.
- Operation: `SubjectAccessReview` for verb `create`, resource `rolebindings`, namespace `lab-escalation-test`, as the probe subject.
- Assertion: the probe subject cannot create RoleBindings in a namespace it is not bound to.
- Outcome: Blocked if denied; Allowed if granted. Verdict PASS if denied.
- Evidence: SAR request and response.
- Remediation: restrict `rolebindings` create and `escalate` to cluster administrators.

**S7 Privileged pod against restricted namespace** (Admission and policy, Safe)
- Technique: privileged container creation.
- Operation: server-side dry-run `create` of a pod with `privileged: true`, in a namespace labelled `pod-security.kubernetes.io/enforce: restricted`.
- Assertion: the dry-run is refused by Pod Security Admission.
- Outcome: Blocked with the admission reason. Verdict PASS if blocked. Allowed means the control failed: FAIL.
- Evidence: the dry-run request, the status code and reason, and the namespace's PSA labels read beforehand.
- Remediation: set `enforce: restricted` on namespaces that run untrusted workloads, or move the workload.
- Limit: this shows admission, not runtime. A pod that is later modified in place is outside this scenario.

**S8 Host namespace and hostPath pod against policy** (Admission and policy, Safe)
- Technique: host PID, host network and hostPath mounting.
- Operation: server-side dry-run `create` of a pod with `hostPID: true`, `hostNetwork: true` and a `hostPath` volume at `/`, in a namespace with `enforce: baseline` or stricter.
- Assertion: the dry-run is refused.
- Outcome: Blocked by PSA or a named validating webhook. If no admission layer exists, the outcome is Allowed and the verdict FAIL.
- Evidence: the dry-run request and response, and the webhook configurations listed before the test.
- Remediation: enforce `baseline` or higher, or add a validating policy that refuses host namespaces and hostPath.

**S9 Cross-namespace pod-to-service reachability** (Network security, Lab)
- Technique: unauthorized pod-to-pod communication.
- Operation: create a probe pod in `np-app` and attempt a TCP connection to a service in `np-db` on the port the policy should block. Remove the probe pod afterwards.
- Assertion: the connection fails for the blocked port and succeeds for the allowed port.
- Outcome: Blocked if the connection fails. Allowed if it succeeds. Verdict is PASS when the observed behaviour matches the policy expectation.
- Evidence: the connection result for each port, the probe pod's UID, and the NetworkPolicy objects in place.
- Remediation: the policy change that restricts the flow.
- Limit: this depends on the CNI enforcing NetworkPolicy. Without enforcement the result is FAIL for a blocked port that connects, and that must be read as a finding about the CNI, not the policy.
- This is the first scenario that tests the NetworkPolicy expectations rather than configuration. It uses the boundaries in `orchestrator/testdata/k8s-netpol/`.

**S10 Reachability to the Kubernetes API from a workload namespace** (Network security, Lab)
- Technique: Kubernetes API endpoint exposure, and service account token use from a pod.
- Operation: from a probe pod in a workload namespace, attempt an HTTPS request to the API server and to `kubernetes.default.svc`, with the default service account token mounted or unmounted as the test case requires.
- Assertion: an anonymous request is refused, and a request with a workload token is refused for any verb the workload has not been granted.
- Outcome: Blocked for each refused request. Allowed if the API returns data for a request that should be refused.
- Evidence: the HTTP status for each request, and the subject the API reports for the token.
- Remediation: set `automountServiceAccountToken: false` on workloads that do not need the API, and remove grants from the default service account.

## 8. Out of scope for this wave

The following domains are specified only by name and are deferred until their execution method and evidence are ready: container image and supply chain, persistence, lateral movement, storage security, runtime security, resource abuse. Their scenario candidates belong in the long-term catalogue, not in this wave.

## 9. Phases

1. **Specification** (this document). Extend it with the remaining domains as they are scheduled.
2. **Cluster registry and target discovery.** Registration per section 3. Namespace and object selection from discovery. This replaces the free-text run form.
3. **First ten scenarios.** Implemented and executed on a designated lab cluster. Each meets section 6.
4. **Execution profiles enforced in the backend.** Profile checks per section 2 on every request, with refusals audited.
5. **Coverage expansion**, toward 35 to 45, based on validated techniques and customer need.

## 10. Boundary with posture assessment

The configured-state reports already in the product (wildcards, breadth, cross-namespace grants, escalation paths, pod configuration, token exposure, attack-path configuration, network-policy boundaries) remain. They are labelled as posture assessment in the product, and they do not count toward this catalogue.
