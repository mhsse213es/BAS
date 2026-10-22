# Kubernetes state-changing scenarios — design (not approved, no code)

**Status:** design direction approved by the owner (decisions in section 10). Not approved for production use. No live execution until the engine, negative tests, rollback-failure tests and lab validation pass.
**Scope:** the state-changing Kubernetes scenarios deferred by QA log O-11 and R-19 in `docs/cloud-mastery-qa-log.md`.
**Related:** `docs/superpowers/specs/2026-10-12-cloud-bas-architecture-design.md`; `orchestrator/internal/cloudgraph/probe.go` (R-19 gates).

## 1. Intent

Let an authorized operator run a small, fixed set of Kubernetes actions that change cluster state, so a configured attack route (see `k8s_attackpath.go`) can be tested for real. The tests run only on disposable lab clusters. Every action must be reversible, verified, and recorded.

## 2. Non-goals

- No state-changing action on any cluster that is not on the allow-list, including managed production clusters.
- No free-form requests. Each action comes from a fixed registry in code, the same model as R-19.
- No credential handling by the scenario engine beyond the scenario's own short-lived token.
- No claim that a successful action proves exploitability in any other environment.

## 3. Gates (all enforced server-side, in order)

1. **Mode.** Dry-run is the default and returns the plan only. A live run needs an explicit mode set by the operator for that run.
2. **Cluster allow-list.** Environment variable (like `CLOUD_PROBE_ALLOWED_ACCOUNTS`): `kubernetes:<cluster-name>@<api-server-host>`. Unset permits nothing. A cluster named only in a graph or request is refused.
3. **Namespace allow-list.** Writes are permitted only in namespaces that carry the label `bas.audspect.io/scenario-sandbox=true` and are on the allow-list. Scenario code creates no namespace on its own.
4. **Registry membership.** Only actions in the code registry run. Each action declares its verbs, resources, object names pattern and rollback.
5. **Operator approval, per run.** A live run needs a named approver and a one-time approval token issued for that run. The approval is not inferred from a request, a graph, or earlier approvals. It covers one scenario, one cluster and one namespace.
6. **Credential scope.** A dedicated scenario ServiceAccount, separate from the read-only discovery account. Its RBAC is limited to the sandbox namespace and the registry's verbs. The token is short-lived (for example one hour). The engine checks that the token resolves to that ServiceAccount before any write (the R-19 "credentials resolve to the named account" check).

## 4. Execution sequence

For each action in a live run:

1. **Audit requested.** Write `k8s.scenario.requested` synchronously. If the write fails, the action does not run (fail closed, as in R-19).
2. **Snapshot.** Read the target objects and record `resourceVersion` and the fields the action changes. Stored in the audit trail, never with credentials.
3. **Apply.** Perform the one registry action. Create objects are labelled `bas.audspect.io/run=<run-id>` so they can be found and removed.
4. **Verify.** Read back and confirm the expected state. A mismatch counts as a failed verification.
5. **Rollback.** On verification failure, on any error, or on a stop condition, run the registry rollback: delete objects labelled with the run ID, and restore snapshotted fields. Verify the rollback the same way.
6. **Audit outcome.** Write `k8s.scenario.outcome` with applied, verified, rolled-back, and the observed resourceVersions. If this write fails, the result is withheld from the operator and flagged for review.

## 5. Stop conditions

- Any object outside the sandbox namespace is touched, or the request is about to touch one.
- The cluster name or API server does not match the allow-list entry.
- The approval token is missing, expired, or already used.
- Verification fails and rollback also fails. The run is marked "needs manual recovery" with the list of labelled objects.

## 6. Recovery

Every created object carries the run label, so a manual cleanup is a single label-selected delete. Every modified field has a recorded snapshot, so a manual restore is a documented patch. The runbook lists both commands per action.

## 7. Actions to consider first (for approval, not yet chosen)

- Create a labelled, unprivileged pod in the sandbox namespace (checks `create pods` route evidence).
- Create a labelled ServiceAccount token request in the sandbox namespace (checks `serviceaccounts/token` route evidence).
- Patch a labelled test ConfigMap (checks write-path evidence without privileged objects).

Actions that bind roles, escalate roles, or touch `nodes/proxy` are excluded from the first milestone. Their blast radius is cluster-wide.

## 8. Open decisions for the owner

1. Which clusters are allowed. The kind lab is the only candidate today.
2. Who approves a live run, and whether approval happens in the console or on the command line.
3. Whether the first milestone is only the three actions in section 7.
4. Whether the scenario engine is built before or after the console UI (QA log O-10).

## 9. Evidence required before any action is approved for live use

- Dry-run output matches the plan for each action.
- Each gate has a failing test (wrong cluster, unlabelled namespace, missing approval, wrong credential, audit write failure).
- A live run on the kind lab shows apply, verify and rollback, with the audit trail, and the lab returns to its prior state.

## 10. Owner decisions (recorded)

1. **Clusters:** only the dedicated kind lab cluster initially. Cluster and namespace allow-lists are enforced server-side. Other clusters need separate validation and explicit approval.
2. **Approval:** an authenticated operator holding an explicit approval permission, separate from the requester. Approval is given in the console UI. The server binds each approval to the exact run, cluster, namespace, action and parameters. No self-approval. CLI approval may be considered later.
3. **First milestone:** the three labelled, non-privileged actions in section 7 only. No binding, privilege-escalation or node-proxy actions. Each action's rollback and verification are reviewed before it is allowed. Note: the token-request action mints a credential, so it needs a redaction design before it is built; it is deferred from the first build.
4. **Order:** build the scenario engine and safety gates first, then the console UI. The engine enforces dry-run by default, allow-lists, the fixed action registry, approval, short-lived credentials, fail-closed audit, and cleanup, independently of the UI.
5. **Rollback failure:** a failed rollback ends in an explicit `CLEANUP_FAILED` terminal state, keeps the audit evidence, and alerts the operator. A run is reported as cleaned up only after restoration is verified.
