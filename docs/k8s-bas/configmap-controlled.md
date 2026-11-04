# ConfigMap patch: first Controlled-eligible action (Phase 4, step 3)

Status: built and tested. Only this action is classified Controlled. Steps 4 and 5 (cancellation, time limits, global
kill switch, full audit coverage) are not built, so Controlled execution is **not yet enabled for customers**.

## What is Controlled

`configmap-patch-labelled` sets one key (`state`) in a ConfigMap that carries the sandbox fixture label, then restores
the prior value. It is the only action in `controlledActions`. These stay lab-only until each has a tested rollback or
cleanup:

- `pod-create-unprivileged`: needs a tested cleanup of the pod it creates.
- `synthetic-secret-read`: needs a defined evidence rule. The secret value must never be persisted.
- `sa-token-probe`: its minted credential cannot be revoked, so it ends in DISCARDED_NOT_REVOKED.

## Requirements for one run

A Controlled run needs all of these. Each is checked server-side:

1. A **customer authorization** (step 2) for this cluster ID, this action and this namespace, active, not expired, not
   revoked.
2. A **per-run approval** for this exact run: requester, action, namespace, parameters hash. It expires after 15
   minutes and can be used once.
3. The namespace carries the sandbox label, and the ConfigMap carries the fixture label. Both are checked in the engine.
4. The cluster's class allows the Controlled profile. Production never does.

## Order of operations (engine)

1. `requested` audit event. If it cannot be written, nothing is applied.
2. Namespace, credential and approval checks.
3. Snapshot: read the ConfigMap's prior value.
4. **`snapshot` audit event, before any write.** It carries the prior value, whether the key was present, the key name,
   the approval ID, and the run's parameters. If it cannot be written, the run is refused and nothing is applied.
5. Apply: set the key to the requested value.
6. Verify the value.
7. Rollback: restore the prior value, or remove the key if it was absent. The restore is verified.
8. `outcome` audit event.

A rollback that cannot be verified ends in `CLEANUP_FAILED` and raises an alert. The run is never reported as cleaned
up without the restore being checked.

## Evidence

The `snapshot` event holds the prior ConfigMap value. ConfigMap values are not secret by design: the fixture label marks
a sandbox object for testing. If a future fixture ever holds a secret, its snapshot must be redacted before it is
written. This is a rule for that future change, not something the current code handles.

## Tests

`internal/k8sscenario/controlled_configmap_test.go`:

- The snapshot is recorded before the first write. The test reads the cluster state inside the audit write for the
  snapshot event, and it still shows the original value. The record names the prior value and the approval.
- If the snapshot cannot be recorded, the run is refused and the ConfigMap is unchanged.
- A lab-only action writes no snapshot event.

`internal/k8sscenario/authorization_test.go`: only `configmap-patch-labelled` is classified Controlled.

Existing tests still cover the ConfigMap restore (`TestConfigMapPatch_RestoresPriorValue`), the rollback failure path
(`TestRollbackFailure_EndsInCleanupFailedAndAlerts`) and rollback verification.

## Not done (step 4 and later)

- **Cancellation** of a running action, with verified rollback. Not built.
- **Global Controlled kill switch.** Not built.
- **10-minute maximum run duration.** Not enforced yet. Only the 15-minute approval validity exists.
- **Console.** The run form still lists this action without any authorization field, so a run from the console will be
  refused until the authorization is in place. The console does not yet show authorizations.
- **Pod creation, secret read and token probe** remain lab-only.
