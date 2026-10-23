# Synthetic secret read-access verification (scenario 1) — design

Status: approved in principle 2026-10-23. Lab fixtures and runner RBAC applied and verified (step 1 of 3). Engine action built with unit tests (step 2 of 3). No live run yet; the live run needs a separate approval (step 3 of 3). Each step below needs its own approval before
it runs on the lab: the RBAC change, the first live run, and any later change to the design.

## 1. Intent

Prove, with an active test, whether an explicitly authorized test identity can read a designated **synthetic** secret
in the lab sandbox. Analysis (scenarios 2–8) only shows what RBAC says. This shows what the API actually returns.

## 2. Scope (hard limits)

- Lab cluster `kind-bas-lab` only. Namespace `bas-sandbox` only.
- One object only: the synthetic secret `bas-synthetic-secret`. Its value is random per run and holds no real data.
- One test identity only: ServiceAccount `bas-sbx-token-probe`, which has no permissions outside this test.
- Never a real credential, never any other secret, never another namespace or cluster.

## 3. Permission the runner needs (least privilege)

The runner (`bas-scenario-runner`) gets only names-restricted verbs on pre-provisioned objects. It is not granted
`create` on secrets or bindings, because RBAC cannot restrict `create` by name, and a namespace-wide create would
let the runner make any secret or grant any binding in the sandbox.

| Object | Verbs granted to the runner | Why |
|---|---|---|
| Secret `bas-synthetic-secret` | `get`, `patch` (resourceNames) | read and rotate the value per run |
| RoleBinding `bas-synthetic-secret-probe` | `get`, `patch` (resourceNames) | add and remove the probe as its subject |
| Role `bas-synthetic-secret-reader` | none to the runner | grants `get` on that one secret to whoever is bound |
| ServiceAccount `bas-sbx-token-probe` | `serviceaccounts/token` `create` (already granted, probe only) | mint the test token |

Neither the runner nor the probe gets `create` or `delete` on secrets, bindings or roles. The fixture objects are created
once by the cluster admin (section 8), not by the engine.

## 4. Steps (the engine's action `synthetic-secret-read`)

1. **Plan (dry run, nothing written).** Validate the target against the allow-list. Read the fixture objects and confirm
   they are exactly as provisioned: the binding has no subjects, the role grants `get` on the one secret only.
2. **Approval** (existing gate): a second admin approves this exact run, single-use, 15 minutes.
3. **Audit "requested"** (fail-closed, as today).
4. **Snapshot:** record the binding's current subjects (expected empty) and the secret's resourceVersion.
5. **Rotate:** patch the secret's `value` to a fresh random string. The value is kept in memory only and never logged or
   returned.
6. **Grant:** patch the binding's subjects to add `bas-sbx-token-probe` (namespace `bas-sandbox`).
7. **Mint:** request a 600-second token for the probe (existing `IssueToken`).
8. **Read:** call `GET` on the secret with the probe token.
   - Returned value equals the rotated value → **READ_SUCCEEDED** (the identity can read it).
   - HTTP 403 → **READ_DENIED**.
   - Any other result → **READ_INCONCLUSIVE** (reported, not treated as denied).
9. **Revoke:** patch the binding's subjects back to empty. The token cannot be revoked, so it is reported as
   `DISCARDED_NOT_REVOKED` for its remaining lifetime, as the token-probe does.
10. **Verify:** read the binding and confirm no subjects; confirm the probe gets 403 on the secret (a second read with the
    same token, or a SubjectAccessReview for the probe on `get secrets/bas-synthetic-secret`).
11. **Finish:** write the outcome to the audit log. Any failure in step 9 or 10 is `CLEANUP_FAILED`, never cleaned up.

Rollback runs on any failure after step 5: revoke the grant, re-verify, then finish.

## 5. Results

| State | Meaning |
|---|---|
| `CLEANED` (with result) | ran, read result recorded, grant removed and verified |
| `DISCARDED_NOT_REVOKED` | ran, grant removed, token alive until expiry |
| `CLEANUP_FAILED` | grant could not be removed or verified: operator action needed |
| `FAILED` / `REFUSED` | did not run, or refused before any write |

The read result (`READ_SUCCEEDED`, `READ_DENIED`, `READ_INCONCLUSIVE`) is a field of the run, separate from the state.
The secret value is never part of the result or the audit record. The test asserts this, as the token-probe does.

## 6. What the owner is approving

- The RBAC change in section 3 on the lab: the runner gains `get` and `patch` on two named objects, and nothing else.
- Creating the fixture objects once (section 8) on the lab.
- Running the action on the lab, after a separate approval of each run by a second admin.
- A test identity that can read one random synthetic value for up to the length of one run.

## 7. Tests before any live run

- Unit: plan refuses any target other than the fixture; read result maps 200 / 403 / other correctly; grant is removed on
  every failure path; the value never appears in the result or audit fields.
- Fake-cluster: rollback after a failed read; `CLEANUP_FAILED` when revoke fails.
- Live (after approval): full run on kind-bas-lab, then verify the binding has no subjects and the probe gets 403.

## 8. Fixtures (created once by the cluster admin, not by the engine)

- Secret `bas-synthetic-secret` in `bas-sandbox`, label `bas.audspect.io/synthetic=true`, initial random value.
- RoleBinding `bas-synthetic-secret-probe` in `bas-sandbox`, roleRef `bas-synthetic-secret-reader`, subjects empty.
- Role `bas-synthetic-secret-reader` in `bas-sandbox`: `get` on secrets, resourceNames `[bas-synthetic-secret]`.
- ClusterRole-free: no cluster-wide grant anywhere.

## 9. Open items

- Resolved for authorization and schema: a server-side dry-run patch of the binding's subjects, and of the secret value,
  both succeeded as the runner on 2026-10-23. The live effect is confirmed only by the first real run.
- The namespace label gate already in the engine (`bas.audspect.io/scenario-sandbox=true`) applies unchanged.
