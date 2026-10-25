# Agent trust lifecycle audit

Scope: TLS identity and certificate lifecycle from enrollment to rotation. Started 2026-10-26.
Companion release gate (separate, still open): [Ubuntu staging runbook](guides/deployment-ca-staging-runbook.md).
That runbook has **not** been executed; deployment validation is not complete.

Evidence classes used below:

* **Verified (executed)**: reproduced by running code.
* **Verified (code)**: established by reading the exact code path; no test has run it yet.
* **Design limit**: working as designed, but weaker than the trust model implies.
* **Missing**: functionality that does not exist.
* **Unconfirmed**: assumption not yet checked; will be settled in its own pass.

Progress: 1 and 2 done (F-01 fixed). 3, 4 and 5 traced by code reading (below, no new tests yet). 6 not started.

## 1. Agent identity binding and 2. certificate issuance

### What holds (verified, code)

| Property | Where |
|---|---|
| AgentID must match `^[0-9a-f]{16}$` before it can reach the CA | `internal/api/enroll_csr_handlers.go` `agentIDPattern` |
| CommonName and DNS SAN come from the server, not the CSR; the CSR's own subject is ignored | `internal/pki/issue.go` `IssueClientCertificate` |
| The CSR signature is checked (proof the requester holds the private key) | `issue.go` `csr.CheckSignature()` |
| Leaf certificate: `ClientAuth` only, `DigitalSignature` only, not a CA, 365 days, random 128-bit serial | `issue.go` |
| Renewal: the claimed agentId must equal the presenting certificate's CN, otherwise 401 | `EnrollCSR`, `mtlsID != req.AgentID` |
| `/ws/agent` over mTLS: claimed agentId must equal the certificate CN | `mtls_context.go` `wsAgentAuthorized` |
| `:9443` requires and verifies a client certificate against the deployment CA | `cmd/server/main.go` `RequireAndVerifyClientCert` |
| The enrollment listener `:9444` exposes enrollment and `/health` only | `api.MountEnrollment` |
| Concurrent bootstraps for one AgentID are serialised | advisory lock in `EnrollCSR` |

### Findings

#### F-01 CSR key algorithm and size are not validated. Medium. Verified (executed). **FIXED**

* **Path:** `IssueClientCertificate` signs `csr.PublicKey` whatever it is. There is no check anywhere.
* **Evidence:** a scratch test issued a certificate for an RSA-1024 key and for an ECDSA P-224 key (both `err = nil`). (RSA-512 could not be tested: Go refuses to generate it.)
* **Impact:** whoever can enroll (holds the bootstrap secret) can obtain a client certificate with a key that is cheap to break, and then impersonate that agent. The agent's own key is ECDSA P-256 (`agent/certstore.go`), so legitimate agents are unaffected.
* **Remediation:** accept ECDSA P-256/P-384 and RSA at least 2048 bits; reject everything else with a clear error. Do the check in `IssueClientCertificate` so every caller is covered.
* **Regression test:** `TestIssueClientCertificate_KeyPolicy` (RSA-1024, P-224, Ed25519 rejected; P-256, P-384, RSA-2048 accepted). Written first and watched fail for exactly the three rejected keys.
* **Fix:** `checkClientKeyPolicy` in `internal/pki/issue.go`; the enrollment handler returns 400 with the reason.

#### F-02 Agent HTTP endpoints ignore the certificate's identity. High. Verified (code). **FIXED when a certificate is present; mandatory binding waits on the legacy listener**

* **Path:** `Heartbeat`, `SubmitRunEvents`, `ReceiveEvents` (logs), `UninstallAgentResult`, `UnenrollAgent` and the other `validateAgentAuth` callers authenticate with the shared `X-Agent-Token` only, and take the AgentID from the request body or URL. `AuthenticatedAgentID` is read in exactly two places: `EnrollCSR` and `wsAgentAuthorized`.
* **Impact:** any holder of the shared secret (and any enrolled agent, which holds it too) can report as, mark `uninstalled` (`UninstallAgentResult`), or retire (`UnenrollAgent`) any other agent, and inject events or heartbeats for it. Holding a valid certificate gives no extra protection on these routes. With `AGENT_SECRET` empty, `validateAgentAuth` returns true and there is no authentication at all.
* **Constraint on the fix:** the plaintext legacy listener (`:9000`) serves the same router and its agents have no certificate, so binding cannot be mandatory until that listener is retired.
* **Remediation:** when a request carries an mTLS identity, require the AgentID in the body or URL to equal it (reject otherwise). Then make the identity mandatory on the agent routes once the legacy listener is gone. Track the legacy listener retirement as the dependency.
* **Regression test:** a table test over each agent route: a request with identity A and an AgentID of B returns 401; identity A with AgentID A succeeds. (Needs the Postgres test harness used by `internal/api`.)

#### Fix for F-02

* `agentMatchesCertificate` (`internal/api/mtls_context.go`): when a request carries a verified client certificate, the AgentID it
  acts on must equal the certificate's identity, otherwise 401. Applied to heartbeat, enroll, unenroll, uninstall-result, log events
  (the whole batch is refused), host events, SharpHound upload, attack-path collection and scenario results.
* Correction to the finding: `SubmitScenarioResult` already refused a result naming an agent other than the one the run was
  dispatched to. It now also checks the certificate. `SubmitRunEvents` and `SubmitRunDetections` carry no agent ID (only run IDs),
  so they are not covered; binding a run to its agent there is still open.
* Not done: requests with **no** certificate (the plaintext legacy listener) are unchanged, so an agent holding only the shared
  secret can still claim any ID there. Making the certificate mandatory depends on retiring that listener.
* Tests: `TestAgentMatchesCertificate`, `TestAgentRoutes_RefuseAnotherAgentsCertificate` (8 routes, written first and failing).

#### F-03 Bootstrap identity is claimed, not attested. Medium. Design limit.

* **Path:** `EnrollCSR` on `:9444` accepts the shared secret and any well-formed AgentID that has no currently valid certificate. AgentID is `hex(SHA-256(hostname))[:16]`, so it is predictable.
* **Impact:** a holder of the bootstrap secret can enroll under another machine's AgentID once that machine's certificate has expired, or before it first enrolls, and later receive its commands. Recovery of an expired agent uses the same path, so this is intended behaviour, but it means the shared secret is the whole trust anchor for first identity.
* **Remediation options (decision needed):** per-agent or single-use enrollment tokens; an operator approval step for an AgentID that already exists; or at minimum an audit event and dashboard alert when an existing AgentID re-bootstraps.
* **Regression test:** depends on the chosen option.

### Positive checks still to execute (cheap, planned)

Tests that pin the properties in the "what holds" table, each written to fail if the property were removed: CSR subject ignored (CSR for CN=other yields CN=requested agent), non-hex AgentID rejected, `agentId` mismatch on renewal returns 401, leaf has `ClientAuth` only and `IsCA=false`.

## 3. Authentication enforcement, 4. renewal and expiry, 5. revocation (code trace)

Path traced: `:9443` listener (`cmd/server/main.go`), `/ws/agent` (`routes.go`, `wsAgentAuthorized`, `ws.ServeAgentWS`),
`EnrollCSR`, and the agent side (`agent/bootstrap.go`, `agent/certstore.go`, `agent/main.go`, `agent/service.go`).

What holds (verified, code): `:9443` uses `RequireAndVerifyClientCert` with the deployment CA as the only client CA, so Go's
chain verification rejects expired certificates, certificates from another CA and certificates without the ClientAuth usage.
Renewal never uses the bootstrap secret, and a certificate marked revoked cannot renew.

#### F-04 There is no way to revoke an agent certificate or block an agent. High. Missing. **FIXED (API; no dashboard button yet)**

* **Evidence (code):** no non-test code sets `agent_certificates.revoked`/`revoked_at` (the columns exist and are only read).
  `UnenrollAgent` only sets `agents.state = 'retired'` and does not touch certificates.
* **Impact:** a stolen or compromised agent key stays valid for up to 365 days. The only available response is replacing the
  whole deployment CA, which forces the entire fleet to re-enroll.
* **Remediation:** an admin action (audited, RBAC-gated) that marks the agent's certificates revoked and sets an agent-level
  block; see F-05 for enforcement. Do not rely on certificate revocation alone, see F-08.
* **Regression test:** revoke agent A, then A's certificate is refused on every agent route while agent B is unaffected.

#### F-05 Revocation and agent state are checked only on renewal, not on connection. High. Verified (code). **FIXED**

* **Evidence:** the only reader of `revoked` is `EnrollCSR`'s renewal branch. `:9443` has no `VerifyPeerCertificate` or
  `VerifyConnection` hook, `wsAgentAuthorized` compares only the claimed ID with the certificate CN, and `ServeAgentWS` does not
  consult `agents.state` (`retired`, `uninstalled`). A later connection from a second client with the same ID replaces the first.
* **Impact:** even once F-04 exists, a revoked or retired agent would keep working until its certificate expires.
* **Remediation:** one enforcement point on the mTLS listener (a `VerifyConnection` check against revoked serials and blocked
  agents, cached with a short TTL), plus the same check in the websocket and agent routes as defence in depth.
* **Regression test:** extract the listener's TLS configuration into one function used by `main` and by tests, then test expired,
  wrong-CA, wrong-usage and revoked certificates against it.

#### F-06 An enrolled agent whose certificate expires is blocked permanently. High (availability). Verified (code). **FIXED**

* **Evidence:** `certExpiringSoon` (renew at 75% of lifetime) has a single caller, inside `ensureCertificate`, which runs only
  at process start (`main.go`, `service.go`) and in the legacy retry loop. There is no renewal timer in a running agent. If the
  certificate is expired at the next start, `ensureCertificate` returns `errBlocked` ("certificate has expired with no
  successful renewal") and the agent retries forever; it never re-bootstraps because the enrolled marker forbids the secret. The
  server would in fact accept a re-bootstrap (the duplicate check ignores expired certificates), so the block is agent-side only.
* **Impact:** an agent that is offline or running without restart for the last 25% of the year (about 91 days) loses the fleet
  connection at expiry and needs manual recovery (reset the enrollment marker). Agents enrolled together expire together.
  Windows and Linux hosts that restart regularly are mostly protected, which is why this has not been seen.
* **Remediation:** renew from a timer inside the running agent (on startup and every few hours once past the threshold, with
  backoff); for an expired certificate, allow one controlled re-bootstrap with the secret, audited server-side, instead of
  blocking forever. Keeping "never use the secret once enrolled" is right while the certificate is still valid.
* **Regression test:** with the clock past the threshold a running agent renews without restart; with an expired certificate
  the agent recovers via re-bootstrap and logs it.

* **Fix:** `agent/cert_renewal.go` re-checks the certificate every 6 hours in the running agent (console and service). An enrolled agent
  with an expired certificate now re-enrols once through the TLS enrolment listener with the secret (`reEnrolling` in
  `ensureCertificate`); if that fails it stays blocked and never uses legacy transport. This reverses the earlier rule that an
  enrolled agent never uses the secret after expiry, so the two tests that pinned that rule were rewritten on purpose. The server
  already accepted such a request; recording it as an audit event is part of F-03.
* **Tests:** `TestEnsureCertificate_EnrolledExpiredCertReEnrolsOverEnrolmentListener`, `..._ReEnrolmentFailureStaysBlocked`,
  `TestResolveOperationalConfig_EnrolledExpiredCertRecovers`, `TestRunPeriodic_RunsImmediatelyThenOnEachTickUntilCancelled`.
  Known unrelated failure: `TestExecStepCleanupRunsAfterOperatorCancel` fails with and without this change.

#### Fix for F-04, F-05 and F-08 (revocation)

* `POST /api/agents/{agentId}/revoke` (admin, reason required, audited): marks all of that agent's certificates revoked, sets
  `agents.state = 'revoked'`, and drops its live websocket (`Hub.DisconnectAgent`). The CA and other agents are untouched.
* `POST /api/agents/{agentId}/reinstate` (admin, reason required): lets the agent enrol again; old certificates stay revoked.
  The agent must enrol afresh (reinstall or reset its enrolment marker); there is no automatic recovery on the agent side.
* Enforcement at connection time: `pki.NewAgentTLSConfig` (used by the `:9443` listener) runs a revocation check on every
  handshake, including resumed sessions, and **fails closed** if the database lookup errors. A revoked agent is refused whatever
  certificate it presents. The bootstrap secret cannot re-enrol a revoked agent (403).
* The same function pins `MinVersion` to TLS 1.2 for the listener.
* Tests: `TestNewAgentTLSConfig_Handshakes` (valid, no cert, expired, other CA, wrong usage, revoked, lookup error),
  `TestRevokeAgent_RevokesOnlyThatAgentsCertificatesAndBlocksIt`, `TestReinstateAgent_AllowsAFreshEnrolment`,
  `TestDisconnectAgent_ClosesTheLiveConnection`, plus RBAC matrix entries. The RBAC matrix suite still has its 314 earlier failures,
  none about these routes.
* Not done: a dashboard button, and the agent does not yet tell the operator it was revoked (it just fails to connect).

#### F-07 Renewal reuses the same private key. Low. Design limit. **FIXED**

* **Fix:** renewal and re-enrolment generate a new key in memory (`newAgentKey`); only after the server issues the certificate are
  the new key and certificate written as `.new` files and moved into place together (`rotateCredentials`). A crash at any point is
  repaired on the next start (`recoverPendingRotation`), and a failed renewal leaves the old key untouched. The first bootstrap
  is unchanged.
* **Tests:** `TestRenewal_GeneratesAFreshKey`, `TestRenewalFailure_LeavesTheOldKeyUntouched`, `TestRecoverPendingRotation`
  (crash before any rename, between the two renames, stale files).

`loadOrGenerateAgentKey` returns the stored key, so a renewed certificate carries the old key. Renewal therefore does not limit
the damage of a key that leaked earlier. Fix by generating a fresh key on renewal and swapping atomically.

#### F-08 Long-lived websocket connections are not re-validated. Low. Untested assumption. **PARTLY FIXED (dropped on revoke; no re-check at expiry)**

TLS verifies the certificate at handshake only. A connection opened before expiry or revocation stays up. Needed alongside
F-05: the server should drop connections of revoked or blocked agents when the block is applied.

## Incidental observations (status after the trace above)

Found while tracing the issuance path; each gets its own pass and verdict.

* **Area 5, missing:** nothing in the code ever sets `agent_certificates.revoked = true` (the column is only read). There is no way to revoke an individual agent certificate. `UnenrollAgent` only sets `agents.state = 'retired'` and does not touch certificates.
* **Area 3, to confirm:** revocation (and agent state) appears to be checked only on renewal, not at the TLS handshake or on `/ws/agent`.
* **Area 5, latent:** the bootstrap duplicate check ignores revoked rows, so once revocation exists, a revoked agent could re-enroll with the shared secret unless an agent-level block is added at the same time.
* **Area 6:** the CA certificate doubles as the server's TLS certificate, so the CA key is used in TLS handshakes. Server certificate and CA rotation are therefore coupled.
* **Area 3:** the listeners set no explicit `MinVersion` (Go's server default applies).
