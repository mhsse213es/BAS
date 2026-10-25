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

Progress: 1 and 2 done. 3, 4, 5, 6 not started (incidental observations recorded at the end, unconfirmed).

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

#### F-01 CSR key algorithm and size are not validated. Medium. Verified (executed).

* **Path:** `IssueClientCertificate` signs `csr.PublicKey` whatever it is. There is no check anywhere.
* **Evidence:** a scratch test issued a certificate for an RSA-1024 key and for an ECDSA P-224 key (both `err = nil`). (RSA-512 could not be tested: Go refuses to generate it.)
* **Impact:** whoever can enroll (holds the bootstrap secret) can obtain a client certificate with a key that is cheap to break, and then impersonate that agent. The agent's own key is ECDSA P-256 (`agent/certstore.go`), so legitimate agents are unaffected.
* **Remediation:** accept ECDSA P-256/P-384 and RSA at least 2048 bits; reject everything else with a clear error. Do the check in `IssueClientCertificate` so every caller is covered.
* **Regression test:** `TestIssueClientCertificate_RejectsWeakKeys` (RSA-1024, P-224 rejected; P-256, P-384, RSA-2048 accepted).

#### F-02 Agent HTTP endpoints ignore the certificate's identity. High. Verified (code).

* **Path:** `Heartbeat`, `SubmitRunEvents`, `ReceiveEvents` (logs), `UninstallAgentResult`, `UnenrollAgent` and the other `validateAgentAuth` callers authenticate with the shared `X-Agent-Token` only, and take the AgentID from the request body or URL. `AuthenticatedAgentID` is read in exactly two places: `EnrollCSR` and `wsAgentAuthorized`.
* **Impact:** any holder of the shared secret (and any enrolled agent, which holds it too) can report as, mark `uninstalled` (`UninstallAgentResult`), or retire (`UnenrollAgent`) any other agent, and inject events or heartbeats for it. Holding a valid certificate gives no extra protection on these routes. With `AGENT_SECRET` empty, `validateAgentAuth` returns true and there is no authentication at all.
* **Constraint on the fix:** the plaintext legacy listener (`:9000`) serves the same router and its agents have no certificate, so binding cannot be mandatory until that listener is retired.
* **Remediation:** when a request carries an mTLS identity, require the AgentID in the body or URL to equal it (reject otherwise). Then make the identity mandatory on the agent routes once the legacy listener is gone. Track the legacy listener retirement as the dependency.
* **Regression test:** a table test over each agent route: a request with identity A and an AgentID of B returns 401; identity A with AgentID A succeeds. (Needs the Postgres test harness used by `internal/api`.)

#### F-03 Bootstrap identity is claimed, not attested. Medium. Design limit.

* **Path:** `EnrollCSR` on `:9444` accepts the shared secret and any well-formed AgentID that has no currently valid certificate. AgentID is `hex(SHA-256(hostname))[:16]`, so it is predictable.
* **Impact:** a holder of the bootstrap secret can enroll under another machine's AgentID once that machine's certificate has expired, or before it first enrolls, and later receive its commands. Recovery of an expired agent uses the same path, so this is intended behaviour, but it means the shared secret is the whole trust anchor for first identity.
* **Remediation options (decision needed):** per-agent or single-use enrollment tokens; an operator approval step for an AgentID that already exists; or at minimum an audit event and dashboard alert when an existing AgentID re-bootstraps.
* **Regression test:** depends on the chosen option.

### Positive checks still to execute (cheap, planned)

Tests that pin the properties in the "what holds" table, each written to fail if the property were removed: CSR subject ignored (CSR for CN=other yields CN=requested agent), non-hex AgentID rejected, `agentId` mismatch on renewal returns 401, leaf has `ClientAuth` only and `IsCA=false`.

## Incidental observations for later passes (unconfirmed)

Found while tracing the issuance path; each gets its own pass and verdict.

* **Area 5, missing:** nothing in the code ever sets `agent_certificates.revoked = true` (the column is only read). There is no way to revoke an individual agent certificate. `UnenrollAgent` only sets `agents.state = 'retired'` and does not touch certificates.
* **Area 3, to confirm:** revocation (and agent state) appears to be checked only on renewal, not at the TLS handshake or on `/ws/agent`.
* **Area 5, latent:** the bootstrap duplicate check ignores revoked rows, so once revocation exists, a revoked agent could re-enroll with the shared secret unless an agent-level block is added at the same time.
* **Area 6:** the CA certificate doubles as the server's TLS certificate, so the CA key is used in TLS handshakes. Server certificate and CA rotation are therefore coupled.
* **Area 3:** the listeners set no explicit `MinVersion` (Go's server default applies).
