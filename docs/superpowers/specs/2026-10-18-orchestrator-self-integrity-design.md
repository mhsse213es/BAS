# Orchestrator Self-Integrity Design

> Extension of the existing `internal/integrity` filesystem watcher, not a
> new subsystem. Scope: detect post-installation tampering with the
> orchestrator's own binary. Explicitly out of scope: whole-filesystem
> monitoring, in-memory integrity protection, clock-rollback mitigation.

## Context

`internal/integrity/watcher.go` already polls a fixed set of paths every
15s (`bas.lic`, `BINARIES.sha256`, wwwroot files, scenario YAMLs), records
mismatches into Postgres `tamper_events`, broadcasts a WS alert, and sets
a global `DispatchBlocked` flag on `"critical"` severity until an admin
acknowledges. Its trust model is **self-referential**: the baseline is a
snapshot taken at this process's own startup, so a binary already
tampered with before the process starts is invisible to it — the baseline
*is* the tampered state. The orchestrator binary itself is not watched at
all today.

This design adds a second, manifest-anchored check, reusing the alert
plumbing but not the self-baseline comparison.

## Trust boundary

Reuses the existing RSA-4096 keypair already used for scenario signing and
`BINARIES.sha256` (`orchestrator/private_key.pem`, never shipped;
public half embedded as `ScenarioPublicKeyPEM` in
`internal/integrity/signing.go`, verified via the existing
`parseContentPublicKey`/`rsa.VerifyPKCS1v15` path — **not** a key read
from the manifest itself, closing the "manifest supplies its own trust"
gap). No new keypair.

A new manifest, `SELFINTEGRITY.sha256` (+ `.sig`), lists exactly one entry:
the SHA-256 of the orchestrator binary as built. Kept separate from
`BINARIES.sha256` (agent/installer artifacts, with its own
download-integrity tests) rather than overloading that file's contract.

## Release-signing workflow

The private key never touches the Docker build context — `docker build`
has no access to it, matching the existing `BINARIES.sha256` flow exactly:

1. `orchestrator/Dockerfile`'s `builder` stage gains one more `-X` flag on
   its existing `-ldflags` (which already injects
   `main.expectedWWWManifestHash` the same way): `-X
   main.orchestratorManifestExpected=true`. This is **unconditional** —
   every build of this Dockerfile is building toward a release image, same
   as the existing wwwroot-hash flag.
2. `packaging/windows-build.ps1`'s `Update-OrchestratorAgentArtifacts`
   (`packaging/signing/sign-orchestrator-artifacts.ps1`) — which already
   extracts `BINARIES.sha256` from the just-built image via `docker cp`,
   signs it on the Windows build host with `private_key.pem`, and patches
   the signed result back into the image via a one-layer `COPY` — gains
   one more extraction: `docker cp <cid>:/orchestrator`, hash it with
   `Get-FileHash` (same technique already used for the Windows agent
   artifacts' hashes), write `SELFINTEGRITY.sha256`, sign it with the same
   `scripts/signer.go sign private_key.pem` call already used for
   `BINARIES.sha256`, and add `COPY SELFINTEGRITY.sha256
   /SELFINTEGRITY.sha256` + `.sig` to the same patch.
3. The signing operation runs **only** on the Windows build host, after
   the image exists, exactly like `BINARIES.sha256` today. A plain `docker
   build -f orchestrator/Dockerfile` run outside this pipeline (customers
   never do this — they only `docker load` pre-built, pre-signed tars via
   `install.sh`) would produce an image with `orchestratorManifestExpected
   = true` baked in but no manifest, and would correctly treat that as
   critical on first run. Noted as a residual constraint below, not
   engineered around.

## Legacy / "not expected" compatibility rule

Absence of `SELFINTEGRITY.sha256` is benign **only** when
`orchestratorManifestExpected != "true"` — i.e. this exact binary was not
built via the Dockerfile's builder stage (bare `go run`/`go build`/`go
test`, which never sets that ldflag). This is deliberately a build-time
marker baked into the binary, not a runtime heuristic (path sniffing,
environment variable) that could itself be spoofed by whatever placed a
tampered binary.

When `orchestratorManifestExpected == "true"`:
- Manifest file missing → **critical** (deleting the manifest must not be
  a way to disable the check).
- Manifest present but its own signature fails to verify, or is malformed
  → **critical**, same severity as a hash mismatch (an unverifiable
  manifest is treated as compromised, not ignored).
- Manifest present, verified, hash doesn't match the running binary →
  **critical**.
- Transient I/O error reading the *binary* (not the manifest) → logged as
  a distinct `integrity_check_error`, not escalated, retried next tick —
  avoids a false lockout from one glitch.

When `orchestratorManifestExpected != "true"`: skip entirely, log once at
startup that the check is disabled for this build.

## State transitions

- **Startup:** `CheckSelfIntegrity` runs synchronously in `main()`,
  **before** the HTTP listener starts accepting connections — so there is
  no window where protected endpoints are reachable on an unverified
  binary. Its outcome is never `log.Fatalf`: a critical result still lets
  the process start (so `/health`, login, and the tamper-event API stay
  reachable for an admin to see and act on the alert — killing the process
  would hide the alert, not surface it), but records the critical event
  and sets `DispatchBlocked` *before* `main()` proceeds to bind the
  listener. This reconciles "verification before accepting protected
  operations" with "do not immediately terminate the service": the gate
  is synchronous, the consequence is `DispatchBlocked`, not process exit.
- **Periodic:** folded into the *existing* `StartWatcher` 15s ticker
  (`internal/integrity/watcher.go`) as one more check per tick, rather
  than a second ticker — that interval was already judged acceptable for
  files that change far more often than a binary should, and hashing one
  file is cheap.
- **Recovery:** never automatic. The existing `AcknowledgeTamperEvent` /
  `AcknowledgeAllTamperEvents` handlers (`internal/api/tamper_handlers.go`)
  already only clear `DispatchBlocked` when zero unacknowledged `critical`
  rows remain — admin-gated by construction, for every tamper type. This
  design adds exactly one behavior on top: both ack handlers re-run
  `CheckSelfIntegrity` synchronously *before* their existing
  zero-unacknowledged-critical-rows count query. If the binary is still
  bad, that re-check inserts a fresh unacknowledged critical row through
  the same `recordTamper` path — which the existing count query then
  finds, so the ack is correctly refused with no new special-casing.
  Restoring the genuinely original, correctly-matching binary is just
  another `CheckSelfIntegrity` call that happens to succeed — there is no
  separate, weaker "trust it again" path.

## Component inventory

Phase 1: the orchestrator binary only (`os.Executable()`, resolved once
at process start — see residual risks). Not PKI/CA files (customer-
generated at install time; a build-time manifest cannot legitimately
cover per-deployment data — those stay on the existing self-baseline
watcher, which is the right tool for them). Not wwwroot (already covered
by the existing `expectedWWWManifestHash` mechanism at
`StaticHandler()` startup). Room to add more build-time-fixed files to
the same manifest later without redesigning anything.

## Reporting

`tamper_events` gains one nullable `detail jsonb` column (migration in
`internal/db/postgres.go`, same idempotent `ALTER TABLE ... ADD COLUMN IF
NOT EXISTS` style already used there for `tenant_id`). For a self-integrity
event, `detail` holds `{"expected_hash", "observed_hash", "outcome"}`.
`path` is set to a fixed sentinel identifying the component (not a
filesystem path, since `os.Executable()`'s path is a container-internal
detail, not useful to an admin). `detected_at` (existing column) supplies
the timestamp. Never logs secrets — hashes and the fixed component name
only. `event_type` gains one new value, `"hash_mismatch"`, alongside the
existing `write`/`remove`/`create` (the file-watcher's event vocabulary
doesn't fit a manifest-anchored check).

## Tests

1. Binary hash matches manifest → no event, no block.
2. Binary modified after a valid manifest is in place → critical event,
   `DispatchBlocked = true`.
3. Manifest missing, `orchestratorManifestExpected = true` (simulated via
   the build-time var) → critical.
4. Manifest missing, `orchestratorManifestExpected = false` → benign,
   no event.
5. Manifest signature invalid/malformed → critical (same as a hash
   mismatch).
6. Binary unreadable (permission/IO error) → `integrity_check_error`,
   not critical, not blocking.
7. Restoring the original binary → next check succeeds; `DispatchBlocked`
   stays however it was — recovery requires the explicit ack path, not an
   automatic clear.
8. Manifest deleted in a build with `orchestratorManifestExpected = true`
   (the specific "deleting the manifest disables the check" attack the
   first correction called out) → critical, confirmed distinct from the
   benign-legacy case.
9. Acknowledging a critical self-integrity event while the binary is
   *still* mismatched → ack is recorded, but a fresh critical row appears
   and `DispatchBlocked` stays `true` (revalidate-before-clear).
10. Acknowledging after the binary has genuinely been restored → clears
    normally, same as any other tamper type today.

## Residual risks (explicit, not hidden)

- **On-disk hashing does not prove in-memory code is unchanged.** A
  ptrace-based or similar in-memory-only patch that never rewrites the
  file on disk is invisible to this check by construction. This detects
  "the file at `os.Executable()`'s path differs from the signed release,"
  not "the code currently executing differs."
- **`os.Executable()` is resolved once per check, not cached across the
  process lifetime in a way that assumes the path is immutable** — each
  tick re-resolves and re-reads the file at that path, so a binary
  replaced via in-place rewrite is caught on the next tick. A replacement
  via unlink+rename on a platform where the OS keeps the original inode
  backing the already-running process can mean the hash check is validating
  bytes that are not byte-for-byte what is mapped into memory; this is
  the same category as the point above, not a separate bug to fix here.
- **A privileged administrator who controls the host can still disable or
  patch this detector itself.** This design makes tampering *visible*,
  not impossible — stated plainly, not implied.
- **A direct `docker build` of this Dockerfile outside the release
  pipeline** produces an image that expects a manifest it will never have,
  and will show critical on first run. Correct for an unofficial build;
  noted so it isn't mistaken for a bug if anyone ever does this.

## Post-implementation release-gate finding (fixed)

A release-gate review after the initial implementation found that
`integrity.DispatchBlocked` — set on every critical tamper event across
the *whole* watcher subsystem, not just self-integrity (`bas.lic`,
`BINARIES.sha256`, `wwwroot` tamper included) — was never actually read
anywhere. `dispatchRun` and all seven of its callers proceeded regardless
of its value; "Run dispatch SUSPENDED" was a log line, not an enforced
state, for every tamper type this design builds on, predating this
change. Fixed in commit `06aa9ec5` with a single check at the top of
`dispatchRun` (its one choke point for every caller), TDD'd against a new
`TestDispatchRun_SkipsWhenDispatchBlocked`. Everything else in this
document's "State transitions" section was already correct — the flag
*was* being set and cleared exactly as designed; it just had no effect
until this fix.
