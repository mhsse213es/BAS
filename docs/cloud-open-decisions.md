# Cloud and Kubernetes open decisions (brief)

Three items need your decision or a configuration step before the next build. Each section says what the item is, what it affects, the choices, and what I recommend.

## R-20b: Trace exporter for cloud spans

**Decision (owner): Option A.** Trace export stays disabled in production. Console export is on the test machine only. No remote trace backend. No Tempo or Jaeger deployment for now. If a local collector is added later, self-hosted Tempo with a set retention period.

**Done:** the OTLP exporters now require a full http:// or https:// URL, refuse port 4317 (the gRPC port), and use the scheme for TLS. The console exporter had been writing to a discard sink and now writes to stdout. Tests cover these cases.

**What it is.** The cloud work emits spans: `cloud.discovery.pass` and `cloud.preflight`. Each span carries the account ID. A span is a timed record of one operation, which lets you see where time goes. Right now no exporter is wired in `cmd/server`, so the spans are discarded. Logs are the only working record.

**What already exists.** The code in `internal/observability/otel.go` builds a tracer provider with three choices:
- **Console:** prints spans to stdout. Useful for a local check. Nothing leaves the process.
- **Tempo:** sends spans over OTLP HTTP to a Grafana Tempo receiver, for example `http://tempo:4318`.
- **Jaeger:** the config has a field for it, but its comment gives port 4317, which is the gRPC port. The exporter uses OTLP HTTP, so that setting would not work as written. I'd fix or remove it before anyone uses it.

No collector is in the deployment compose file. Turning tracing on therefore means adding a container or pointing at one you already run.

**What it affects.**
- Spans include the account ID, and later the identities. The product is on-prem only, so traces must stay on your network. A hosted tracing service would be a data-sharing change and needs a decision of its own.
- Sampling and volume are not set. Every discovery pass would produce spans.

**Options.**
1. **Leave it off** (current state). Logs and metrics only. No new containers, no new data paths.
2. **Console only,** on a test machine. Lets you see the spans without any network path.
3. **Local Tempo or Jaeger** on the same host or network as the server. Gives you a trace view. Adds a container and a retention decision.

**My recommendation.** Option 1 for this build. Option 2 on your test machine, to confirm the spans look right. Option 3 after that, with a local collector and a short retention period, and only if you need trace views. Also decide whether to fix or drop the Jaeger setting.

**What I need from you.** Which option, and if option 3, which backend (Tempo or Jaeger) and how long to keep traces.

## R-20c: Windows permissions on the Azure secrets file

**What it is.** The Azure client secret is read from the file named by `CLOUD_AZURE_SECRETS_FILE`. On Linux the server refuses to start if the file is readable by anyone but its owner. On Windows, file permissions are access lists (ACLs), and the code does not check them. Anyone with read access to the file on that machine can read the secret.

**Why it's an operator task.** Only the operator can set the ACL, because it depends on the service account the server runs as. The code cannot know who should have access.

**What to do.** Give read access only to the account the server runs as, and remove inherited access. For example, from an elevated prompt:

    icacls "C:\path\to\azure.env" /inheritance:r /grant:r "NT SERVICE\<service-account>:R"

Then check it with `icacls "C:\path\to\azure.env"`. The output should list only that account (and Administrators, if you want them to keep access).

**When.** Before the Azure accounts are allow-listed on any Windows host. The server reports nothing about this, so the check is manual.

## R-19d: Least-privilege AWS credentials for the server

**What it is.** The cloud probes and the AWS discovery use the server's default AWS credential chain. That is whichever credentials the server's environment or instance role provides. The code cannot verify that those credentials are no more powerful than they need to be.

**The exact calls the probes make.**
- `sts:GetCallerIdentity`: reads which account the credentials belong to.
- `s3:ListBucket` on the bucket named in the probe.
- `iam:SimulatePrincipalPolicy`: asks IAM whether a principal would be allowed an action. It reads policies but changes none.

The discovery needs its own read permissions on top of these, because it reads IAM, S3 policies, Organizations, CloudTrail and Backup. Those are listed in the AWS discovery code.

**What to do.**
1. Create one IAM role for the server that holds read-only permissions only.
2. Start from the discovery's read list and the three probe calls above. Do not add write permissions.
3. Attach it to the server's instance role, or to a profile the server's environment names.
4. Run IAM Access Analyzer's policy check on the role, or simulate the calls, to confirm nothing beyond the list is granted.

**Why it matters.** If the role can write, a probe bug or a misuse of the API could change the account. The probes are read-only by design, but the credentials are the last line of defence.

**What I need from you.** Confirm whether you want me to write the exact IAM policy JSON for the discovery and probe calls. It would be a file in the repo, which you would then attach yourself. I cannot create the role or attach it.

## R-21: Stratus Red Team cloud attack-execution subsystem (REQ-010 broaden-cloud)

**What it is.** Datadog's open-source cloud adversary-emulation tool (`github.com/DataDog/stratus-red-team`). Each attack technique is Go code with `Detonate` and `Revert`, provisions its own ephemeral prerequisite infrastructure via embedded Terraform, and (per the maintainer) does not detonate against a customer's existing infrastructure. Proposed to close part of REQ-010 (cloud IAM-abuse, storage-exposure and workload attacks) by executing real, reversible attack techniques against a dedicated Audspect sandbox account, as a new execution subsystem separate from discovery and the read-only probes (`probe.go`).

**Decision (owner, 2026-11-09).** Direction approved, with conditions:
1. **Account:** one dedicated Audspect-owned AWS account, isolated from customer and operational accounts (never `opshddbackup` or any existing operational account). No detonation-capable code is built until the account is provisioned, ownership confirmed, budgets/spend alerts configured, and its permissions restricted to the approved technique set.
2. **Approval:** per detonation, by an operator other than the requester. No standing approval for a technique class. Bound to the exact technique version, account, target resources, parameters and execution window. Re-validated immediately before detonation.
3. **Spend:** Audspect owns warmup/detonate/cleanup/leaked-resource-recovery cost. Per-run budget guardrail plus an account-level budget alert. Cleanup is not treated as proof that every billable resource or charge is gone.
4. **Execution method:** the pinned, released `stratus` binary (not the Go library, not `@latest`), with its checksum and license verified before bundling, signed through Audspect's own supply-chain process after verification (see below for what upstream provides).
5. **Effort:** sized comparably to the read-only-probe work (`R-19`), not a quick library wire-up — it adds approval, durable lifecycle state, recovery/reconciliation, and its own API/console surface.

Also decided: `Revert` is a technique-supplied recovery mechanism, not proof of restored state — Audspect must independently verify post-revert state. Revert (attack-effect rollback) and cleanup (Terraform-destroy of prerequisites) are tracked and recorded independently. Lifecycle phase transitions are persisted before proceeding, so a restart can tell whether a run needs revert, cleanup, verification, or manual intervention, and never blindly re-runs a non-idempotent detonation. Dry-run must provision nothing and call no detonation API. Stratus's technique catalog is upstream content, not an Audspect coverage claim — only techniques Audspect has independently reviewed and tested are exposed. Azure and GCP are explicitly out of v1 (Azure doubly so: Azure discovery itself is still blocked on the tenant gap in `O-1`).

**Priority-1 verification (done 2026-11-09, read-only, no account needed):**
- License: confirmed from the repository's own `LICENSE` file — Apache License, Version 2.0 (permissive; standard attribution/NOTICE terms apply to anything bundled).
- Latest release: `v2.38.0` (2026-11-04). Assets: the pre-built archives for Darwin/Linux/Windows plus one `checksums.txt` (GitHub-computed SHA-256 digests per asset). **No signature or provenance file exists in the release assets** — no `.sig`, `.pem`, `.intoto.jsonl`, `.sigstore` or cosign bundle. The release notes' "verified signature" refers to GitHub's commit/tag signing, not a signed release artifact.
- OpenSSF Scorecard (scored 2026-11-04, before v2.38.0): **Signed-Releases score is 0** — "Project has not signed or included provenance with any releases," flagged for v2.36.0 through v2.37.2. No reason to assume this changed for v2.38.0. Pinned-Dependencies score 9 (healthy).
- GCP is a stated target platform (mentioned alongside AWS/Azure/Entra ID/Kubernetes in the project's own tooling), but I could not confirm a current technique count for it — moot for v1 since GCP is out of scope regardless.
- **Consequence for decision #4:** upstream provides no signed release or provenance attestation to verify against. "Verify upstream release provenance" therefore means: pin an exact tag, fetch the binary and `checksums.txt` over TLS from the official GitHub release, verify the SHA-256 matches, and treat that checksum-at-time-of-pinning as the trust anchor — not an upstream signature, because none exists. Audspect's own signing happens after that manual verification, on the binary Audspect then owns.

**What's blocked.** Everything past Priority 1 (sandbox account, fixed technique registry, approval/lifecycle, executor, reconciliation, evidence correlation, API/console — Priorities 2 through 8) waits on the AWS sandbox account: provisioned, ownership confirmed, budget alerts configured, permissions scoped to the eventual approved technique set.

**What I need from you.** Confirm whether the sandbox account exists yet or is being provisioned, and who owns the budget alert configuration. No detonation-capable code will be written before that.
