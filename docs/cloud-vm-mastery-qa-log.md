# Cloud VM Mastery - QA Log

Scope: the Cloud VM Compromise and IAM Abuse expansion (pasted analysis, 31 numbered items, items 6 to 36). Built as five generated scenarios, alongside the existing `cloud-vm-attack` pack (unchanged).

| Scenario | Steps | Gate(s) |
|---|---|---|
| `cloud-vm-azure-identity` | cv-a6 to cv-a13 (8) | none; read-only |
| `cloud-vm-aws-iam` | cv-b14 to cv-b21 (8) | none; read-only (IAM policy simulation changes nothing) |
| `cloud-vm-credential-exposure` | cv-c22 to cv-c26 (5) | none; local, no cloud access |
| `cloud-vm-persistence-lateral` | cv-d27 to cv-d31 (5) | d27, d28, d29 gated; d30, d31 read-only |
| `cloud-vm-data-access` | cv-e32 to cv-e36 (5) | e36 gated; the rest read-only |

Sources: `scenarios-src/cloud-vm-common/lib.ps1` (shared helpers), one directory per scenario (`header.yaml`, `stages.json`, `cv-*.ps1`), generated with `appctlgen`, then signed.

## Verdict model
- PASS: the cloud control refused the action (HTTP 401/403, or AccessDenied / UnauthorizedOperation in CLI output). Local checks PASS when the host has no exposure.
- FAIL: the action succeeded for an identity the operator did not expect, or local material was found at rest.
- SKIP: a prerequisite is missing (not an Azure or EC2 instance, no identity, no CLI, gate not set, target not configured). Also used for "expected by the operator" and for GetCallerIdentity, which every principal may call and so scores no control.
- ERROR: the answer cannot be classified (for example HTTP 404, a timeout, or a refusal of the policy simulation itself).
- Operator expectations are set with exact-`true` env vars (`BAS_CLOUD_EXPECT_ENUMERATION`, `BAS_CLOUD_EXPECT_INSTANCE_ROLE`, `BAS_CLOUD_EXPECT_IMDS_ACCESS`, `BAS_CLOUD_EXPECT_KEY_CREATE`, `BAS_CLOUD_EXPECT_ROLE_ASSUME`, `BAS_CLOUD_EXPECT_EXFIL_SIM`, `BAS_CLOUD_EXPECTED_RESOURCES`). Without them, successful access is FAIL.

## Safety rules applied
- Tokens, access keys, client secrets, secret values and object bodies are held in memory and never printed or recorded. Steps record counts, names and lengths only.
- Write actions are gated (`BAS_CONFIRM_CLOUD_ROLE_ASSUME`, `BAS_CONFIRM_CLOUD_IAM_WRITE`, `BAS_CONFIRM_CLOUD_EXFIL_SIM`) and act only on operator-named test identities, buckets, containers or applications. The gate is checked before any cloud call.
- Create-then-delete steps (d28 access key, d29 client secret, e36 synthetic object) verify the deletion and report a FAIL that names the leftover id if cleanup could not be confirmed.
- WinRM and firewall state are read only (d30). Startup folders are checked by ACL only (d31).
- The privilege-escalation check (cv-b21) uses `iam simulate-principal-policy`, so no IAM change is made.

## What was verified (2026-11-17, Windows 10 Pro build host, not a cloud VM)
- All 31 generated step scripts parse in PowerShell 5.1 (ParseFile, zero failures).
- Classifier unit tests: 15 checks pass (HTTP 401/403 to PASS, 200 to FAIL, 0/500/404 to ERROR, AWS AccessDenied to PASS, missing credentials to SKIP, exact-case gate handling).
- Every step was executed on this host from the generated YAML. Cloud and gated steps returned SKIP with a stated reason. Local steps returned:
  - cv-c22 FAIL: `C:\Users\Administrator\.aws\credentials` holds a plaintext `aws_secret_access_key` (1 profile). Values were not printed. **This is a real finding on this host.**
  - cv-c23, c24, c25, c26 PASS (no Azure token cache, no cloud credential environment variables, no Terraform state with secret-like attributes, no SDK secret keys).
  - cv-d30 PASS (a WinRM listener exists, no inbound allow rule for 5985/5986).
  - cv-d31 PASS (startup folders not writable by non-administrative groups).
- Gated steps d27, d28, d29, e36 returned SKIP with no gate set. No temp payload was created by e36.
- The signer verifies all 193 scenarios. Go count pin updated 152 to 157; step-contract ledger and baseline regenerated (additions only, 31 steps).

## NOT verified (requires real Azure and AWS test environments)
- Every Azure and AWS step has never reached a cloud API. Their PASS, FAIL and ERROR branches are checked only by the classifier unit tests, not by a live response.
- Cloud-native evidence (Entra sign-in, Azure Activity Log, Key Vault audit, CloudTrail, storage analytics) was not collected. Endpoint output is not proof of cloud detection.
- The write steps (d27, d28, d29, e36) have never run with their gates set. Their cleanup branches are untested.
- Managed-identity behaviour (token issuance, scope) depends on the tenant configuration of the test VM.

## Not built, with reasons
- Cross-account and multi-subscription attack paths (the analysis's P2). They need two test accounts or subscriptions.
- Azure Blob upload for e36 uses the same storage token path as e32; it has not run against a real account.
- Cloud-side persistence via new federated credentials, and any change to existing production role assignments. Out of scope for a lab pack.

## Honest limits
- The `cloud-vm-attack` pack and these packs overlap at IMDS access (cv-a6 and the existing stage 1). cv-a6 adds the child-process check; it does not replace stage 1.
- cv-c22 to cv-c26 describe this host only. A PASS means this host was checked and no exposure was found, not that the fleet is clean.
- Stray output from a generator run with a mistyped root path was written to `C:\c\...`, outside the repository. A safety check blocked its removal; it still needs to be deleted by hand.

## Code review (commit 5f660ebf) and fixes
Ten findings. Fixed in this change:
- cv-d27 read the wrong expectation variable; it now honours `BAS_CLOUD_EXPECT_ROLE_ASSUME`.
- cv-d28 could not parse the created key id when CLI stderr preceded the JSON, and then attempted no cleanup. The JSON is now extracted tolerantly (`Get-CvJson`), and an unparseable id is a FAIL that says cleanup was not attempted.
- cv-d29 ignored `BAS_CLOUD_EXPECT_KEY_CREATE` on success; it now matches cv-d28.
- cv-e35 read a secret value with no confirm gate while marked production-safe. It now requires `BAS_CONFIRM_CLOUD_SECRET_READ`, and is marked not production-safe, high risk.
- cv-b21 treated unparseable simulation output as zero escalation paths (a false PASS). It is now ERROR.
- cv-b14 treated any metadata read failure as "no instance profile". Only HTTP 404 is now PASS; other failures are ERROR.
- cv-d31 turned a failed ACL read into PASS. It is now ERROR.
- cv-c24 flagged identifiers (AZURE_CLIENT_ID, AWS_ACCESS_KEY_ID) as secrets. It now flags only secret-bearing variables and an existing GCP credential file.
- The classifier checks lived only in this log. They are now committed as `scenarios-src/cloud-vm-common/lib.Tests.ps1` (exit 1 on failure); 0 failures.

Deferred, not changed here:
- The generator (`appctlgen`) appends a default cleanup to every step, so the step-contract ledger counts cv-d28 and cv-d29 as having declared undo even though the undo runs only inside the script. This is generator-wide, so it belongs in its own change. Until then, treat the ledger's cleanup column as unreliable for this pack.
- The ledger's destructive/non-destructive classification of the read-only AWS steps and cv-e36 looks inverted in places. Same owner: the contract classifier, not this pack.

Re-run after the fixes: all 31 steps parse; `lib.Tests.ps1` passes; the same 31 steps run locally with the same verdicts as before (cloud and gated steps SKIP, cv-c22 FAIL on this host, cv-c23/c24/c25/c26/d30/d31 PASS); signer verify-all ok=193 fail=0; step-contract and product-line tests pass.

## Linux variants (built 2026-11-17, bash, untested against cloud)
Ten further scenarios, each the Linux counterpart of a Windows pack above. Same step IDs with an `l` (`cvl-a6`..`cvl-e36`), `executor: bash`, `supported_os: [linux]`.

| Scenario | Steps | Gate(s) |
|---|---|---|
| `cloud-vm-linux-azure-identity` | cvl-a6 to cvl-a13 (8) | none; read-only |
| `cloud-vm-linux-aws-iam` | cvl-b14 to cvl-b21 (8) | none; read-only; b21 requires `jq` |
| `cloud-vm-linux-credential-exposure` | cvl-c22 to cvl-c26 (5) | none; local |
| `cloud-vm-linux-persistence-lateral` | cvl-d27 to cvl-d31 (5) | d27, d28, d29 gated; d30, d31 read-only |
| `cloud-vm-linux-data-access` | cvl-e32 to cvl-e36 (5) | e35 and e36 gated; the rest read-only |

Linux specifics: credentials paths are under `$HOME`; d30 reads `ss` (or `netstat`) plus `ufw`/`iptables` for SSH (22) and WinRM (5985/5986) exposure and never changes a service or rule; d31 checks group/other write bits on `/etc/rc.local`, `/etc/cron.d`, `/etc/cron.daily`, `/etc/profile.d`, `/etc/init.d`, `~/.config/autostart` and `~/.bashrc`. Gates, expectation variables, run tag and synthetic-data rules are identical to the Windows packs. Shared helpers are in `scenarios-src/cloud-vm-linux-common/lib.sh`.

### What was verified for Linux
- All 31 bash steps pass `bash -n`. Every step was executed from its generated YAML under Git Bash on this Windows host (not a Linux VM). Cloud and gated steps SKIP with the stated reason; cvl-c22 FAIL (the same plaintext AWS key); cvl-c23/c24/c25/c26 and cvl-d31 PASS; cvl-d30 ERROR, because Windows has no `ss` or `netstat -ltn` in the form the step uses. On a real Linux host d30 reads the sockets and should not ERROR.
- `lib.Tests.sh` checks the classifiers offline (13 checks, 0 failures): HTTP 401/403 PASS, 2xx FAIL, 000/500/404 ERROR, AWS AccessDenied PASS, missing credentials SKIP, exact-case gates.
- Signed (verify-all ok=205 fail=0), product-line pin 169, step-contract ledger and baseline regenerated (additions only).

### NOT verified: Azure and AWS (no test environment available)
- None of the Azure or AWS branches has run against a real endpoint, neither the Windows nor the Linux versions. The Linux IMDS paths (`169.254.169.254`) are exercised only as unreachable.
- The Linux steps were not run on a Linux VM. The d30 and d31 logic (ss/ufw/iptables parsing, `find -perm /022`) is unverified on Linux.
- Gated write steps (d27, d28, d29, e35, e36) have never run with gates set, on either OS.
- Azure and AWS verdict behaviour (PASS on 401/403, FAIL on unexpected success) is covered by the classifier tests only.
