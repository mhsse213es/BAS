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
- Linux VM variants. The analysis asked for Windows and Linux execution. No Linux test VM is available, so Linux steps would be unverified. Everything here is `supported_os: [windows]`.
- Cross-account and multi-subscription attack paths (the analysis's P2). They need two test accounts or subscriptions.
- Azure Blob upload for e36 uses the same storage token path as e32; it has not run against a real account.
- Cloud-side persistence via new federated credentials, and any change to existing production role assignments. Out of scope for a lab pack.

## Honest limits
- The `cloud-vm-attack` pack and these packs overlap at IMDS access (cv-a6 and the existing stage 1). cv-a6 adds the child-process check; it does not replace stage 1.
- cv-c22 to cv-c26 describe this host only. A PASS means this host was checked and no exposure was found, not that the fleet is clean.
- Stray output from a generator run with a mistyped root path was written to `C:\c\...`, outside the repository. A safety check blocked its removal; it still needs to be deleted by hand.
