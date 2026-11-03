# AWS permissions for the BAS server (R-19d)

`bas-server-readonly-policy.json` is the read-only IAM policy for the credentials the BAS server uses for AWS discovery and the read-only probes.

## What it covers

| Actions | Used by |
|---|---|
| `iam:GetAccountAuthorizationDetails` | Discovery of users, roles and policies |
| `iam:SimulatePrincipalPolicy` | Read-only probe (asks IAM whether a principal would be allowed) |
| `s3:ListAllMyBuckets`, `s3:ListBucket`, `s3:GetBucketPolicy` | Discovery and the S3 probe |
| `backup:ListBackupVaults` | Discovery of backup vaults |
| `cloudtrail:LookupEvents` | Event source when an observe window is set |
| `organizations:ListParents`, `ListPoliciesForTarget`, `DescribePolicy` | Organization-level SCP evaluation |

`sts:GetCallerIdentity` is not listed: AWS allows every principal to call it.

## Choices made in this version

- `s3:ListBucket` is included as well as `s3:ListAllMyBuckets`, because the register describes the S3 probe as `s3:ListBucket`. Remove it if the probe is confirmed to use only the list-all call.
- `cloudtrail:LookupEvents` is included. Remove it if observe windows are not used on this server.
- The Organizations actions only succeed from the management account or a delegated administrator. In any other account the SCP step reports that it could not read the policies.

## What this file does not do

- It is not attached to anything. The operator attaches it to the server's IAM role or user.
- It grants no write access. Nothing here allows changing an account.
- It does not replace the account allow-list (`CLOUD_ALLOWED_ACCOUNTS`), which decides which accounts the server may read at all.

## Check before attaching

1. Validate the file: `python3 -m json.tool bas-server-readonly-policy.json`.
2. Run IAM Access Analyzer's policy validation on it.
3. After attaching, run the preflight for the account. Every check should pass, and the probes should run in dry-run mode.
