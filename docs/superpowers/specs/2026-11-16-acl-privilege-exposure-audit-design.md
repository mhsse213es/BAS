# ACL Privilege Exposure Audit: enterprise upgrade (design)

Status: DRAFT, awaiting approval. Scenario: `scenarios/acl-privilege-exposure-audit.yaml` (id unchanged; `internal/admatrix` references it).

## Intent
Make this scenario enterprise-grade. Acceptance criterion (user's): starting from a low-privileged domain principal, Audspect identifies and explains every permission path that could lead to control of a Tier-0 identity or resource, with reproducible evidence and an explicit confidence/status.

## Goals
- Add 16 stages (user numbering 7-22) on top of existing stages 0-5.
- Read-only by default: permission analysis only. Never reset passwords, modify ACLs, add members or write key credentials.
- Effective-permission calculation, not raw ACE listing.
- Every finding carries evidence: object DN, trustee SID, ACE, rights, ObjectType, inheritance source, affected targets, confidence.
- Fix the five issues the user listed in existing stages.

## Non-goals
- Not AD CS, Kerberos delegation, privileged-group-path or GPO-exploitation depth. Those sibling scenarios (`adcs-esc-template-exposure-audit`, `kerberos-delegation-exposure-audit`, `gpo-writable-linked-exposure-audit`, `dcsync-replication-rights-audit`) are upgraded later, one by one.
- No agent code change. No live exploitation.

## Anti-goals
- A raw ACE dump reported as "exploitable". An ACE is not a privilege until effective access is calculated.
- Inflated results: unresolved SIDs, unreadable DACLs, or an unverified path must report SKIP or a lower confidence, never PASS.

## Approaches (user chose 2)
1. Inline PowerShell per stage: simple, but ~22 drifting copies of the same logic.
2. **Chosen:** one shared reviewed PowerShell library, expanded by a build script into each stage's `command`. YAML stays fully reviewable and signed.
3. Native agent collector: rejected, conflicts with the dumb-executor rule and needs agent releases.

## Overlap decision (user agreed)
Stages 15 (RBCD), 19 (DCSync) and 22 (GPO) are built here as ACL-level checks: who holds the right. Link scope, trust and live verification stay in the sibling scenarios.

## Stages
Existing 0-5 are kept and corrected (below). New stages, by user numbering:
- P0: 7 GenericAll, 8 GenericWrite on sensitive attributes, 9 AddMember/AddSelf, 10 Ownership, 13 Shadow Credentials (msDS-KeyCredentialLink), 14 SPN modification, 16 LAPS read (legacy and Windows LAPS), 17 gMSA read (msDS-ManagedPassword), 19 DCSync rights, 20 OU inheritance, 21 domain root/Configuration/Schema ACLs, 22 GPO ACL and link permission.
- P1: 11 Delete/DeleteTree, 12 Validated writes (DNS hostname, SPN), 15 RBCD (msDS-AllowedToActOnBehalfOfOtherIdentity), 18 sensitive account attributes.
- Final stage: attack-path correlation (low-privilege principal to Tier-0 across relationships), with confidence.
Build order: P0 first, then P1, then correlation.

## Engine capabilities (shared library)
Effective permissions through nested groups (tokenGroups plus recursive expansion); inherited versus explicit; ObjectType GUID and extended-right resolution; explicit and inherited deny handling; SID resolution including foreign principals and SID history; AdminSDHolder/SDProp awareness; risk ranking (principal privilege, target criticality, scope, exploitability); evidence record per finding.

## Corrections to existing stages
1. Stage 1 targets add Builtin Administrators and other domain/forest privileged groups.
2. Stage 3 separates stale adminCount from actual effective permissions.
3. Stage 4 splits into ForceChangePassword, AddMember and property-specific WriteProperty.
4. Stage 5 adds ownership and effective-control relationships.
5. MITRE mapping per behaviour, not one technique for the audit. T1069 is group discovery, T1222 is file/directory permissions; mappings to be chosen per stage from the ATT&CK text and flagged in the QA log if uncertain.

## Constraints
- Each edit requires re-signing the `.sig` with the release key; a worktree needs `private_key.pem` copied from main first.
- Must satisfy the step contract (`step_contract_test.go`): detection, telemetry, cleanup or non-mutating declaration per step.
- Output keeps the PASS/FAIL/SKIP line convention the runner parses; Windows PowerShell 5.1 compatible; no em-dash footgun in generated strings.
- Large generated YAML: keep each stage's embedded library minimal (garble literal-size note applies only to Go).
- Control/ATT&CK IDs verified against source text, not memory.

## Verification plan
Unit tests: generator output is deterministic; every step passes the contract and signature gates. Lab canary (seeded OU with known ACEs) is written but NOT run until the user says to test. Nothing is claimed live-verified before that.

## Left to the builder
Library file layout, generator language (Go test helper or script), exact tier-0 target lists, confidence scale wording, output record format (within the PASS/FAIL/SKIP convention).

## Calls I made (flag if you disagree)
- Final correlation stage does its own single ACL walk, since steps share no state.
- Existing stage numbers stay; new stages use your numbers 7-22.
- Builder check done by me reading it as the builder, not a subagent (your inline-over-subagents preference).
