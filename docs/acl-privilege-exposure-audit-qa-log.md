# ACL Privilege Exposure Audit: upgrade QA log

Scenario: `scenarios/acl-privilege-exposure-audit.yaml` (id unchanged). Spec: `docs/superpowers/specs/2026-11-16-acl-privilege-exposure-audit-design.md`. Plan: `docs/superpowers/plans/2026-11-16-acl-privilege-exposure-audit.md`.

**Verification status.** Everything below that says "verified" was checked offline: unit tests with in-memory security descriptors, PowerShell parsing, generator and contract tests, signature gate. **Nothing has been run against a real Active Directory domain. All live behaviour is NOT VERIFIED.** On a host with no domain, every stage returns `SKIP` (checked on the Windows build host).

## How it is built
- Sources: `scenarios-src/acl-privilege-exposure-audit/` (`header.yaml`, `lib.ps1`, `stages.json`, `tests/lib.Tests.ps1`).
- Generator: `go run ./scripts/aclgen` (from `orchestrator/`), then re-sign. The YAML is generated; edit the sources, not the YAML.
- Each step embeds only the library functions it reaches (tree-shaken, comments and indentation stripped). Steps are self-contained because the schema has no shared-prelude field and other tools parse the YAML on their own.
- Commands over 8000 bytes already run from a temp file (`agent/scriptfile.go`), so length is not a launch problem.

## Before and after
Before = `HEAD` of this branch (`05cd683b`). After = this change.

| Area | Before | After |
|---|---|---|
| Steps | 6 (1 context + 5 audit) | 23 (1 context + 21 audit + 1 attack-path correlation; file stages 0-22) |
| Audit stages | 5 | 22 |
| Command size | 17 KB file, 6 steps | 446 KB file, 23 steps (about 16 KB each) |
| Targets audited | 3 groups, domain head, AdminSDHolder, adminCount=1 objects | Privileged groups (domain, builtin and operator groups, Key Admins, DCs, GPCO), tier-0 users/computers/groups and their parent OUs, domain head, AdminSDHolder, Configuration and Schema heads, all OUs, GPOs and link points, gMSAs |
| Rights covered | GenericAll, GenericWrite, WriteDacl, WriteOwner, CreateChild/DeleteChild, any WriteProperty (stage 3), reset-password and all extended rights, member write | Adds AddSelf, ownership, Delete/DeleteTree/DeleteChild, validated writes (DNS hostname, SPN), msDS-KeyCredentialLink, servicePrincipalName, RBCD attribute, legacy and Windows LAPS reads, gMSA reads, account-restriction attributes, DCSync extended rights, GPO write and gPLink write |
| Trustee analysis | Direct ACE SID only | Nested group members expanded; a group whose members are all tier-0 is not a finding; empty group is reported at lower confidence |
| Deny ACEs | Ignored (only Allow read) | Matching Deny lowers the finding to MEDIUM with a note; it is not silently dropped |
| Inheritance | Not handled; inherit-only ACEs counted | Inherit-only and class-mismatched ACEs ignored; stage 19 reports inherited ACEs only |
| Expected principals | Wildcard RID patterns matched any domain; SELF and CREATOR OWNER not excluded | Domain-SID-anchored RIDs; SELF, CREATOR OWNER, SYSTEM, Enterprise DCs and built-in admin groups excluded |
| Attribute GUIDs | Two hard-coded GUIDs | Resolved from the live schema by name; missing attribute (for example LAPS not deployed) reports "not deployed" |
| adminCount handling | Every adminCount=1 object treated as privileged | Stale protection reported separately from effective control |
| Evidence per finding | `SID \| target \| rights` | Target DN, trustee SID and name, capability, rights, ObjectType, inherited flag, confidence, membership path, note |
| Confidence labels | None | HIGH / MEDIUM / LOW per finding and per path |
| Attack-path correlation | None | Stage 22: backward search from tier-0 objects, up to 3 hops, cycle-safe, broad-principal flag |
| Unreadable data | Could print PASS | `SKIP` unless a finding exists; truncated scopes also `SKIP` |
| Detection declared | 6 of 6 | 22 of 22 audit stages (context stage has none) |
| Telemetry declared | 5 of 6 | 23 of 23 |
| MITRE mapping | T1069 x5, T1222 x1 | T1069.002 x3, T1087.002 x2, T1098 x12, T1003.006, T1484.001, T1485, T1555 x2, T1558.003 (per behaviour; see below) |
| Tests | 1 admatrix grounding test | 29 offline tests (20 PowerShell cases, 9 Go tests) (library, generator, parse, contract, size, destructive-guard) plus the unchanged admatrix test |
| Lab canary | None | `lab/ad-canary/acl-canary.ps1` written, NOT run |
| Writes to AD | None | None (read-only; a test forbids mutating calls in stage text) |

## Stage numbering
File stage N is your stage N+1 (the file keeps stage 0 as the context stage). Mapping for new stages: file 6 = your 7 GenericAll, 7 = 8 GenericWrite, 8 = 9 AddMember/AddSelf, 9 = 10 Ownership, 10 = 11 Delete/DeleteTree, 11 = 12 Validated Write, 12 = 13 Shadow Credentials, 13 = 14 SPN, 14 = 15 RBCD, 15 = 16 LAPS, 16 = 17 gMSA, 17 = 18 Sensitive attributes, 18 = 19 DCSync, 19 = 20 OU inheritance, 20 = 21 Domain/Config/Schema, 21 = 22 GPO, 22 = correlation (added).

## Your five corrections
1. Stage 1 now includes Builtin Administrators, operator groups, Key Admins, Domain Controllers and GPCO, not only the three forest groups.
2. Stage 3 separates `STALE=` lines from effective exposure; stale-only does not FAIL.
3. Old stage 4 is split: ForceChangePassword stays in stage 4, member write moved to stage 8 (AddMember/AddSelf), attribute-specific writes to stages 7, 12-14, 17.
4. Stage 5 now includes ownership (`GetOwner`) alongside WriteDacl/WriteOwner; stage 9 widens ownership to containers and GPOs.
5. MITRE mappings are set per stage. Mappings I am not sure of and want you to confirm: stage 10 uses T1485 (closest fit for deletion of privileged objects), stage 14 RBCD uses T1098 (no dedicated ATT&CK technique), stages 4-9 and 11-13 use T1098 for "Account Manipulation". T1222 was removed everywhere.

## Behaviour changes to be aware of
- Stage 2 no longer flags CreateChild/DeleteChild on the domain head. Those rights are granted broadly by default (for example Authenticated Users creating computer accounts) and are not takeover paths.
- Stage 3 previously flagged any WriteProperty by non-tier-0 trustees, which includes SELF on every account; that false-positive source is gone.
- Stage 1 name and telemetry/detection strings are unchanged because `internal/admatrix` pins them.

## Not done or only partly done (stated plainly)
- **Effective access is approximate.** Group membership uses recursive `member` expansion, not `tokenGroups`. Deny ACEs lower confidence but ordering and ACE-by-ACE evaluation are not modelled.
- **SID history is not resolved.** Foreign-domain principals are only resolved when the local DC can translate their SID; foreign group members are not expanded.
- **AdminSDHolder/SDProp awareness is partial:** stage 3 reports stale protection and stage 19 documents that protected objects have inheritance disabled; no SDProp timing logic.
- **Scope caps:** OU sweeps cap at 2000, tier-0 computer sweeps at 200, member expansion at 2000 nodes. A cap hit returns `SKIP` with a note when nothing was found, never a clean PASS.
- **LAPS and gMSA reads** are reported at MEDIUM when the control-access bit is not seen, because confidential-attribute reads need both ReadProperty and control access.
- **Real-AD behaviour of the LDAP code (scope resolvers, schema lookup, ACL reads, group expansion) is NOT VERIFIED.** The offline tests cover the evaluation logic only.
- **Size:** the file is about 446 KB, 6x the next-largest scenario (`dlp-exfiltration-file-carriers.yaml`, 66 KB). A shared-prelude field in the loader would cut it to roughly 40 KB but touches every YAML consumer; not done.
- **Step-contract test:** the class-aware contract test from the 11-11 work is not on this branch's base, so it was not run here.
- Sibling scenarios (AD CS, delegation, privileged-group paths, GPO exploitation) are untouched and are upgraded one at a time afterwards.

## Verification run (offline)
- `go test ./scripts/aclgen/`: library tests (20 PowerShell cases), generator determinism, contract fields, no mutating calls, tree-shake integrity, PowerShell parse of all 23 commands, size budget, destructive-step guard. Pass.
- `go test ./internal/scenario/... ./internal/admatrix/... ./internal/adcoverage/... ./internal/compliance/... ./scripts/...`: pass.
- `go run scripts/signer.go verify-all ../scenarios`: `ok=156 fail=0`, re-signed with the main checkout's release key.
- `agent/destructiveguard.Classify` on all 23 commands: non-destructive.
- Real-mode smoke on the build host (not domain-joined): stages 0, 3, 6, 9, 16, 18, 22 return `SKIP` quickly with "no reachable domain context".

## To test when you are ready (lab)
Run `lab/ad-canary/acl-canary.ps1 -Mode Seed` in a disposable domain, run the scenario as an ordinary domain user, compare with the expected-findings table in the script header, then `-Mode Remove`.
