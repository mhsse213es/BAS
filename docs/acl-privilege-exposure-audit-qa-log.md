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
| Tests | 1 admatrix grounding test | 38 offline tests (29 PowerShell cases, 9 Go tests) (library, generator, parse, contract, size, destructive-guard) plus the unchanged admatrix test |
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
- **LAPS** findings require ReadProperty on the attribute (or all properties) AND control access; plain read-all, which is the default, is not a finding.
- **gMSA:** msDS-ManagedPassword is a constructed attribute, so ACEs on it mean nothing. The stage checks the msDS-GroupMSAMembership reader list (a group of computers is normal; users, broad principals and groups with user members are findings) and who can write that list.
- **Real-AD behaviour of the LDAP code (scope resolvers, schema lookup, ACL reads, group expansion) is NOT VERIFIED.** The offline tests cover the evaluation logic only.
- **Size:** the file is about 446 KB, 6x the next-largest scenario (`dlp-exfiltration-file-carriers.yaml`, 66 KB). A shared-prelude field in the loader would cut it to roughly 40 KB but touches every YAML consumer; not done.
- **Step-contract test:** the class-aware contract test from the 11-11 work is not on this branch's base, so it was not run here.
- Sibling scenarios (AD CS, delegation, privileged-group paths, GPO exploitation) are untouched and are upgraded one at a time afterwards.

## Verification run (offline)
- `go test ./scripts/aclgen/`: library tests (29 PowerShell cases), generator determinism, contract fields, no mutating calls, tree-shake integrity, PowerShell parse of all 23 commands, size budget, destructive-step guard. Pass.
- `go test ./internal/scenario/... ./internal/admatrix/... ./internal/adcoverage/... ./internal/compliance/... ./scripts/...`: pass.
- `go run scripts/signer.go verify-all ../scenarios`: `ok=156 fail=0`, re-signed with the main checkout's release key.
- `agent/destructiveguard.Classify` on all 23 commands: non-destructive.
- Real-mode smoke on the build host (not domain-joined): stages 0, 3, 6, 9, 16, 18, 22 return `SKIP` quickly with "no reachable domain context".

## To test when you are ready (lab)
Run `lab/ad-canary/acl-canary.ps1 -Mode Seed` in a disposable domain, run the scenario as an ordinary domain user, compare with the expected-findings table in the script header, then `-Mode Remove`.

## Code audit of this implementation (2026-11-17)
You asked for an honest check of what I claimed. I re-read all of `lib.ps1` and wrote tests for realistic default-AD cases. Eight tests failed against the code as first delivered, so these claims were wrong or overstated:
1. **LAPS and gMSA stages would fail on a clean default domain.** Authenticated Users has read-all on most objects by default and was reported as a LAPS exposure. Fixed: LAPS needs read plus control access. The gMSA ACE check was conceptually wrong (constructed attribute); replaced by the reader-list and reader-list-write checks.
2. **Any stage using the tier-0 parent scope would always SKIP.** The domain head's parent DN (`DC=local`) is not an object, so it counted as unreadable. Fixed: parents must be inside the domain.
3. **Child-domain false positives.** Enterprise and Schema Admins carry the forest-root SID, not the local domain's, so they were flagged in child domains. Fixed.
4. **Protected Users (RID 525) was treated as an expected principal**, which could hide a real finding. Removed.
5. **The path stage printed PASS even when a tier-0 object could not be read.** Fixed: SKIP unless every node was read.
6. **GPO write only matched all-property writes**, missing property-specific writes such as gPCFileSysPath. Fixed.
7. **A failed schema lookup was treated as "attribute not deployed"** (a possible false PASS). Fixed: it is recorded as unreadable and not cached. Not covered by an offline test.
8. **gMSA reader list was read through `DirectoryEntry.Properties`**, which likely returns a COM object rather than bytes. Changed to `DirectorySearcher`. NOT VERIFIED live.

Still true and still open (none of this was fixed):
- Group member lists over 1500 entries are not range-retrieved; such a group is now marked truncated (so it is not wrongly dismissed) but never fully expanded.
- Members whose primary group is the trustee group are not in the `member` attribute and are not seen.
- Deny matching compares the same SID, Everyone and Authenticated Users only; a Deny on a group the trustee belongs to is not detected, so the finding stays HIGH.
- Account, Server, Backup and Print Operators and Replicator ACEs are suppressed as expected principals (as the original did). A delegation to them on a tier-0 object is never reported.
- In the path stage the start of a path is the trusted group, not each member.
- Any unreadable object makes a stage SKIP when there are no findings, which may make some stages SKIP routinely in a real domain until tuned.
- A GenericAll ACE reports once per capability checked, so one ACE can yield several lines.
- None of the LDAP code path (scope queries, schema lookup, ACL reads, group expansion) has run against a real domain.

Full `go test ./...` on this worktree: failures outside this change. `internal/killchain` signature tests fail in this worktree only (they pass on the main checkout; this branch changes no campaign or killchain files). `internal/api` needs the Docker Postgres container and cannot run here. `internal/apibas/runner` (`TestABUSE002Repeatability`) and `internal/networkefficacy` (live Suricata, 60 s timeouts) failed in the full run; I did not run them on a clean baseline. None of those packages is touched by this change.
