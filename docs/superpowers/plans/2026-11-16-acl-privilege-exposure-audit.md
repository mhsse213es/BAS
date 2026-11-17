# ACL Privilege Exposure Audit Upgrade Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans (user chose inline execution). Steps use checkbox syntax.

**Goal:** Upgrade `scenarios/acl-privilege-exposure-audit.yaml` from 5 audit stages to 22 audit stages plus a path-correlation stage, read-only, with effective-permission analysis and evidence records.

**Architecture:** One reviewed PowerShell library (`lib.ps1`) plus a stage table (`stages.json`) live in `scenarios-src/acl-privilege-exposure-audit/`. A Go generator (`orchestrator/scripts/aclgen`) expands them into each step's `command`, so the signed YAML stays fully self-contained. Library logic is unit-tested offline with in-memory `ActiveDirectorySecurity` objects driven from a Go test; no domain is needed.

**Tech Stack:** Windows PowerShell 5.1 (System.DirectoryServices), Go (generator + tests), existing `scripts/signer.go`.

**Spec:** `docs/superpowers/specs/2026-11-16-acl-privilege-exposure-audit-design.md`

## Global Constraints
- Read-only: no DACL write, password reset, ownership take, membership change, or key-credential write. Stage commands contain no `.CommitChanges`, `SetAccessRule`, `Set-ADObject`, `Add-ADGroupMember`, `SetPassword`.
- Scenario id `acl-privilege-exposure-audit` and Stage 1 name `ACL Stage 1 — Privileged Group DACL Exposure (Domain/Enterprise/Schema Admins)` unchanged: `internal/admatrix` pins that name and its telemetry/cleanup strings (`capability_state_test.go:244`).
- Output convention per step: exactly one of `PASS:`, `FAIL:`, `SKIP:` first line ending `[ACL-Sn]`; evidence lines indented two spaces.
- PowerShell 5.1 compatible; ASCII-safe string literals (em-dash footgun); each step `timeout_sec` set.
- Every step passes the step contract (detection, telemetry, cleanup or non-mutating declaration) and the signature gate (`go run scripts/signer.go verify-all <scenarios dir>` from `orchestrator/`).
- Re-sign every edited YAML with the main checkout's `orchestrator/private_key.pem` (absolute path); never copy the key, never `--allow-dev`.
- Unresolved SID, unreadable DACL or unverified path never yields PASS: it yields SKIP or lower confidence.
- ATT&CK/GUID facts come from source text, uncertain ones go to the QA log. Nothing is lab-verified; QA log says NOT VERIFIED.

## Review Focus
- Trustee is a group whose members are tier-0 only: must not FAIL (effective-membership check).
- Explicit Deny ACE on the same right for the same trustee: finding downgraded, not silently dropped.
- Inherit-only ACE or ACE whose InheritedObjectType does not match the target class: ignored.
- SELF (S-1-5-10), CREATOR OWNER (S-1-3-0), SYSTEM and Enterprise Domain Controllers are expected principals, not findings.
- LAPS or gMSA not deployed (attribute absent from schema): PASS-N/A with a clear note, not a failure and not an error.
- Unresolvable SID (deleted account, foreign principal): reported with LOW confidence, not dropped.

---
## File Structure
- `scenarios-src/acl-privilege-exposure-audit/lib.ps1`: shared library.
- `scenarios-src/acl-privilege-exposure-audit/stages.json`: per-stage metadata and arguments.
- `scenarios-src/acl-privilege-exposure-audit/tests/lib.Tests.ps1`: offline PowerShell tests.
- `orchestrator/scripts/aclgen/main.go`, `aclgen_test.go`: generator and its tests.
- `scenarios/acl-privilege-exposure-audit.yaml` (+ `.sig`): generated output.
- `docs/acl-privilege-exposure-audit-qa-log.md`: QA log with the before/after table.
- `lab/ad-canary/acl-canary.ps1`: lab seeding script (written, NOT run).

### Task 1: Generator and stage table
**Files:** Create `orchestrator/scripts/aclgen/main.go`, `aclgen_test.go`, `scenarios-src/.../stages.json`, `lib.ps1` (stub).
**Interfaces:** Produces `func Generate(srcDir string) ([]byte, error)` returning full scenario YAML; `stages.json` entries `{id, n, name, technique_id, attack_note, timeout_sec, telemetry[], detection[], blast_radius, call}` where `call` is the one-line `Invoke-AclStage ...` invocation appended after the library.
- [ ] Test `TestGenerateDeterministic` (two runs byte-identical), `TestEveryStepHasContractFields` (detection, telemetry, cleanup key, production_safe true, reversible true), `TestNoMutatingCalls` (command text contains none of the forbidden tokens), `TestStage1NamePinned`.
- [ ] Run `go test ./scripts/aclgen/` from `orchestrator/`: FAIL.
- [ ] Implement generator: header fields copied from the current YAML (id, product_line, tags, live_policy, supported_os), steps in `n` order, `command` = lib.ps1 + call, written with `|` block scalars.
- [ ] Run tests: PASS. Commit.

### Task 2: Library core with offline tests
**Files:** `lib.ps1`, `tests/lib.Tests.ps1`, Go harness `aclgen/pslib_test.go` (skips if `powershell.exe` missing).
**Interfaces (all in lib.ps1):**
- `Get-AclContext -> object{DomainDN,ConfigDN,SchemaDN,DomainSid,Tier0 (hashset of SIDs and RID suffix rules)}`
- `ConvertTo-AceRecord($Ace,$TargetDn,$TargetClass) -> {Trustee,Type,Rights,ObjectType,InheritedObjectType,IsInherited,InheritOnly,TargetDn}`
- `Test-AceApplies($Rec,$TargetClass) -> bool` (drops inherit-only and class-mismatched)
- `Test-AceGrants($Rec,$Cap) -> bool`, `$Cap = @{Rights=[ActiveDirectoryRights]; ObjectTypes=[guid[]]; AllowEmptyObjectType=bool}`; GenericAll always grants; empty ObjectType grants all properties
- `Get-EffectiveMembers($Sid,$Ctx) -> string[]` (tokenGroups for users, recursive member expansion for groups, cycle-safe)
- `Test-ExpectedPrincipal($Sid,$Ctx) -> bool` (tier-0 set plus S-1-5-10, S-1-3-0, S-1-5-18, S-1-5-9, Builtin Administrators)
- `Resolve-Trustee($Sid) -> {Name,Kind,Resolved}`; `Get-Confidence($Rec,$Members,$Denies) -> 'HIGH'|'MEDIUM'|'LOW'`
- `Find-CapabilityExposure($TargetDns,$Cap,$Ctx) -> finding[]` where finding = `{Target,Trustee,TrusteeName,Rights,ObjectType,Inherited,Confidence,Path}`
- `Write-StageVerdict($StageId,$Findings,$ReadErrors,$PassText)`: SKIP if read errors and no findings, PASS if none, FAIL otherwise; prints evidence lines `  TARGET=<dn> | TRUSTEE=<sid> (<name>) | RIGHTS=... | OBJECTTYPE=... | INHERITED=... | CONFIDENCE=...`
- [ ] Tests (build `ActiveDirectorySecurity` objects in memory): `AddMember ACE for low-priv SID => finding`, `same ACE for Domain Admins => none`, `Deny same right => MEDIUM not dropped`, `inherit-only ACE => ignored`, `class-mismatched InheritedObjectType => ignored`, `SELF/CREATOR OWNER => none`, `unresolved SID => LOW`, `group whose only member is tier-0 => none`, `unreadable target => SKIP`.
- [ ] Run harness: FAIL. Implement. Run: PASS. Commit.

### Task 3: Rewrite existing stages 0-5 with corrections
**Files:** `stages.json`, regenerate YAML.
- Stage 0 context only. Stage 1 targets add Builtin Administrators (S-1-5-32-544), Account/Server/Backup/Print Operators, Key Admins, Enterprise Key Admins, Domain Controllers, Administrators-equivalents; AdminSDHolder too. Stage 2 domain head and AdminSDHolder, inheritance-aware. Stage 3 reports adminCount stale-protection (no longer in privileged group closure) and effective exposure separately (two evidence sections). Stage 4 becomes ForceChangePassword, AddMember WriteProperty, with GUIDs `00299570-246d-11d0-a768-00aa006e0529` and `bf9679c0-0de6-11d0-a285-00aa003049e2`, as separate checks. Stage 5 adds owner (`GetOwner`) check beside WriteDacl/WriteOwner.
- MITRE: stages 1,2 T1222.001 is wrong (file/dir); use T1069.002 only for group-discovery steps, T1087.002 / T1098 for permission exposure per behaviour; record chosen IDs and rationale in `attack_note`, uncertain ones flagged in QA log.
- [ ] Test `TestExistingStagePinsForAdmatrix`: parse generated YAML with `scenario.ParseYAML`, Stage 1 name and telemetry exact. Run admatrix tests: `go test ./internal/admatrix/ -run ACL`. Commit.

### Task 4: P0 direct ACL stages 7,8,9,10
Calls via `Find-CapabilityExposure`: 7 GenericAll over users, groups, computers, OUs, domain object of tier-0 scope; 8 WriteProperty (all-props) plus sensitive attributes on privileged objects; 9 member WriteProperty and Self right with ObjectType member (AddSelf); 10 owner not in expected set (`GetOwner`). 
- [ ] Add one library test per stage invocation shape, regenerate, run harness and aclgen tests, commit.

### Task 5: P0 credential-attribute stages 13,14,16,17
13 msDS-KeyCredentialLink; 14 servicePrincipalName; 16 LAPS: `ms-Mcs-AdmPwd`, `msLAPS-Password`, `msLAPS-EncryptedPassword`; 17 gMSA: `msDS-ManagedPassword` readers via `msDS-GroupMSAMembership` and ACEs. Attribute GUIDs resolved at runtime via `Get-SchemaGuid($LdapName)` (query schemaIDGUID in Schema NC); absent attribute gives `PASS: not deployed` with note.
- [ ] Tests: `Get-SchemaGuid` returns $null offline => stage prints not-deployed PASS; others as Task 4. Commit.

### Task 6: P0 domain and forest stages 19,20,21,22
19 DS-Replication-Get-Changes `1131f6aa-9c07-11d1-f79f-00c04fc2dcd2`, Get-Changes-All `1131f6ad-9c07-11d1-f79f-00c04fc2dcd2`, Get-Changes-In-Filtered-Set `89e95b76-444d-4c62-991a-0facbeda640c` on domain head, non-DC trustees; 20 inherited ACEs on OUs holding tier-0 objects; 21 domain root, Configuration and Schema NC heads; 22 GPO container ACLs (`CN=Policies,CN=System`), GPO owner, and `gPLink` write on domain/DC OU.
- [ ] Tests as above; confirm GUIDs against Microsoft extended-rights reference and log source. Commit.

### Task 7: P1 stages 11,12,15,18
11 Delete and DeleteTree on privileged objects and their containers; 12 validated writes (Self right with DNS-Host-Name-Attributes `72e39547-7b18-11d1-adef-00c04fd8d5cd`, SPN `f3a64788-5306-11d1-a9c5-00c04fd8d5cd`); 15 msDS-AllowedToActOnBehalfOfOtherIdentity write; 18 userAccountControl, msDS-AllowedToDelegateTo, and related restriction attributes.
- [ ] Tests, regenerate, commit.

### Task 8: Stage 23 attack-path correlation
`Find-AttackPaths($Ctx) -> path[]`: one walk over tier-0 objects and OUs; edges = capability exposures from earlier tasks; path = low-priv principal -> (edge)* -> tier-0 object, depth limit 3, each path with `Confidence` and `Steps`. Output: `FAIL: N path(s)` with `PATH=` evidence lines; SKIP if the walk was truncated.
- [ ] Tests: two-hop synthetic graph (group A has AddMember on group B, B has GenericAll on Domain Admins) yields one path; cycle does not loop; depth cap respected. Commit.

### Task 9: Gates, canary, QA log, sign, comparison
- [ ] Write `lab/ad-canary/acl-canary.ps1` (seeds OU with known ACEs; header states LAB ONLY, not run).
- [ ] Regenerate YAML; `go run scripts/signer.go sign <main>/orchestrator/private_key.pem scenarios/acl-privilege-exposure-audit.yaml`; `verify-all` expects `fail=0`.
- [ ] Run: `go test ./internal/scenario/... ./internal/admatrix/... ./scripts/aclgen/... -p 2`; expect PASS. Update contract baseline only via `STEP_CONTRACT_WRITE=1` if the contract test requires, and diff it.
- [ ] Write `docs/acl-privilege-exposure-audit-qa-log.md`: changes, MITRE rationale, NOT VERIFIED lab items, before/after table. Commit and push.
