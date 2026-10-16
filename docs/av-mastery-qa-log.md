# AV/NGAV BAS Mastery — Deferred QA Log

This document tracks every verification gap, blocked item, or deliberate scope exclusion that came up while implementing the AV/NGAV BAS Mastery initiative (`av.txt`, repo root — no separate design spec was written; this initiative was driven directly from that root file, phase by phase, mirroring the already-merged WAF BAS Mastery initiative's package shapes). Each entry stays here until it's actually resolved; resolving one means updating its own entry with the resolution and date, not deleting it.

This is the single place to check before claiming AV/NGAV Mastery is "done" or making any external maturity claim about it — mirrors the role `docs/webgw-mastery-qa-log.md` plays for Web Gateway BAS Mastery.

**Note on this doc's own history:** the testing/QA detail for this initiative was reported only in chat at the end of each work session, not saved here, until this entry was added on 2026-10-16 in direct response to the user asking where it lived. Every item below is reconstructed from the actual current code (verified by direct read/grep on 2026-10-16), not from memory of what was said earlier.

## Open items

### 1. Real Microsoft Defender vertical — blocked on tenant/infra access, not engineering

**Status:** Open, blocked on infrastructure the user does not currently have, per the user's own standing directive (do not enable/alter protection on the build host just to make a test pass; use a dedicated lab endpoint).

**What's needed:** A real adapter exercising an actual Defender for Endpoint tenant (Microsoft Graph Security API) end-to-end — policy/config read, real detection-event correlation, real prevention verdicts — instead of `internal/avval`'s fixture-backed evidence model.

**Why it's blocked:** Requires an Entra ID app registration with admin consent for the Graph Security scopes, plus a dedicated test endpoint with real-time protection actually enabled (the build/staging hosts in use are not suitable targets for this). Neither is available in this environment today.

**What this means today:** every `internal/avefficacy` scenario (9 registered scenarios) is fixture-backed only (`EvidenceSourceFixture`; `EvidenceSourceLiveExecution` is declared in `internal/avefficacy/evaluate.go` for forward compatibility but has no real producer). This is disclosed in-band: every `ScenarioResult.Summary` carries a fixed fixture-only disclosure sentence, never silently presented as live coverage.

**Resolution path, when it unblocks:** build a `ConfigurationLookup`/`DetectionLookup`-shaped real provider (same pattern as `internal/rwevidence`'s own fake-to-real seam) against the Graph Security API, once tenant access exists.

### 2. SentinelOne adapter — explicitly deprioritized

**Status:** Open, deprioritized by the user's own earlier direction (not reopened without being asked).

**What's needed:** A second real vendor adapter alongside Defender, same shape as item #1.

**Why it's deferred:** User directive from earlier in this initiative explicitly deprioritized this relative to the Defender vertical. Not pursued further.

### 4. `AV-CONFIG-003` (security tampering) — permanently restricted from ordinary dispatch by design

**Status:** Open by design — this is a permanent scope boundary, not a gap to close. Enforcement of the boundary is now structural (resolved 2026-10-16, see Resolved items #10).

**What it is:** `internal/avcatalog/catalog_configweakness.go`'s `AV-CONFIG-003` vector attempts a real-time-protection-disable change. It must never enter a general-purpose dispatchable bundle, never run against this build host, and never run against any production endpoint.

**Resolution path:** only add this to any dispatchable set once there is a genuinely dedicated, disposable lab endpoint to run it against, with its execution gate (#10) deliberately set for that run — never this build host.

### 5. MSP industry profile — permanently unmapped by design

**Status:** Open by design, confirmed 2026-10-16 (see Resolved items #11) — not a gap to close, a permanent non-mapping. Government, previously grouped with MSP under this same item, is now partially mapped; see #11.

**What it is:** none of av.txt §3's 5 named MSP priorities (multi-tenant isolation, customer-specific policy drift, agent health across customer estates, inconsistent product configurations, evidence attribution to the correct tenant) describes a single-endpoint AV/NGAV technique — every one is a multi-tenant fleet/platform-management concern, the wrong axis for anything in `avcatalog`.

**Resolution path:** only closes if a future vector genuinely tests a multi-tenant/fleet-management property — none of avcatalog's 15 single-endpoint vectors ever will, by construction.

## Resolved items

### 10. `AV-CONFIG-003` eligibility, execution gate, and precondition-check — RESOLVED 2026-10-16

**What was wrong:** the vector's permanent restriction (item #4) was documentary only — enforced by `AV-CONFIG-003` simply not appearing in `avscenario`'s `dispatchableSeedVectorIDs`, with no structural guard against it being added there later, and its command unconditionally attempted the real-time-protection-disable change with no execution gate and no real precondition check.

**What changed:**
- `internal/avcatalog/eligibility.go` (new): `LabRestrictedVectorIDs()` is now the single, authoritative, structural registry of vectors that must never enter a general-purpose dispatchable bundle. `internal/avscenario`'s `TestDispatchableSeedVectorIDs_NeverIncludesALabRestrictedVector` cross-checks the two packages and fails the moment anyone adds a lab-restricted vector to `dispatchableSeedVectorIDs` — a vector's definition (it has a real, runnable command) is now structurally separated from its execution eligibility, not just separated by convention.
- `internal/avcatalog/catalog_configweakness.go`'s `AV-CONFIG-003` command now has two independent safety layers before it will ever touch `Set-MpPreference`: (1) an explicit `BAS_CONFIRM_AV_RTP_DISABLE_ATTEMPT` execution gate (mirroring `internal/rwevidence`'s existing `BAS_CONFIRM_VSS_DELETE` gate), and (2) a real `Get-MpComputerStatus` precondition check requiring both `IsTamperProtected` and `RealTimeProtectionEnabled` to already be true — i.e. it only ever attempts the change when a denial is the expected, safe outcome, never disabling protection merely to demonstrate that disabling protection creates a gap. Every SKIP path reports itself as `(restricted)` or `(untested)` in its own stdout text; a skipped `CheckResult` resolves `Inconclusive` through `internal/avefficacy`'s dispatch bridge, never a fabricated pass.
- A best-effort detection check (Defender operational-log EID 5013, the Tamper-Protection-blocked-change event per third-party Sigma rules and practitioner guides, not independently verified against Microsoft's own official Event ID reference) was added to the command, disclosed as best-effort in `Limitations`.

**Verified locally (this build host, read-only, gate never set, mutating call never executed):** confirmed the gate-not-set SKIP path fires correctly, and confirmed the real precondition check correctly reads `IsTamperProtected=False, RealTimeProtectionEnabled=False` on this machine — meaning even if the gate were set, this host's own real state would cause the script to SKIP rather than attempt the change. The mutating `Set-MpPreference` call was never run by Claude on this or any machine.

### 11. Government and MSP industry profiles — Government partially mapped with honest per-requirement gaps, MSP confirmed fully unmappable — RESOLVED 2026-10-16

**What was wrong:** item #5 (prior version) skipped both Government and MSP entirely as an all-or-nothing decision, with no per-requirement record of which of their named priorities might actually map to something real.

**What changed:**
- `internal/avprofile/objectives.go` (new): `ControlObjectiveCoverage` is a per-requirement mapping record (objective, the real vector that satisfies it if one exists, rationale, required evidence, and an explicit `Covered`/`Gap` status), validated at construction so a `Gap` can never carry a disguised vector mapping and a `Covered` entry can never omit one. `Profile` gained an optional `ControlObjectives` field (`WithControlObjectives`); `ValidateAgainstCatalog` now also validates it.
- `internal/avprofile/government.go` (new): `AVPROFILE-GOVERNMENT` (7th profile) maps 3 of av.txt §3's 6 named Government priorities to a real vector each — restricted/disconnected networks → `AV-CONFIG-002`, privileged workstations → `AV-CREDACCESS-001`, auditability → `AV-CONFIG-003` — and records the other 3 (legacy/unsupported endpoints, centralized policy enforcement, constrained update delivery) as explicit gaps, each naming the real reason: the closest existing capability for policy-enforcement/update-currency is `avval`'s evaluation-layer snapshot/drift comparison given caller-supplied evidence, not a Vector execution at all.
- `MSPControlObjectives()` records all 5 of av.txt §3's named MSP priorities as gaps, each with its own real reason (every one is a multi-tenant fleet/platform-management concern, the wrong axis for any single-endpoint `avcatalog` vector). No `AVPROFILE-MSP` is minted — enforced by `TestMSPControlObjectives_AllFiveAreGaps_NoMSPProfileMinted`.
- Fixed 3 stale hardcoded profile-count assertions found via grep: `internal/avprofile/catalog_test.go` (6→7, renamed to `...ReturnsSevenProfiles`, industry 4→5), `internal/reporting/av_industry_profiles_test.go` (6→7), plus the doc-comment counts in `internal/api/av_industry_profiles_handlers.go` and `internal/reporting/av_industry_profiles.go`.

### 8. `AV-BEHAV-001` (process injection) — RESOLVED 2026-10-16: real harness built, dispatch-correlation bridge built, verified locally; real lab-AV/NGAV validation remains separate open work

**Status:** Resolved for the harness and the avval/avefficacy correlation bridge. One new sub-item (below) remains open: validating this against a real, dedicated lab AV/NGAV endpoint.

**What was wrong:** `AV-BEHAV-001`'s `ExecutionTemplate` named a test-harness binary (`avtest-injector.exe`) that never existed, so it was excluded from `dispatchableSeedVectorIDs` and never dispatched by `AudspectAVAssessmentScenario()`.

**Decision on harness delivery (user-confirmed):** rather than building a genuinely new standalone `.exe` — which would require new agent-side binary-delivery, integrity-verification, and execution infrastructure that does not exist anywhere in this codebase — the harness reuses the exact, already-reviewed-and-shipped pattern in `scenarios/endpoint-mastery/em-03-memory-attacks.yaml`'s own "Cross-process memory WRITE (injection precursor)" step: inline PowerShell `Add-Type` compiles a small P/Invoke shim in memory (genuinely building a small, deterministic native-code-backed executable component, just JIT'd at dispatch time instead of shipped pre-built), which performs real `OpenProcess`+`VirtualAllocEx`+`WriteProcessMemory` calls against a disposable, self-spawned `notepad.exe` — no remote thread, no code execution. A standalone-binary delivery mechanism remains a separate, larger project, to be justified only if a future vector genuinely requires it.

**What changed (code):**
- `internal/avcatalog/catalog_behavioral.go`: `AV-BEHAV-001`'s `ExecutionTemplate` now has a real `Executor: "powershell"` command (the Add-Type injection probe) plus a second, independent, best-effort check of this endpoint's own local Windows Defender operational event log (EIDs 1116/1117) for a correlating detection event — real local telemetry, not the tenant-gated remote Graph API (see item #1), reported `UNAVAILABLE` rather than fabricated when the log can't be queried. A full harness-contract doc comment (invocation, prerequisites, exact behavior, observation/result mapping, timeout, cleanup) sits above the vector definition.
- `internal/avscenario/catalog.go`/`adapter.go`: `AV-BEHAV-001` added to `dispatchableSeedVectorIDs`; stale doc comments naming it as the harness-required example updated.
- `internal/avefficacy/dispatch.go` (new): `BuildCollectionResultsFromDispatch` — a real, non-fixture bridge turning one dispatched step's raw outcome (`pass`/`fail`/`skipped`/`error` + the harness's own `detection=DETECTED|NOT_OBSERVED|UNAVAILABLE` stdout token) into the exact `[]avval.CollectionResult` shape `VectorFixture.PreventionEvidence` already consumes — a drop-in replacement for a hand-authored fixture, reusable for any future AV vector dispatched this way, not special-cased to this one.
- Tests updated in `internal/avscenario/adapter_test.go` and `catalog_test.go` (previously asserted AV-BEHAV-001's exclusion; now assert its inclusion and real build success), plus 10 new tests in `internal/avefficacy/dispatch_test.go` covering every case the user's own directive named: Blocked→VerifiedProtection; **Allowed with no detection evidence→Inconclusive, never a fabricated ConfirmedGap** (the user's specific caveat: execution succeeding alone must never be equated with a detection failure); Allowed+detection genuinely searched-and-not-found→ConfirmedGap (an earned gap); Allowed+detection genuinely found→ConfirmedGap (enforcement gap, distinct reason text); detection source unavailable→`CoverageSourceUnavailable`, not a fabricated verified-negative; Skipped→Inconclusive via `CompletenessInsufficient`; Error→Go error, never a finding; **contradictory evidence** (two different control sources disagreeing)→Inconclusive via avval's real `AxisContradictory` path; **delayed evidence**→`LatencySLABreached`, exercised against the real `AV-BEHAV-001` vector and avefficacy's existing SLA-latency evaluator, not a synthetic stand-in.

**What was verified locally (2026-10-16, this build host, not a lab endpoint):** ran the exact harness script twice directly. Both runs: deterministic (`FAIL` — the injection primitive succeeded unblocked — both times, `detection=NOT_OBSERVED` both times, i.e. the local Defender log was genuinely queryable and genuinely found nothing), and cleanup was verified exact (0 stray hidden-notepad processes before and after, both runs). One real incident during verification, resolved as a false alarm rather than a bug: a lingering `notepad.exe` was found after the first run, initially looking like a cleanup failure — it turned out to be the user's own real, pre-existing, unsaved `*Untitled - Notepad` window, which the cleanup filter (`MainWindowTitle -eq ''`) correctly and deliberately left untouched, proving the filter discriminates real user windows from the harness's own disposable instance rather than killing anything named `notepad`.

**What this local run does NOT establish, and remains open:** this build host is an ordinary dev machine, not a dedicated, intentionally-configured lab endpoint with a real AV/NGAV product under test — per the user's own closing instruction, "then validate its efficacy against a real, appropriately configured lab endpoint" is separate work, not done here. The `FAIL`/`NOT_OBSERVED` result observed locally is one honest, real (if informal and uncontrolled) data point about this machine's own current state, not a statement about any AV/NGAV product's real-world efficacy, and it must never be reported as the latter.

### 9. Real lab-endpoint validation of `AV-BEHAV-001`'s harness — OPEN, new sub-item of item #1

**Status:** Open, same infrastructure gap as item #1 (no dedicated, intentionally-configured lab endpoint with a real AV/NGAV product available).

**What's needed:** dispatch `AV-BEHAV-001` (now real and dispatchable) against an actual enrolled lab endpoint running a real AV/NGAV product with behavioral/injection protection enabled, and confirm the resulting `PASS`/`FAIL` + Detection-axis evidence resolves through `internal/avefficacy`'s real pipeline to a finding that matches the product's actual, known configuration.

**Resolution path:** once a dedicated lab endpoint exists (same resolution path as item #1), register this vector's scenario for live dispatch (note: no avscenario-built scenario, for AV-BEHAV-001 or any of the other 10, is registered in the live `scenario.Engine` today — this is a pre-existing gap shared by the whole initiative, not unique to this vector, and was not in scope to fix here) and run it for real.

### 6. Ransomware-precursor scenario family (`av.txt` §2.F / §3) — RESOLVED 2026-10-16, via bridge not duplication

**Status:** Resolved.

**What was needed:** `av.txt` §8 step 5 requires a ransomware-precursor scenario family, explicitly instructing integration with the existing ransomware mastery rather than duplicating it.

**What was found:** the real ransomware-mastery evidence pipeline (`internal/rwevidence.EvaluateStep` → DB → `internal/rwscore`, wired via `internal/api/rwevidence_dispatch.go`'s `recordRWEvidence`) is already mature and real — not fixture-only like AV's own packages — gated on a fixed `ransomwareScenarioIDs` allowlist of 13 real, signed YAML scenarios, and already serves per-run findings at `GET /api/scenarios/runs/{runId}/rw-score`.

**What was built:** `GET /api/av/ransomware-precursor-coverage` (`internal/api/av_ransomware_bridge.go`, commit `75778e1a`) — a pure pointer, zero new evaluation logic. For each of rwevidence's 4 modeled techniques (T1490, T1486, T1567.002, T1560.001), it reports which real scenarios in `ransomwareScenarioIDs` actually declare a step for it, computed live from the engine's currently loaded scenarios (never a hardcoded list), plus the real `rw-score` endpoint format to follow up on. Verified against the real signed scenario corpus: T1486 correctly resolves to `ransomware-drill`'s production-safe `.bas_locked` rename-probe step among its `RealScenarioIDs`. A nil engine fails closed to all 4 techniques present with empty coverage, never a panic.

**Why no new avcatalog Vector or avefficacy scenario:** that would have been exactly the duplication `av.txt` forbids — the real pipeline already produces independently-verified evidence for these techniques.

### 7. Phase-2 catalog vectors had placeholder pseudo-commands — RESOLVED during Phase 4 (av.txt build)

**Status:** Resolved, found and fixed while building `internal/avscenario` (the dispatch adapter).

**What was wrong:** several seed vectors in `internal/avcatalog` originally had prose-in-angle-brackets placeholder commands or referenced a fictional `avtest-injector.exe`, harmless until a real dispatch adapter was built against them.

**What changed:** 9 of these were fixed with real, concretely-runnable PowerShell/cmd commands and real `CleanupCommand` values (e.g. `AV-FILE-002` reframed from "password-protected" to "nested archive" since `Compress-Archive` has no password support; `AV-NET-001` reframed from browser-UI automation to `Invoke-WebRequest`, narrowed to Windows only). The one genuine remaining exception, `AV-BEHAV-001`, is explicitly excluded rather than silently left broken — see item #3.

## Test/build summary (as of 2026-10-16)

- `go build ./...` and `go vet ./...`: clean throughout every phase of this initiative (scoped to the AV packages; the full repo build was noisy with an unrelated concurrent session's in-progress emailgw edits at the time of this update, not this initiative's concern).
- 134+ tests passing across `internal/avval`, `internal/avcatalog`, `internal/avefficacy`, `internal/avscenario`, `internal/avprofile`, plus green reporting/API-layer tests for every new endpoint (`/api/av/scenarios/*` × 9, `/api/av/industry-profiles`, `/api/av/ransomware-precursor-coverage`), plus the 10 new real-correlation-bridge tests from item #8.
- `TestRBACMatrix_NoDrift`: every new route in this initiative was added to both `routes.go` and `rbac_matrix_test.go` in the same commit. Remaining failures are pre-existing drift from the unrelated `emailgw-mastery` merge (`e783e7a2`) on `/api/emailgw-*`/`/api/webgw/industry-profiles*` routes — confirmed each time, never caused by this initiative, not fixed here (belongs to a different initiative).
- `TestRansomwareScenarioIDs_MatchesRealCorpus` and the new `TestGetAVRansomwarePrecursorCoverage_*` tests both load the real, signed `scenarios/` corpus via `scenario.NewEngine` with the default `integrity.CompiledVerifier` — not a fixture or a mock of the engine.
