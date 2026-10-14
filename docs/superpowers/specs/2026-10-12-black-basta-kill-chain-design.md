# Black Basta Kill Chain — Design

Sub-project #10's first family-content pass: a new, individually-vetted
ransomware family scenario, built on top of the metadata schema and
validation infrastructure that already shipped (`28a0d366..fb3dbba1`).
This pass is content authoring only — no engine changes, no new
`execclass.go` catalog entries (every technique below already has one), no
new registry/DB work. Per the locked decision from sub-project #10's own
brainstorming: "Each family pass should independently establish credible
family attribution, distinct techniques, step-level source citations,
safety classification, and regression-test results before the scenario is
signed and admitted through the existing TCF path."

## A. Scope

- New scenario file: `scenarios/black-basta-kill-chain.yaml`.
- `id: black-basta-kill-chain`, matching the existing naming convention
  (`akira-kill-chain`, `blackcat-kill-chain`, `clop-kill-chain`,
  `lockbit-kill-chain`, `play-kill-chain`, `ransomhub-kill-chain`).
- Windows only (`supported_os: [windows]`) — matches every existing family
  scenario's convention. Not revisited in this pass.
- 10-step linear kill chain (the engine has no branching/alternative-path
  concept anywhere — confirmed by reading `engine.go`/`builder.go`; every
  consumer iterates `Scenario.Steps` as a flat ordered list). The sequence
  below is a representative documented kill chain, not a claim that every
  real Black Basta incident follows this exact order, and not a definitive
  reconstruction of operational chronology — stated explicitly in the
  scenario's own `description:` field.
- T1190 (Exploit Public-Facing Application, ConnectWise CVE-2024-1709) is a
  real, CISA-documented alternative initial-access path. It is **not
  modeled** in this scenario — documented in the description as a known,
  unmodeled alternative, never represented as tested coverage. A future
  T1190 scenario is only worth building when there's a clearly-defined
  safe simulation contract and a meaningful control-validation objective,
  not merely to raise technique count.
- Registration across content-list touchpoints (now **7**, not 6 — sub-
  project #10's infrastructure pass added `internal/contentregistry`'s own
  copy of the ransomware-scenario-files list, on top of the 6 sub-project
  #9 already established: `internal/api/rwevidence_dispatch.go`'s
  `ransomwareScenarioIDs`, `internal/rwdetect/profiles.go`+
  `profiles_test.go`, `internal/rwevidence/realcorpus_test.go`,
  `internal/rwtaxonomy/mapping_corpus_test.go`,
  `internal/contentregistry/realcorpus_test.go`, and
  `web/src/features/ransomware.js`) is a plan-level task, not resolved
  here.

## B. Step sequence, sources, and confidence

Every technique-tagged step carries `threat_intel_sources`,
`last_reviewed`, and `family_attribution_confidence` per the schema
sub-project #10's infrastructure pass added. Confidence follows the
closed vocabulary exactly: `confirmed` only where a government advisory
or MITRE ATT&CK's own curated Software page directly attributes *this
specific behavior* to Black Basta; `reported` where only secondary
analyst reporting does, or where the primary sources disagree on the
exact technique mapping.

| # | Technique | Purpose | Confidence | Primary source(s) |
|---|---|---|---|---|
| 1 | T1566 | Phishing-inspired initial-access behavioral emulation | `confirmed` | CISA AA24-131A, Table 2: "Black Basta affiliates have used spearphishing emails to obtain initial access." |
| 2 | T1003.001 | Credential dumping simulation (LSASS handle access) | `reported` | Kroll, "Black Basta: Technical Analysis" (names Mimikatz among Black Basta's tools) — see review note below |
| 3 | T1562.001 | Defense impairment simulation | `confirmed` | CISA AA24-131A, Table 4: "Deployed a tool called Backstab to disable endpoint detection and response (EDR) tooling." |
| 4 | T1543.003 | Windows service persistence | `confirmed` | MITRE ATT&CK Software S1070: "Black Basta can create a new service to establish persistence." |
| 5 | T1021.002 | SMB/Windows Admin Shares lateral-movement simulation | `reported` | Elisity, "How to Stop Lateral Movement in Black Basta, Akira, and LockBit Ransomware Attacks" |
| 6 | T1083 | File and directory discovery | `confirmed` | MITRE ATT&CK Software S1070 (direct listing: "Black Basta can enumerate specific files for encryption"), corroborated by Qualys and Trend Micro's Ransomware Spotlight |
| 7 | T1567.002 | Exfiltration-over-web-service simulation | `reported` | Qualys, "What Is Black Basta Ransomware and How to Mitigate Attack"; Trend Micro, "Ransomware Spotlight: Black Basta" — see review note below |
| 8 | T1486 | Encryption-for-impact simulation | `confirmed` | CISA AA24-131A, Table 6: "Used a public key to fully encrypt files"; MITRE ATT&CK S1070: ChaCha20 cipher, multithreaded |
| 9 | T1490 | Recovery-inhibition enumeration | `confirmed` | CISA AA24-131A, Table 6: "Used the vssadmin.exe program to delete shadow copies." |
| 10 | T1490 | Destructive recovery-inhibition action, lab-gated | `confirmed` | Same as #9 — same technique, same evidence |

### Review notes (documented source disagreements — never silently resolved)

- **Step 2 (T1003.001):** CISA AA24-131A's own table categorizes Black
  Basta's Mimikatz reference under **T1068, Exploitation for Privilege
  Escalation** (Table 3), grouped with Zerologon/NoPac/PrintNightmare, not
  under T1003. The advisory does not independently establish T1003.001 as
  Black Basta's technique mapping — only MITRE's *general* tool-to-
  technique convention (Mimikatz's `sekurlsa` module is the canonical
  T1003.001 example tool, independent of any one advisory) supports the
  association. Kroll's analysis names Mimikatz among Black Basta's tools
  but — after attempting to verify directly — its exact wording on whether
  it describes LSASS-memory access specifically, versus only naming the
  tool, could not be confirmed (Kroll's page returned HTTP 403 to direct
  fetch; secondary summaries only confirm tool-naming, not mechanism).
  This step therefore emulates the **generic, publicly-documented LSASS-
  handle-access behavior Mimikatz's `sekurlsa` module performs** — not a
  claim that Black-Basta-specific reporting independently describes that
  exact mechanism. Confidence stays `reported`, not `confirmed`, on both
  grounds: the CISA/MITRE technique-ID disagreement, and the unverified
  specificity of the Black-Basta-specific source.
- **Step 7 (T1567.002):** at least one source in earlier general research
  mapped Black Basta's Rclone/WinSCP-based exfiltration to **T1048**
  (Exfiltration Over Alternative Protocol) rather than T1567.002
  (Exfiltration Over Web Service). Qualys and Trend Micro's Ransomware
  Spotlight both specifically use T1567.002; CISA's advisory describes the
  underlying behavior (data transfer via WinSCP to actor-controlled
  accounts) without itself using either sub-technique label. This scenario
  models T1567.002, consistent with the majority of named sources and with
  `rwevidence`'s own existing T1567.002 model, but the T1048 mapping
  disagreement is preserved here rather than treated as resolved.

`confirmed` requires either a definitive government advisory or MITRE's
own curated attribution for *that specific behavior* — never mere
agreement on a generic ATT&CK mapping, and never source count alone (two
citations are not automatically two independent sources; step 10 shares
step 9's identical source rather than being treated as independently
corroborated).

## C. Per-step safe-simulation contract

Every step reuses an existing, already-shipped safe-simulation pattern
from the real corpus — nothing here is a new simulation technique:

1. **T1566** — reuses `apt36-kill-chain.yaml`'s pattern exactly: copy
   `cmd.exe` to a temp `winword.exe`, spawn a hidden child `powershell.exe`
   process with a benign exit, delete the copy. No real document, no
   phishing email, no macro. `action_key` omitted (T1566.001 has exactly
   one catalog entry, `enumerate`).
2. **T1003.001** — reuses `em-04-credential-theft.yaml`'s pattern exactly:
   `OpenProcess(PROCESS_VM_READ)` against `lsass.exe`, immediate
   `CloseHandle`, zero memory read. **`action_key: handle_probe`** set
   explicitly — `T1003.001` has three catalog entries (`enumerate`,
   `handle_probe`, `minidump`); only `handle_probe` matches this safe,
   zero-extraction contract, so it must never be left to resolve by
   default.
3. **T1562.001** — Defender-tampering invocation probe, same shape as
   Akira's existing step. **`action_key: enumerate`** set explicitly (two
   entries exist for this technique; `enumerate` is the Windows-Defender-
   focused one, `stop_auditd` is Linux-only and must never be selected
   here).
4. **T1543.003** — benign BAS-owned service: `sc.exe create` + `start` +
   `stop` + `delete` of a uniquely-named, self-contained service.
   **`action_key: service_create_start_stop_delete`** set explicitly (the
   catalog's other entry, `enumerate`, is a read-only WMI query and would
   not match this step's actual create/delete behavior).
5. **T1021.002** — reuses Akira's SMB admin-share reachability check
   exactly: `net use ADMIN$` probe, immediately `/delete`'d, SMB1/signing
   registry reads. `action_key` omitted (one catalog entry).
6. **T1083** — BFSI-flavored file-discovery probe, same shape as Clop's
   Stage 1: read-only file-discovery scan plus synthetic decoy files
   created/enumerated/deleted in the BAS process's own TEMP directory.
   `action_key` omitted (one catalog entry).
7. **T1567.002** — reuses Clop's Stage 4 cloud-egress-reachability probe
   exactly: a benign TCP connectivity test (no upload, no data) against a
   set of well-known cloud-storage hostnames. Flavored with Mega's
   endpoint alongside the generic set, since Mega is Black Basta's
   specifically documented exfil destination (Qualys). `action_key`
   omitted (one catalog entry).
8. **T1486** — reuses the existing `ransomware_sim_sandboxed` contract
   exactly (synthetic decoy files in a BAS-owned TEMP subdirectory, toy
   XOR cipher, verified `Remove-Item -Recurse` cleanup). "ChaCha20-
   flavored" is narrative framing only (the step's narration may mention
   Black Basta's real cipher choice) — never a claim that real ChaCha20
   encryption, or any real cryptographic operation, runs against real
   data. **`action_key: ransomware_sim_sandboxed`** set explicitly (the
   catalog's `enumerate` entry is a capability check only, not the actual
   simulation).
9. **T1490 (enumeration)** — reuses the existing read-only
   `vssadmin list shadows` / backup-catalog enumeration pattern.
   **`action_key: enumerate`** set explicitly (four entries exist for
   T1490: `enumerate`, `backup_readiness_check`, `vss_delete`,
   `wbadmin_delete_catalog`, `bootloader_recovery_disable` — never leave
   this to a default with that many options).
10. **T1490 (destructive)** — reuses the existing lab-gated
    `vssadmin`-based shadow-copy deletion pattern exactly (default-
    disabled behind an explicit operator-confirmation environment
    variable, same risk profile as every other family scenario's
    equivalent step — never a synthetic stand-in). **`action_key:
    vss_delete`** set explicitly.

## D. Observed behavior vs. control efficacy (carried forward explicitly)

Two things this scenario's content must never conflate, per the user's own
standing rule:

- A `PASS`/`FAIL` outcome on the T1486 step is a statement about whether
  the *simulated* encryption behavior executed and was or wasn't blocked —
  it is never evidence that a customer's control would or wouldn't have
  stopped real encryption of real data.
- A `SKIP` on the T1490 destructive step caused by the safety gate not
  being confirmed (`BAS_CONFIRM_VSS_DELETE`-equivalent env var unset) must
  never be scored or reported as if a customer's control had prevented
  recovery inhibition. `rwevidence`'s existing `classifyRansomwareStep`
  (confirmed this session, sub-project #9) already distinguishes
  `gate_not_confirmed` from a genuine control-blocked outcome — this
  scenario's step text must use the exact same skip-text conventions
  (`"BAS_CONFIRM_VSS_DELETE not set"` style phrasing) so that existing
  classification continues to apply correctly, rather than silently
  falling through to a less specific skip reason.

## E. Testing strategy

- A YAML-parse smoke test (same pattern as sub-project #9's
  `linux_ransomware_drill_test.go`): `scenario.ParseYAML` succeeds,
  `SupportedOS == ["windows"]`, exactly 10 steps with the technique-ID
  sequence `T1566, T1003.001, T1562.001, T1543.003, T1021.002, T1083,
  T1567.002, T1486, T1490, T1490` in order, and every step with a
  `FamilyAttributionConfidence` set has a non-empty `ThreatIntelSources`
  (asserting `unsourced` is never used here, since every step has real
  grounding) — this is a scenario-specific test, not a change to
  `contentregistry`'s generic validation.
- Registration across all 7 touchpoints from section A, each verified by
  that touchpoint's own existing real-corpus test (the same fail-closed
  pattern sub-project #9 already established; a forgotten touchpoint shows
  up as exactly one failing test, which is the intended signal).
- `.sig` generation and `verify-all` — same signing mechanism every other
  scenario in the corpus uses.
- No new `execclass.go` entries, so no new catalog tests are needed —
  every `(technique_id, action_key)` pair this scenario uses already has
  test coverage via the catalog's own existing suite.

## F. Explicitly deferred (not this pass)

- T1190 (ConnectWise exploitation) as a separate scenario — only when a
  safe simulation contract and a real control-validation objective exist.
- Medusa, Rhysida, Hunters International — separate, individually-vetted
  later passes, per sub-project #10's locked decision.
- Any `rwevidence`/`execclass.go`/engine change. Every technique this
  scenario uses already has full support; none of this pass's work
  requires touching those packages.
- Branching/alternative-path support in the scenario engine — the engine
  stays a flat, linear `Steps []Step` list.
