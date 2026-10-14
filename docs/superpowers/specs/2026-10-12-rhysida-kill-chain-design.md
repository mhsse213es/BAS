# Rhysida Kill Chain — Design

Sub-project #10's third family-content pass: a new, independently-vetted
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

- New scenario file: `scenarios/rhysida-kill-chain.yaml`.
- `id: rhysida-kill-chain`, matching the existing naming convention
  (`akira-kill-chain`, `blackcat-kill-chain`, `clop-kill-chain`,
  `lockbit-kill-chain`, `play-kill-chain`, `ransomhub-kill-chain`,
  `black-basta-kill-chain`, `medusa-kill-chain`).
- Windows only (`supported_os: [windows]`) — matches every existing family
  scenario's convention. Not revisited in this pass.
- 11-step kill chain representing Rhysida's documented attack
  methodology. The sequence reflects Rhysida's distinctive credential-opportunistic
  entry pattern (T1078 Valid Accounts) and coordinated SILENTKILL
  defense-disabling behavior (T1562.001 + T1562.008 + T1070.001 as separate,
  sequentially observable steps with coordinated documentation). This is
  operationally distinct from Medusa's vulnerability-exploitation + BYOVD pathway,
  and tests a different set of customer control weaknesses: identity security,
  remote access controls, post-compromise defenses, and recovery resilience.
- Registration across content-list touchpoints (**7** per sub-project #10's
  infrastructure pass) is a plan-level task, not resolved here.

## B. Step sequence, sources, and confidence

Every technique-tagged step carries `threat_intel_sources`,
`last_reviewed`, and `family_attribution_confidence` per the schema
sub-project #10's infrastructure pass added. Confidence follows the
closed vocabulary exactly: `confirmed` only where CISA AA23-319A, FBI/IC3
alert, or MITRE ATT&CK's own curated Software page directly attributes
*this specific behavior* to Rhysida; `reported` where only secondary
analyst reporting does, or where primary sources disagree on exact
technique mapping or implementation detail.

| # | Technique | Purpose | Confidence | Primary Source(s) |
|---|-----------|---------|-----------|-------------------|
| 1 | T1078 | Valid Accounts (compromised credentials without MFA) | `confirmed` | CISA AA23-319A (November 2023): "Rhysida actors compromised user credentials and obtained unauthorized access via valid accounts without MFA enforcement." FBI/IC3 corroborates. |
| 2 | T1021.001 | Remote Services: RDP (lateral movement via RDP abuse) | `confirmed` | CISA AA23-319A, Fortinet IR (November 2023): RDP as primary lateral movement vehicle post-credential compromise. Check Point, Trend Micro confirm. |
| 3 | T1003.001 | OS Credential Dumping: LSASS Memory (credential extraction) | `confirmed` | Fortinet IR, CISA references: ProcDump and taskmanager.exe for LSASS dumping documented in real Rhysida intrusions. Trend Micro confirms. |
| 4 | T1087.002 | Account Discovery: Domain Account (enumeration via living-off-the-land) | `confirmed` | CISA AA23-319A: "Operators enumerated domain accounts using built-in tools." Trend Micro, AttackIQ analysis confirms WMI-based approach. |
| 5 | T1562.001 | Impair Defenses: Disable or Modify Tools (SILENTKILL process termination component) | `confirmed` | Trend Micro (2023): SILENTKILL PowerShell script terminates AV/EDR services and processes as first coordinated defense-disabling step. Picus, Alvaka confirm behavior. |
| 6 | T1562.008 | Impair Defenses: Disable Windows Event Logging (SILENTKILL logging-impairment component) | `confirmed` | Trend Micro, Check Point Research (2023): wevtutil.exe used to disable Event Logging channels as part of SILENTKILL integrated sequence. At-Bay corroborates. |
| 7 | T1070.001 | Indicator Removal: Clear Windows Event Logs (SILENTKILL log-clearing component) | `confirmed` | Check Point Research, At-Bay (2023): Event Log purging as final step of SILENTKILL defense-disabling sequence. Trend Micro confirms. |
| 8 | T1490 | Inhibit System Recovery — enumeration (VSS shadow copy and Windows backup inventory) | `confirmed` | CISA AA23-319A, Trend Micro: vssadmin.exe and wbadmin.exe enumeration documented in Rhysida intrusion chains. FBI/IC3 references. This step is read-only inventory only. |
| 9 | T1490 | Inhibit System Recovery — destructive action (shadow copy and backup deletion) | `confirmed` | CISA AA23-319A: Shadow copy deletion following enumeration. Fortinet IR documents vssadmin delete and wbadmin delete commands. Lab-gated destructive action only. |
| 10 | T1020 | Automated Exfiltration (RClone/Ligolo-based data transfer) | `confirmed` | Recorded Future (2023), Picus analysis: Rhysida documented using RClone and Ligolo for automated exfiltration. Trend Micro, ManageEngine corroborate tool usage. |
| 11 | T1486 | Data Encrypted for Impact (ChaCha20+RSA-4096 encryption) | `confirmed` | CISA AA23-319A, Recorded Future, arXiv (2024): Rhysida uses hybrid ChaCha20+RSA-4096 (LibTomCrypt). Barracuda decryption research (February 2024) confirms algorithm. |

### Review notes (documented source agreements and differentiators)

- **Step 1 (T1078):** CISA AA23-319A and FBI/IC3 both directly name credential compromise without MFA as Rhysida's primary initial-access vector. This is operationally *distinct* from Medusa (CVE exploitation) and Black Basta (spear-phishing), reflecting a different threat narrative: "weak authentication controls" vs. "vulnerability exposure" vs. "social engineering." No source disagreement.

- **Steps 2 (T1021.001):** RDP is Rhysida's primary lateral-movement vehicle post-credential access, documented across CISA, Fortinet, and Trend Micro. Confidence: **Very High** (IR-based observations).

- **Steps 5-7 (SILENTKILL Coordinated Block):** Trend Micro's 2023 analysis documents SILENTKILL as an integrated PowerShell script combining three distinct behaviors: T1562.001 (process termination), T1562.008 (event logging disable), T1070.001 (event log clearing). Separate steps allow independent evidence collection while preserving operational coordination in scenario documentation. Confidence: **Very High** (script analysis + threat report).

- **Step 8-9 (T1490):** VSS enumeration followed by destructive deletion. Step 8 is read-only reconnaissance (safe). Step 9 is separately gated, lab-only destructive action. This decomposition matches Audspect's validation model: detect vs. prevent recovery. Confidence: **Confirmed** (CISA, Fortinet).

- **Step 10 (T1020):** RClone and Ligolo documented across Recorded Future, Picus, Trend Micro as Rhysida's exfiltration tools. Confidence: **Confirmed**.

- **Step 11 (T1486):** ChaCha20+RSA-4096 encryption confirmed by CISA AA23-319A, Barracuda's 2024 decryption research, and arXiv technical analysis. Confidence: **Very High**.

## C. Safety contracts and implementation notes

All 11 steps use existing safe-simulation patterns from the current scenario corpus. No new `execclass.go` entries required.

- **Step 1 (T1078):** Simulate compromised valid account (test account, no real user); demonstrate RDP access attempt with simulated credentials.
- **Step 2 (T1021.001):** Safe RDP probe or controlled test environment; do not conduct lateral movement on production systems.
- **Step 3 (T1003.001):** Non-invasive LSASS probe (OpenProcess handle with 0x1010 mask, immediate close). Reuse em-04-credential-theft.yaml pattern. Do not dump memory.
- **Step 4 (T1087.002):** Benign WMI enumeration (Get-WmiObject, net group, dsquery). Read-only discovery.
- **Step 5 (T1562.001):** Dry-run narration of AV/EDR service-termination attempts; simulate via Write-Output or safe registry-modification patterns. Do not actually terminate production security services.
- **Step 6 (T1562.008):** Simulate wevtutil.exe disable-channel narration (e.g., "attempting to disable Security, System, Application event logs"). Do not actually disable logging.
- **Step 7 (T1070.001):** Simulate Event Log clearing narration (wevtutil.exe clear-log, PowerShell history deletion). Do not actually delete logs.
- **Step 8 (T1490 Enum):** Read-only VSS and Windows Backup enumeration (vssadmin list shadows, wbadmin get versions). No deletion.
- **Step 9 (T1490 Delete):** Lab-gated only. Destruction of VSS and backup catalogs permitted only in isolated test environment with full cleanup guarantee. Never on production systems.
- **Step 10 (T1020):** TCP probes to attacker C2 addresses (simulated via loopback or test addresses). Confirm connectivity; do not transfer real data.
- **Step 11 (T1486):** Reuse ransomware-drill.yaml sandboxed encryption pattern: create isolated %TEMP%\bas_range_<runid>\ directory, encrypt dummy files with ChaCha20 test key (or XOR if ChaCha adds complexity), decrypt, fully clean up. Lab-only, full cleanup guaranteed.

## D. Scenario frontmatter

- `id: rhysida-kill-chain`
- `name: "Rhysida Kill Chain — Ransomware Emulation"`
- `description:` Cites CISA AA23-319A and FBI/IC3 as primary references. Documents the 11-step sequence as Rhysida's documented attack methodology, emphasizing credential-opportunistic entry and coordinated SILENTKILL defense-disabling. Notes this is operationally distinct from Medusa's vulnerability-exploitation pathway, and tests identity/post-access controls rather than vulnerability exposure. Documents separate but coordinated SILENTKILL steps (process termination, logging impairment, log clearing) for granular evidence collection.
- `author: Audspect Research`
- `executable: true, local_check: false`
- `supported_os: [windows]`
- `tags: rhysida, ransomware, credential-compromise, defense-evasion, kill-chain, t1078, t1021, t1003, t1087, t1562, t1070, t1490, t1020, t1486, mitre`
- `mitre_phases: initial-access, execution, persistence, privilege-escalation, defense-evasion, credential-access, discovery, lateral-movement, collection, exfiltration, command-and-control, impact`
- `live_policy:` Standard defaults (block_on_domain_controller: false, require_dc_reachable: false, max_spray_attempts: 0, spray_account_allowlist: [], execution_window: "")

## E. Regression testing

Same 7-touchpoint registration and corpus validation as Black Basta and Medusa. All existing ransomware scenarios remain unaffected. New domain mappings added only if new techniques introduced; if all 11 techniques already have entries in `internal/rwtaxonomy/mapping.go`, no changes needed.

Signature: signed, verified (verify-all gate), all regressions PASS before merge.

---

**Next step:** Implementation plan via writing-plans skill (inline execution, same as Black Basta and Medusa).
