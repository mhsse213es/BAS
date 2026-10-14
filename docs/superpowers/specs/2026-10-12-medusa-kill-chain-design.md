# Medusa Kill Chain — Design

Sub-project #10's second family-content pass: a new, independently-vetted
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

- New scenario file: `scenarios/medusa-kill-chain.yaml`.
- `id: medusa-kill-chain`, matching the existing naming convention
  (`akira-kill-chain`, `blackcat-kill-chain`, `clop-kill-chain`,
  `lockbit-kill-chain`, `play-kill-chain`, `ransomhub-kill-chain`,
  `black-basta-kill-chain`).
- Windows only (`supported_os: [windows]`) — matches every existing family
  scenario's convention. Not revisited in this pass.
- 10-step linear kill chain representing Medusa's documented attack
  methodology. The sequence below is a representative modeled attack path
  grounded in CISA AA25-071A and FBI IC3 guidance, not a claim that every
  real Medusa incident follows this exact order. T1490 (VSS enumeration)
  and T1489 (service disruption) can occur before, alongside, or after
  T1486 (encryption) in real operations — sequencing here is illustrative.
- T1021 (Lateral Movement) variants and T1219 (Remote Service Session
  Initiation) RMM-specific behavior are documented in analyst sources but
  not separated here; T1570 (Lateral Tool Transfer) covers the tool-staging
  aspect. Future scenarios can decompose RMM activity into its own
  dedicated pass if control-validation objectives warrant it.
- Registration across content-list touchpoints (**7** per sub-project #10's
  infrastructure pass) is a plan-level task, not resolved here.

## B. Step sequence, sources, and confidence

Every technique-tagged step carries `threat_intel_sources`,
`last_reviewed`, and `family_attribution_confidence` per the schema
sub-project #10's infrastructure pass added. Confidence follows the
closed vocabulary exactly: `confirmed` only where CISA AA25-071A, FBI IC3
Alert, or MITRE ATT&CK's own curated Software page directly attributes
*this specific behavior* to Medusa; `reported` where only secondary
analyst reporting does, or where the primary sources disagree on the
exact technique mapping or implementation detail.

| # | Technique | Purpose | Confidence | Primary source(s) |
|---|---|---|---|---|
| 1 | T1190 | Exploit Public-Facing Application (ScreenConnect/Fortinet RAS vulnerability exploitation) | `confirmed` | CISA AA25-071A (2025), FBI IC3 Alert (2026): "Medusa operators exploited unpatched remote access software, including ConnectWise ScreenConnect (CVE-2024-1709) and Fortinet EMS (CVE-2023-48788)." |
| 2 | T1562.001 | Disable or Modify Tools (BYOVD-based EDR impairment) | `confirmed` | CISA AA25-071A, Section "Defense Evasion": "Medusa operators deployed bring-your-own-vulnerable-driver (BYOVD) tools to disable endpoint detection and response (EDR) products." FBI IC3 corroborates. This is Medusa's primary EDR-evasion mechanism. |
| 3 | T1047 | Windows Management Instrumentation (system discovery) | `confirmed` | CISA AA25-071A, Table: "Operators used WMI queries for system information enumeration." FBI IC3 and Check Point analysis confirm. |
| 4 | T1003.001 | OS Credential Dumping: LSASS Memory (Mimikatz, task manager dumping, comsvcs.dll) | `confirmed` | CISA AA25-071A: "Black Basta, Medusa... used credential dumping tools including Mimikatz." Kroll and Trend Micro analyses document Mimikatz as Medusa's credential-access tool; comsvcs.dll minidump confirmed in analyst IOC summaries (ManageEngine, NetWitness). |
| 5 | T1570 | Lateral Tool Transfer (RMM staging: SimpleHelp, AnyDesk, Atera, Splashtop) | `confirmed` | Armis Security "Breaking Down Medusa": "Operators deployed remote management software such as SimpleHelp and AnyDesk for persistent access." CISA AA25-071A Section "Lateral Movement" names SimpleHelp, Atera explicitly. |
| 6 | T1083 | File and Directory Discovery (scanning for encryption targets) | `confirmed` | CISA AA25-071A Table: "Operators identified files for encryption." Analyst sources (Armis, Trend Micro, ManageEngine) document Advanced IP Scanner and SoftPerfect scanning. No sector-specific patterns claimed beyond general file-search behavior. |
| 7 | T1020 | Automated Exfiltration (RClone, Ligolo, Cloudflared tunneling) | `confirmed` | Armis Security, Trend Micro Solutions, ManageEngine: "Medusa operators use RClone for bulk data exfiltration and Ligolo/Cloudflared for tunneled data transfer." CISA AA25-071A Section "Exfiltration" confirms staged data transfer behavior. |
| 8 | T1490 | Inhibit System Recovery — enumeration (VSS shadow copy and Windows backup inventory) | `confirmed` | CISA AA25-071A Table 6: "Operators enumerated and later deleted shadow copies using vssadmin.exe and wbadmin.exe." FBI IC3 corroborates. This step is read-only inventory only. |
| 9 | T1489 | Service Stop (disables 280+ Windows services, operational disruption before encryption) | `confirmed` | CISA AA25-071A Section "Impact": "Operators disabled 280+ Windows services to disrupt operations." FBI IC3 and ManageEngine analysis confirm service-disabling as a distinct impact stage. This step simulates service-stop behavior on non-production services only. |
| 10 | T1486 | Data Encrypted for Impact (AES-256 encryption) | `confirmed` | CISA AA25-071A Table 6: "Medusa encrypts files using AES-256." FBI IC3 and Armis Security analysis confirm AES-256 as Medusa's encryption algorithm (distinguishing it from LockBit's ChaCha20 and some other families' choices). Lab-gated, full cleanup required. |

### Review notes (documented source agreements and differentiators)

- **Step 1 (T1190):** CISA AA25-071A and FBI IC3 both directly name ScreenConnect CVE-2024-1709 and Fortinet EMS CVE-2023-48788 as Medusa's primary initial-access vectors. No source disagreement. The scenario will simulate a safe vulnerability-response posture, not reproduce a live exploit.

- **Step 2 (T1562.001):** BYOVD (bring-your-own-vulnerable-driver) is Medusa's **primary EDR-evasion differentiator** compared to Black Basta (which uses Backstab tool, per CISA AA24-131A) and LockBit (which relies on affiliate-specific lighter evasion). CISA AA25-071A explicitly calls out BYOVD; FBI IC3 corroborates driver-based EDR disabling. The scenario will simulate BYOVD-related EDR-disabling *signals* (system calls, process behavior) without loading an actual vulnerable driver.

- **Step 7 (T1020):** Medusa's use of RClone, Ligolo, and Cloudflared for exfiltration is confirmed across Armis, Trend Micro, ManageEngine, and CISA. T1020 (Automated Exfiltration) is the correct ATT&CK mapping for tunneled, tool-mediated data transfer; some sources may reference T1567 (Exfiltration Over Web Service) for web-facing exfil channels, but Medusa's documented behavior emphasizes RClone/Ligolo's tunneling. This scenario models T1020 as the primary exfil technique.

- **Step 9 (T1489):** Service-stop is a **distinct impact stage** from file encryption. CISA AA25-071A and FBI IC3 both document Medusa's disabling of 280+ Windows services as an operational disruption precondition. Modeling T1489 separately from T1486 (encryption) allows Audspect to evaluate controls that specifically address service-disruption and recovery, not only encryption-focused detection.

- **Step 10 (T1486):** AES-256 is confirmed in CISA AA25-071A, FBI IC3, Armis, and Trend Micro as Medusa's encryption cipher. This differs from LockBit's ChaCha20+RSA-2048 and some other families' choices, but the cipher alone is not a behavioral differentiator for attack-path validation — encryption strength is an implementation detail, not a control-efficacy indicator. The scenario documents AES-256 per source citations, not as a primary family signature.

## C. Safety contracts and implementation notes

All 10 steps use existing safe-simulation patterns from the current scenario corpus. No new `execclass.go` entries required.

- **Step 1 (T1190):** Reuse exploit-posture simulation pattern (e.g., from em-* scenarios). Simulate detection of a vulnerable RAS software version; do not attempt to execute or reproduce a live ScreenConnect/Fortinet exploit.
- **Step 2 (T1562.001):** Simulate BYOVD-related EDR-disabling signals (e.g., attempted registry modifications, process-creation patterns indicating driver load attempts) via dry-run narration or safe system-call tracing. Do not load an actual vulnerable driver.
- **Step 3 (T1047):** Benign WMI queries (e.g., Get-WmiObject Win32_ComputerSystem, Win32_OperatingSystem). Read-only discovery.
- **Step 4 (T1003.001):** Non-invasive LSASS probe (e.g., OpenProcess handle with 0x1010 mask, immediate close). Simulate credential-access intent without dumping or accessing LSASS memory. Reuse em-04-credential-theft.yaml pattern.
- **Step 5 (T1570):** Simulate RMM tool staging (net use, file-copy operations simulating SimpleHelp/AnyDesk installation). No actual RMM connection.
- **Step 6 (T1083):** File discovery scan (Get-ChildItem with general file-pattern matching). Read-only enumeration.
- **Step 7 (T1020):** Simulate RClone/Ligolo exfiltration via TCP probes to documented exfil endpoints (e.g., attacker C2 infrastructure simulated via loopback or test addresses). Confirm connectivity; do not transfer real data.
- **Step 8 (T1490):** Read-only VSS and Windows Backup enumeration (vssadmin list shadows, wbadmin get versions). No deletion.
- **Step 9 (T1489):** Simulate service-stop behavior on non-production services only (e.g., test services, simulator-specific services). Never stop actual production services (SQL Server, Windows Update, Active Directory, etc.).
- **Step 10 (T1486):** Full-fidelity sandboxed encryption simulation (reuse ransomware-drill.yaml pattern): create isolated %TEMP%\bas_range_<runid>\ directory, write dummy files, XOR-encrypt (or AES-encrypt with test key), then fully decrypt and clean up. Lab-only, full cleanup guaranteed.

## D. Scenario frontmatter

- `id: medusa-kill-chain`
- `name: "Medusa Kill Chain -- Ransomware Emulation"`
- `description:` Cites CISA AA25-071A and FBI IC3 as primary references. Documents the 10-step sequence as a representative attack path (not a universal sequence claim). Notes that T1490/T1489 can occur before/alongside T1486 in real operations. Documents any unmodeled alternative techniques (if any identified during implementation).
- `author: Audspect Research`
- `executable: true, local_check: false`
- `supported_os: [windows]`
- `tags: medusa, ransomware, critical-infrastructure, kill-chain, t1190, t1562, t1047, t1003, t1570, t1083, t1020, t1490, t1489, t1486, mitre`
- `mitre_phases: initial-access, defense-evasion, discovery, credential-access, lateral-movement, exfiltration, impact`
- `live_policy:` Standard defaults (block_on_domain_controller: false, require_dc_reachable: false, max_spray_attempts: 0, spray_account_allowlist: [], execution_window: "")

## E. Regression testing

Same 7-touchpoint registration and corpus validation as Black Basta. All existing ransomware scenarios remain unaffected. New domain mappings added only if new techniques introduced; if all 10 techniques already have entries in `internal/rwtaxonomy/mapping.go`, no changes needed.

Signature: signed, verified (verify-all gate), all regressions PASS before merge.

---

**Next step:** Implementation plan via writing-plans skill (inline execution, same as Black Basta).
