# Medusa Kill Chain Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Author and ship a 10-step Medusa ransomware kill-chain scenario, grounded in CISA AA25-071A and FBI IC3 threat intelligence, reusing existing safe-simulation patterns and registering across the 7-touchpoint corpus validation infrastructure.

**Architecture:** Single scenario file with 10 steps covering Medusa's documented kill chain (T1190 → T1562.001 → T1047 → T1003.001 → T1570 → T1083 → T1020 → T1490 → T1489 → T1486). All steps reuse verified safe-simulation patterns from existing scenarios (em-04, akira, blackcat, clop, ransomware-drill); no new execclass.go catalog entries. Registration across 7 existing touchpoints (internal/api, internal/rwdetect, internal/rwevidence, internal/rwtaxonomy, internal/contentregistry, web, api corpus test). Domain mappings verified; signing via existing pipeline.

**Tech Stack:** YAML scenario authoring, Go test harness, gofmt, cosign signing, git.

**Spec:** `docs/superpowers/specs/2026-10-12-medusa-kill-chain-design.md`

## Global Constraints

- **Scenario ID:** `medusa-kill-chain` (matching existing `*-kill-chain` naming)
- **Supported OS:** Windows only (`supported_os: [windows]`)
- **Steps:** Exactly 10, linear sequence (no branching)
- **Safety:** No real encryption (only sandboxed XOR/test-AES), no driver loading, no EDR disabling, no production-service stopping
- **Provenance:** Every technique-tagged step must have `threat_intel_sources`, `last_reviewed` (YYYY-MM-DD format), `family_attribution_confidence` (unsourced/inferred/reported/confirmed per spec Section B)
- **Sources:** CISA AA25-071A primary; FBI IC3 corroboration; analyst sources (Armis, Trend Micro, ManageEngine, Cyble, Check Point) documented per spec table
- **Execution:** Inline on main (no worktree), same model as Black Basta pass (3 commits: scenario+test, registration, signing)

## Review Focus

1. **T1489 (service stop) recognition in dispatch.go:** Step 9 simulates service-disruption (sc.exe stop on non-production services). Confirm dispatch.go's classifyRansomwareStep pattern-matches recognize the step's technique ID and skip-text correctly — do not assume new T1489 patterns are recognized without verification.

2. **Domain mapping completeness for 10 techniques:** Verify all 10 techniques (T1190, T1562.001, T1047, T1003.001, T1570, T1083, T1020, T1490, T1489, T1486) are present in orchestrator/internal/rwtaxonomy/mapping.go. If any are missing, add them with the same `Domain` enum value and confidence level as the step that uses them.

3. **Provenance field consistency:** Every step's `threat_intel_sources`, `last_reviewed`, and `family_attribution_confidence` must match spec Section B exactly — no paraphrasing or collapsing of source names. Copy verbatim from the spec table.

4. **Step patterns reused from existing scenarios:** Each step reuses a specific existing scenario's pattern (em-04 for T1003.001, akira for T1562.001, ransomware-drill for T1490/T1486, etc.). Regression tests must confirm no unintended interaction (existing scenario behavior unchanged).

5. **AES-256 vs. XOR encryption in Step 10:** Spec says "AES-encrypt with test key," but existing ransomware-drill.yaml uses XOR for simplicity. Plan's Step 10 implementation choice (AES-256 or preserve XOR, with cleanup contract unchanged) must be explicit and tested before commit.

---

## Task 1: Scenario YAML + Smoke Test

**Files:**
- Create: `scenarios/medusa-kill-chain.yaml` (10 steps, ~650 lines)
- Create: `orchestrator/internal/scenario/medusa_kill_chain_test.go` (smoke test)

**Interfaces:**
- Produces: Scenario object with `id: "medusa-kill-chain"`, 10 steps, all provenance fields populated, Windows-only

- [ ] **Step 1.1: Read Black Basta scenario structure for template**

Read `scenarios/black-basta-kill-chain.yaml` (first 50 lines to confirm frontmatter structure) and `orchestrator/internal/scenario/black_basta_kill_chain_test.go` (full smoke test pattern).

Expected: Frontmatter includes `id`, `name`, `description`, `author`, `executable`, `supported_os`, `tags`, `mitre_phases`, `live_policy`, `detection_profiles`, `steps`.

- [ ] **Step 1.2: Read source patterns for each of the 10 steps**

For each step's technique, read the example from an existing scenario:
- T1190: Read `scenarios/em-*/` (endpoint-mastery scenario) for posture-check pattern
- T1562.001: Read `scenarios/akira-kill-chain.yaml` Step 4 (EDR tampering via dry-run narration)
- T1047: Read any scenario's discovery phase (e.g., `scenarios/blackcat-kill-chain.yaml` Stage 2)
- T1003.001: Read `scenarios/endpoint-mastery/em-04-credential-theft.yaml` (LSASS handle probe pattern)
- T1570: Read `scenarios/akira-kill-chain.yaml` Stage 5 (lateral movement tool staging)
- T1083: Read `scenarios/clop-kill-chain.yaml` Stage 1 (file discovery with Get-ChildItem)
- T1020: Read `scenarios/clop-kill-chain.yaml` Stage 4 (cloud egress via TCP probes)
- T1490 enum: Read `scenarios/ransomware-drill.yaml` "VSS + Backup Catalog Enumeration" step
- T1489: Read `scenarios/blackcat-kill-chain.yaml` Stage 5 (sc.exe service manipulation, adapted to stop-only)
- T1486: Read `scenarios/ransomware-drill.yaml` "XOR Encryption Simulation" step (full cleanup contract)

Expected: Each pattern exists and is reusable verbatim or with minimal adaptation.

- [ ] **Step 1.3: Create medusa-kill-chain.yaml**

Write the full scenario YAML with:
- Frontmatter: `id: medusa-kill-chain`, `name: "Medusa Kill Chain -- Ransomware Emulation"`, description citing CISA AA25-071A and FBI IC3, sequencing caveat about T1490/T1489 order variation
- Author: `Audspect Research`
- `executable: true, local_check: false, supported_os: [windows]`
- Tags: `medusa, ransomware, critical-infrastructure, kill-chain, t1190, t1562, t1047, t1003, t1570, t1083, t1020, t1490, t1489, t1486, mitre`
- MITRE phases: `initial-access, defense-evasion, discovery, credential-access, lateral-movement, exfiltration, impact`
- Live policy: `block_on_domain_controller: false, require_dc_reachable: false, max_spray_attempts: 0, spray_account_allowlist: [], execution_window: ""`
- 10 steps with exact content from source patterns

**Step 1 (T1190):**
```yaml
- name: "ScreenConnect Exploit Vulnerability Posture Check"
  technique_id: T1190
  description: "Simulate detection of outdated ConnectWise ScreenConnect version vulnerable to CVE-2024-1709."
  action_key: ~  # Omitted; T1190 has exactly one execclass entry
  threat_intel_sources:
    - reference: "CISA AA25-071A: Initial Access"
      url: "https://www.cisa.gov/news-events/cybersecurity-advisories/aa25-071a"
  family_attribution_confidence: "confirmed"
  last_reviewed: "2026-10-12"
  details: |
    EXEC: check [ScreenConnect version]; report [outdated version matched to CVE-2024-1709]
    Narration: "ScreenConnect version 23.x detected (vulnerable to CVE-2024-1709)"
  detection_profiles: []
```

**Step 2 (T1562.001):**
```yaml
- name: "BYOVD-Based EDR Impairment Simulation"
  technique_id: T1562.001
  description: "Simulate BYOVD (bring-your-own-vulnerable-driver) EDR disabling signals without loading actual driver."
  action_key: "enumerate"
  threat_intel_sources:
    - reference: "CISA AA25-071A: Defense Evasion"
      url: "https://www.cisa.gov/news-events/cybersecurity-advisories/aa25-071a"
    - reference: "FBI IC3 Alert 2026"
      url: "https://www.ic3.gov/CSA/2026/"
  family_attribution_confidence: "confirmed"
  last_reviewed: "2026-10-12"
  details: |
    EXEC: Write-Output "BYOVD driver load attempt detected"; registry modification narration
    Narration: "Attempted registry modifications consistent with BYOVD driver loading"
  detection_profiles: ["windows_defender_tampering"]
```

**Step 3 (T1047):**
```yaml
- name: "WMI System Discovery"
  technique_id: T1047
  description: "Benign WMI queries for system information enumeration."
  action_key: ~
  threat_intel_sources:
    - reference: "CISA AA25-071A: Discovery"
      url: "https://www.cisa.gov/news-events/cybersecurity-advisories/aa25-071a"
  family_attribution_confidence: "confirmed"
  last_reviewed: "2026-10-12"
  details: |
    EXEC: Get-WmiObject Win32_ComputerSystem; Get-WmiObject Win32_OperatingSystem
    PASS: queries executed successfully
  detection_profiles: []
```

**Step 4 (T1003.001):**
```yaml
- name: "LSASS Handle Access Probe"
  technique_id: T1003.001
  description: "Non-invasive LSASS handle probe via P/Invoke OpenProcess/CloseHandle."
  action_key: "handle_probe"
  threat_intel_sources:
    - reference: "CISA AA25-071A: Credential Access (Mimikatz)"
      url: "https://www.cisa.gov/news-events/cybersecurity-advisories/aa25-071a"
    - reference: "Kroll: Black Basta Technical Analysis"
      url: "https://kroll.com"
  family_attribution_confidence: "confirmed"
  last_reviewed: "2026-10-12"
  details: |
    [Reuse exact em-04-credential-theft.yaml pattern: P/Invoke block with OpenProcess(0x1010), CloseHandle]
    FAIL if access succeeded; PASS with error code if denied
  detection_profiles: ["windows_defender_tampering"]
```

**Step 5 (T1570):**
```yaml
- name: "RMM Tool Staging (SimpleHelp/AnyDesk)"
  technique_id: T1570
  description: "Simulate RMM tool staging via net use and file-copy operations."
  action_key: ~
  threat_intel_sources:
    - reference: "CISA AA25-071A: Lateral Movement"
      url: "https://www.cisa.gov/news-events/cybersecurity-advisories/aa25-071a"
    - reference: "Armis Security: Breaking Down Medusa"
      url: "https://www.armis.com/blog/breaking-down-medusa-ransomware/"
  family_attribution_confidence: "confirmed"
  last_reviewed: "2026-10-12"
  details: |
    EXEC: net use \\127.0.0.1\ADMIN$; simulated tool staging via Copy-Item
    PASS: staging attempt narration
  detection_profiles: ["windows_smb_lateral_probe"]
```

**Step 6 (T1083):**
```yaml
- name: "File and Directory Discovery"
  technique_id: T1083
  description: "Scan for files matching general business-process patterns."
  action_key: ~
  threat_intel_sources:
    - reference: "CISA AA25-071A: Discovery"
      url: "https://www.cisa.gov/news-events/cybersecurity-advisories/aa25-071a"
    - reference: "Trend Micro: Ransomware Spotlight: Medusa"
      url: "https://success.trendmicro.com"
  family_attribution_confidence: "confirmed"
  last_reviewed: "2026-10-12"
  details: |
    [Reuse clop-kill-chain.yaml file-discovery pattern]
    EXEC: Get-ChildItem -Depth 2 -Path Desktop, MyDocuments, Downloads
    Count matches; report EXEC narration only (no FAIL/PASS gate)
  detection_profiles: ["windows_file_discovery"]
```

**Step 7 (T1020):**
```yaml
- name: "Automated Exfiltration via RClone/Ligolo"
  technique_id: T1020
  description: "Simulate exfiltration endpoint connectivity via TCP probes."
  action_key: ~
  threat_intel_sources:
    - reference: "Armis Security: Breaking Down Medusa"
      url: "https://www.armis.com/blog/"
    - reference: "Trend Micro: Ransomware Spotlight: Medusa"
      url: "https://success.trendmicro.com"
    - reference: "ManageEngine: Medusa Ransomware IOCs & Detection"
      url: "https://www.manageengine.com/"
  family_attribution_confidence: "confirmed"
  last_reviewed: "2026-10-12"
  details: |
    [Reuse clop-kill-chain.yaml cloud-egress pattern]
    EXEC: TCP probes to attacker C2 addresses (simulated via loopback/test addresses)
    FAIL if endpoint reachable; PASS if blocked
  detection_profiles: ["windows_cloud_egress"]
```

**Step 8 (T1490):**
```yaml
- name: "VSS and Backup Catalog Enumeration"
  technique_id: T1490
  description: "Read-only enumeration of VSS shadow copies and Windows backups."
  action_key: "enumerate"
  threat_intel_sources:
    - reference: "CISA AA25-071A: Impact"
      url: "https://www.cisa.gov/news-events/cybersecurity-advisories/aa25-071a"
    - reference: "FBI IC3 Alert 2026"
      url: "https://www.ic3.gov/CSA/2026/"
  family_attribution_confidence: "confirmed"
  last_reviewed: "2026-10-12"
  details: |
    [Reuse ransomware-drill.yaml VSS enumeration pattern exactly]
    EXEC: vssadmin list shadows; wbadmin get versions
    Count occurrences; report EXEC narration only
  detection_profiles: ["windows_vss_inhibition"]
```

**Step 9 (T1489):**
```yaml
- name: "Non-Production Service Stop Simulation"
  technique_id: T1489
  description: "Simulate service-disruption behavior on safe test services only."
  action_key: "service_stop"
  threat_intel_sources:
    - reference: "CISA AA25-071A: Impact"
      url: "https://www.cisa.gov/news-events/cybersecurity-advisories/aa25-071a"
    - reference: "FBI IC3 Alert 2026"
      url: "https://www.ic3.gov/CSA/2026/"
    - reference: "ManageEngine: Medusa Threat Analysis"
      url: "https://www.manageengine.com/"
  family_attribution_confidence: "confirmed"
  last_reviewed: "2026-10-12"
  details: |
    [Adapt blackcat-kill-chain.yaml service-manipulation pattern to stop-only]
    EXEC: sc.exe query [safe-test-service]; sc.exe stop [safe-test-service]
    PASS: service stop attempt narration; never stop production services
  detection_profiles: ["windows_malicious_service"]
  requires_priv: "admin"
```

**Step 10 (T1486):**
```yaml
- name: "AES-256 Encryption Simulation (Lab, Full Cleanup)"
  technique_id: T1486
  description: "Sandboxed encryption simulation with guaranteed cleanup."
  action_key: "ransomware_sim_sandboxed"
  threat_intel_sources:
    - reference: "CISA AA25-071A: Impact"
      url: "https://www.cisa.gov/news-events/cybersecurity-advisories/aa25-071a"
    - reference: "FBI IC3 Alert 2026"
      url: "https://www.ic3.gov/CSA/2026/"
    - reference: "Armis Security: Breaking Down Medusa"
      url: "https://www.armis.com/blog/"
  family_attribution_confidence: "confirmed"
  last_reviewed: "2026-10-12"
  details: |
    [Reuse ransomware-drill.yaml XOR encryption pattern, OR adapt to AES-256 test-key]
    Create %TEMP%\bas_range_<runid>\; write dummy files; encrypt; decrypt; cleanup
    CLEANUP narration; full directory removal verified via Test-Path
  detection_profiles: ["windows_ransomware_encryption"]
  fidelity: "lab-only"
  production_safe: false
  risk: "high"
  reversible: false
```

- [ ] **Step 1.4: Create smoke-test Go file**

Create `orchestrator/internal/scenario/medusa_kill_chain_test.go`:

```go
package scenario

import (
	"testing"
)

func TestMedusaKillChain_ParsesWithTenStepsWindowsOnlyFullyGrounded(t *testing.T) {
	b, err := readScenarioFile("../../../scenarios/medusa-kill-chain.yaml")
	if err != nil {
		t.Fatalf("read scenario: %v", err)
	}

	sc, err := ParseYAML(b)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	// Verify 10 steps
	if len(sc.Steps) != 10 {
		t.Errorf("got %d steps, want 10", len(sc.Steps))
	}

	// Verify Windows-only
	if len(sc.SupportedOS) != 1 || sc.SupportedOS[0] != "windows" {
		t.Errorf("supported_os = %v, want [windows]", sc.SupportedOS)
	}

	// Verify all steps have technique_id and provenance fields
	for i, step := range sc.Steps {
		if step.TechniqueID == "" {
			t.Errorf("Step %d: technique_id missing", i+1)
		}
		if step.LastReviewed == "" {
			t.Errorf("Step %d (%s): last_reviewed missing", i+1, step.TechniqueID)
		}
		if step.FamilyAttributionConfidence == "" {
			t.Errorf("Step %d (%s): family_attribution_confidence missing", i+1, step.TechniqueID)
		}
		if len(step.ThreatIntelSources) == 0 {
			t.Errorf("Step %d (%s): threat_intel_sources empty", i+1, step.TechniqueID)
		}
	}

	// Verify action_key values where required
	step4 := sc.Steps[3] // T1003.001
	if step4.ActionKey != "handle_probe" {
		t.Errorf("Step 4 (T1003.001): action_key = %q, want handle_probe", step4.ActionKey)
	}
	step2 := sc.Steps[1] // T1562.001
	if step2.ActionKey != "enumerate" {
		t.Errorf("Step 2 (T1562.001): action_key = %q, want enumerate", step2.ActionKey)
	}
	step8 := sc.Steps[7] // T1490 enum
	if step8.ActionKey != "enumerate" {
		t.Errorf("Step 8 (T1490): action_key = %q, want enumerate", step8.ActionKey)
	}
	step9 := sc.Steps[8] // T1489
	if step9.ActionKey != "service_stop" {
		t.Errorf("Step 9 (T1489): action_key = %q, want service_stop", step9.ActionKey)
	}
	step10 := sc.Steps[9] // T1486
	if step10.ActionKey != "ransomware_sim_sandboxed" {
		t.Errorf("Step 10 (T1486): action_key = %q, want ransomware_sim_sandboxed", step10.ActionKey)
	}
}
```

- [ ] **Step 1.5: Run smoke test**

Run: `cd orchestrator && go test ./internal/scenario -v -run TestMedusaKillChain`

Expected: `PASS: TestMedusaKillChain_ParsesWithTenStepsWindowsOnlyFullyGrounded — 10 steps parsed, Windows-only, all action_keys correct, all provenance fields present`

- [ ] **Step 1.6: Commit Task 1**

```bash
cd /c/Users/Administrator/Downloads/Audspect_Cloud
git add scenarios/medusa-kill-chain.yaml orchestrator/internal/scenario/medusa_kill_chain_test.go
git commit -m "feat(scenarios): Medusa kill chain -- 10-stage CISA AA25-071A-grounded ransomware emulation

- 10-step kill chain from T1190 (ScreenConnect exploit) through T1486 (AES-256 encryption)
- All steps reuse existing safe-simulation patterns (em-04, akira, blackcat, clop, ransomware-drill)
- BYOVD-based EDR impairment (Step 2) as distinctive mechanism vs. Black Basta/LockBit
- T1489 (service stop) as separate impact stage from encryption (Step 9 vs. Step 10)
- All provenance fields (threat_intel_sources, last_reviewed, family_attribution_confidence) satisfied per spec Section B
- Grounded in CISA AA25-071A (2025/2026 updates) and FBI IC3 Alert; corroborated by Armis, Trend Micro, ManageEngine, Cyble

Co-Authored-By: Claude Haiku 4.5 <noreply@anthropic.com>"
```

---

## Task 2: Registration Across 7 Touchpoints

**Files:**
- Modify: `orchestrator/internal/api/rwevidence_dispatch.go` (ransomwareScenarioIDs map)
- Modify: `orchestrator/internal/rwdetect/profiles_test.go` (ransomwareScenarioFiles list)
- Modify: `orchestrator/internal/rwevidence/realcorpus_test.go` (ransomwareScenarioFiles list)
- Modify: `orchestrator/internal/rwtaxonomy/mapping_corpus_test.go` (ransomwareScenarioFiles list)
- Modify: `orchestrator/internal/contentregistry/realcorpus_test.go` (ransomwareScenarioFiles list)
- Modify: `orchestrator/internal/api/rwevidence_dispatch_corpus_test.go` (ransomwareScenarioIDs corpus test)
- Modify: `orchestrator/web/src/features/ransomware.js` (RR_SCENARIO_IDS array)
- Check: `orchestrator/internal/rwtaxonomy/mapping.go` (domain mappings for all 10 techniques)

**Interfaces:**
- Consumes: Scenario ID `medusa-kill-chain`, 10 techniques (T1190, T1562.001, T1047, T1003.001, T1570, T1083, T1020, T1490, T1489, T1486)
- Produces: Registered scenario in all 7 touchpoints; domain mappings verified

- [ ] **Step 2.1: Register in rwevidence_dispatch.go**

Read `orchestrator/internal/api/rwevidence_dispatch.go` to find the `ransomwareScenarioIDs` map. Add entry:

```go
"medusa-kill-chain": true,
```

Expected: Map includes akira, blackcat, clop, lockbit, play, ransomhub, em-07, linux-ransomware-drill, black-basta, medusa.

- [ ] **Step 2.2: Register in profiles_test.go**

Read `orchestrator/internal/rwdetect/profiles_test.go` to find the `ransomwareScenarioFiles` slice. Add entry to the list:

```go
"medusa-kill-chain.yaml",
```

Expected: List is ordered alphabetically or by insertion; entry appears alongside black-basta, linux-ransomware-drill, etc.

- [ ] **Step 2.3: Register in rwevidence/realcorpus_test.go**

Read `orchestrator/internal/rwevidence/realcorpus_test.go` to find the `ransomwareScenarioFiles` slice. Add entry:

```go
"medusa-kill-chain.yaml",
```

- [ ] **Step 2.4: Register in rwtaxonomy/mapping_corpus_test.go**

Read `orchestrator/internal/rwtaxonomy/mapping_corpus_test.go` to find the `ransomwareScenarioFiles` slice. Add entry:

```go
"medusa-kill-chain.yaml",
```

- [ ] **Step 2.5: Register in contentregistry/realcorpus_test.go**

Read `orchestrator/internal/contentregistry/realcorpus_test.go` to find the `ransomwareScenarioFiles` slice. Add entry:

```go
"medusa-kill-chain.yaml",
```

- [ ] **Step 2.6: Update rwevidence_dispatch_corpus_test.go**

Read `orchestrator/internal/api/rwevidence_dispatch_corpus_test.go` and find the `TestRansomwareScenarioIDs_MatchesRealCorpus` test. It has a hardcoded `files` list. Add entry:

```go
"medusa-kill-chain.yaml",
```

Expected: The test's `files` list now includes all 10 ransomware scenarios (9 existing + 1 new).

- [ ] **Step 2.7: Verify domain mappings in mapping.go**

Read `orchestrator/internal/rwtaxonomy/mapping.go` and check for all 10 techniques:

- T1190: Exploit Public-Facing Application
- T1562.001: Disable or Modify Tools
- T1047: Windows Management Instrumentation
- T1003.001: OS Credential Dumping: LSASS Memory
- T1570: Lateral Tool Transfer
- T1083: File and Directory Discovery
- T1020: Automated Exfiltration
- T1490: Inhibit System Recovery
- T1489: Service Stop
- T1486: Data Encrypted for Impact

If all 10 are already present in the `TechniqueDomain` map, no changes needed. If any are missing (unlikely), add them with the same `Domain` enum value and confidence from the spec.

Expected: All 10 techniques map to appropriate domains (Initial Access, Defense Evasion, Discovery, Credential Access, Lateral Movement, Exfiltration, Impact, Post-Incident Assurance per spec Section B).

- [ ] **Step 2.8: Register in ransomware.js**

Read `orchestrator/web/src/features/ransomware.js` and find the `RR_SCENARIO_IDS` array. Add entry:

```javascript
'medusa-kill-chain'
```

Expected: Array includes all 10 ransomware scenario IDs in order.

- [ ] **Step 2.9: Run per-touchpoint regression tests**

Run the test suites for each modified package:

```bash
cd orchestrator

# Taxonomy tests
go test ./internal/rwtaxonomy -v -run TestTechniqueDomain_MatchesRealCorpus

# Detection profile tests
go test ./internal/rwdetect -v -run TestRansomwareRelevantProfiles_MatchesRealCorpus

# Rwevidence corpus tests
go test ./internal/rwevidence -v -run TestRealCorpus_EveryTechniqueTaggedStepIsAccountedFor

# Contentregistry tests
go test ./internal/contentregistry -v -run TestRealRansomwareCorpus_StillParsesAndStructurallyPasses

# API corpus test
go test ./internal/api -p 1 -timeout 20m -v -run TestRansomwareScenarioIDs_MatchesRealCorpus
```

Expected: All tests PASS. No regressions on existing 9 scenarios.

- [ ] **Step 2.10: Commit Task 2**

```bash
git add orchestrator/internal/api/rwevidence_dispatch.go \
        orchestrator/internal/rwdetect/profiles_test.go \
        orchestrator/internal/rwevidence/realcorpus_test.go \
        orchestrator/internal/rwtaxonomy/mapping_corpus_test.go \
        orchestrator/internal/contentregistry/realcorpus_test.go \
        orchestrator/internal/api/rwevidence_dispatch_corpus_test.go \
        orchestrator/web/src/features/ransomware.js

git commit -m "feat(rwevidence): register medusa-kill-chain across all 7 scenario-list touchpoints

- Added 'medusa-kill-chain' to ransomwareScenarioIDs map (internal/api)
- Updated corpus-matching tests in rwdetect, rwevidence, rwtaxonomy, contentregistry
- Verified all 10 techniques present in rwtaxonomy/mapping.go (no new domain mappings needed)
- Registered in web/ransomware.js RR_SCENARIO_IDS array
- All per-touchpoint regressions PASS: TestTechniqueDomain_MatchesRealCorpus, TestRansomwareRelevantProfiles_MatchesRealCorpus, TestRealCorpus_EveryTechniqueTaggedStepIsAccountedFor, TestRealRansomwareCorpus_StillParsesAndStructurallyPasses, TestRansomwareScenarioIDs_MatchesRealCorpus

Co-Authored-By: Claude Haiku 4.5 <noreply@anthropic.com>"
```

---

## Task 3: Scenario Signing

**Files:**
- Create: `scenarios/medusa-kill-chain.yaml.sig`

**Interfaces:**
- Consumes: Scenario file `scenarios/medusa-kill-chain.yaml`
- Produces: Signature file `scenarios/medusa-kill-chain.yaml.sig`

- [ ] **Step 3.1: Sign the scenario**

Run the signer:

```bash
cd /c/Users/Administrator/Downloads/Audspect_Cloud/orchestrator
go run scripts/signer.go sign private_key.pem ../scenarios/medusa-kill-chain.yaml
```

Expected: Creates `scenarios/medusa-kill-chain.yaml.sig` with RSA-4096 signature.

- [ ] **Step 3.2: Verify all signatures**

Run:

```bash
cd orchestrator
go run scripts/signer.go verify-all ../scenarios
```

Expected: Output shows `ok=120 fail=0` (119 pre-existing scenarios + 1 new Medusa).

- [ ] **Step 3.3: Commit Task 3**

```bash
git add scenarios/medusa-kill-chain.yaml.sig

git commit -m "chore(scenarios): sign medusa-kill-chain.yaml

- RSA-4096 signature via scripts/signer.go
- verify-all: ok=120 fail=0 (all scenarios including new Medusa pass)

Co-Authored-By: Claude Haiku 4.5 <noreply@anthropic.com>"
```

---

## Task 4: Final Regression Verification

**Files:**
- No file changes; run existing test suites

**Interfaces:**
- Consumes: All changes from Tasks 1-3
- Produces: Green test suite confirmation

- [ ] **Step 4.1: Verify dispatch.go recognizes Step 8 and Step 9**

Read `orchestrator/internal/rwevidence/dispatch.go` and find the `classifyRansomwareStep` function. Search for patterns that handle:
- T1490 VSS enumeration step names and skip-text (Step 8)
- T1489 service-stop step names and skip-text (Step 9)

Expected: Both T1490 and T1489 have switch cases or pattern matches for step-name and skip-text recognition. If Step 9's `service_stop` action_key is new, verify dispatch.go has a case for it (or note it as a Task 4 finding).

**Critical:** If dispatch.go does NOT recognize Step 9's patterns, this is a blocking issue. Flag immediately and add dispatch.go changes to Task 4 before proceeding.

- [ ] **Step 4.2: Run pure-Go regression suite (scenario, rwdetect, rwevidence, rwtaxonomy)**

Run:

```bash
cd orchestrator
go test ./internal/scenario ./internal/rwdetect ./internal/rwevidence ./internal/rwtaxonomy -v
```

Expected: All tests PASS. No timeouts. 100+ tests green.

- [ ] **Step 4.3: Run contentregistry with testcontainer**

Run:

```bash
cd orchestrator
go test ./internal/contentregistry -v -timeout 2m
```

Expected: Testcontainer starts, all structural checks PASS, ~50-60s completion.

- [ ] **Step 4.4: Run API integration suite**

Run (sequential, to avoid testcontainer concurrency issues):

```bash
cd orchestrator
go test ./internal/api -p 1 -timeout 20m -v
```

Expected: ~1200/1200 tests PASS. No timeouts. No connection errors.

If tests fail, investigate:
- Are testcontainers running?
- Is Docker Desktop running?
- Are ports 5432 (Postgres) available?
- Check prior feedback: Docker Desktop must be manually started.

- [ ] **Step 4.5: Check gofmt on all modified files**

Run:

```bash
cd orchestrator
gofmt -l scenarios/medusa-kill-chain.yaml \
      internal/scenario/medusa_kill_chain_test.go \
      internal/api/rwevidence_dispatch.go \
      internal/rwdetect/profiles_test.go \
      internal/rwevidence/realcorpus_test.go \
      internal/rwtaxonomy/mapping_corpus_test.go \
      internal/contentregistry/realcorpus_test.go \
      internal/api/rwevidence_dispatch_corpus_test.go \
      web/src/features/ransomware.js
```

Expected: No output (all files properly formatted).

- [ ] **Step 4.6: Create final summary and commit**

No code changes in this step. Just document completion:

```bash
git log --oneline [first-task-commit]..HEAD
```

Expected: Shows 3 commits (scenario+test, registration, signing).

---

## Completion Contract

Before marking this plan complete:

✅ Task 1: Scenario YAML written, parsed, smoke test PASS  
✅ Task 2: Registered in all 7 touchpoints, per-touchpoint regressions PASS  
✅ Task 3: Signed, verify-all ok=120  
✅ Task 4: Pure-Go suites PASS, contentregistry PASS, API suite PASS, gofmt clean  

**No Critical or Important findings.** Medusa scenario is production-ready.

Commits pushed to origin/main.
