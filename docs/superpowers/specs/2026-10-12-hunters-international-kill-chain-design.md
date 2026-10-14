# Hunters International Kill Chain Design Specification

> **Sub-Project #10, Family Content Pass #4**  
> Ransomware Mastery Master Roadmap  
> Author: Claude Code  
> Date: 2026-10-12

---

## 1. Executive Summary

Hunters International was a Ransomware-as-a-Service (RaaS) operation active October 2023 – November 2024, conducting 200+ attacks globally targeting industrials, legal services, healthcare, finance, and logistics. The group announced closure in November 2024 and rebranded as World Leaks (extortion-only model).

This scenario models Hunters International's **distinctive three-layer attack sequence**: Oracle WebLogic exploitation → China Chopper web shell deployment → CVE-2020-1472 Zerologon domain-controller targeting, followed by credential access, lateral movement, exfiltration, recovery inhibition, and encryption.

**Scope:** Windows-only kill chain, 9 steps, grounded in CISA/FBI/IC3 advisories and public threat intelligence.

**Validation Focus:** Vulnerability exposure detection, web-layer defense efficacy, domain-controller targeting detection, credential-access monitoring, recovery resilience.

---

## 2. Threat Intelligence Grounding

### Primary Sources

- Barracuda Security Blog: [Hunters International](https://blog.barracuda.com/2024/07/29/hunters-international--your-data-is-the-prey)
- BlackPoint Cyber Threat Profile
- AttackIQ Emulation Report: [Emulating the Splintered Hunters](https://www.attackiq.com/2025/01/27/emulating-the-splintered-hunters/)
- Forescout: Anatomy of Attack — Hunters International Ransomware
- Brandefense Technical Analysis
- Orange CERT Polska CTI Report
- Vectra Threat Actor Profile

### Key Findings

**Distinctive Attack Pattern:**
- Initial compromise: unpatched Oracle WebLogic servers (CVE-2020-14644)
- Web shell: China Chopper (T1505.003)
- Domain targeting: Zerologon exploitation (CVE-2020-1472, T1556)
- Credential theft: DCSync replication abuse (T1003.006)
- Lateral movement: RDP + SMB
- Exfiltration: Custom "Software Storage" tool (T1020)
- Recovery inhibition: vssadmin shadow copy deletion (T1490)
- Impact: AES-256 encryption with RSA public key wrapping, `.locked` file extension

**Operational Context:**
- ~60% code overlap with defunct Hive ransomware (disrupted January 2023)
- Operators claimed independent acquisition of Hive source code, not direct rebrand
- November 2024: Announced closure citing excessive government attention and geopolitical risk
- Post-closure rebranding: World Leaks (extortion-only model, no encryption)

---

## 3. Kill Chain Architecture

### Overview

**9-step Windows-only scenario** modeling Hunters International's documented attack sequence, with distinct evidence-producing steps for vulnerability exposure, detection, and response validation.

### Step Sequence and Technique Mapping

| Step | MITRE ATT&CK | Behavior | Validation Objective | Safety Model |
|------|--------------|----------|----------------------|--------------|
| 1 | T1190 | Oracle WebLogic CVE-2020-14644 exposure assessment | Vulnerability detection; public-facing app exposure | Non-destructive assessment |
| 2 | T1505.003 | China Chopper web shell — deployment/detection | Web-server monitoring; unauthorized backdoor detection | Controlled lab or benign simulation |
| 3 | T1087.002 | Domain account discovery — enumerate users/groups | Discovery reconnaissance detection | Living-off-the-land recon (safe) |
| 4 | T1556 | CVE-2020-1472 Zerologon vulnerability assessment | Domain-controller exposure; vulnerability indicators | Enumeration only, no exploit attempt |
| 5 | T1003.006 | DCSync credential replication — safe simulation | Credential-access behavior detection | Lab simulation or benign signal |
| 6 | T1021.001 | RDP lateral movement to secondary systems | Post-compromise movement detection | Valid test-environment credentials |
| 7 | T1020 | Automated exfiltration via Software Storage behavior pattern | Exfiltration behavior detection; data staging | Synthetic data, test-controlled destination |
| 8 | T1490 | Shadow copy enumeration (safe enumeration only) | Recovery inhibition reconnaissance detection | List volumes, no deletion |
| 9 | T1490 + T1486 | Simulated shadow copy deletion + ChaCha20 encryption simulation | Recovery prevention + ransomware impact | Lab-only destructive action, full recovery capability |

### Design Principles

#### 1. Distinctive Attack Narrative

Hunters International's three-layer vulnerability sequence (WebLogic → China Chopper → Zerologon) tests security boundaries distinct from prior family passes:

- **Black Basta** (pass #1): Spear-phishing entry, RDP lateral movement, EDR evasion
- **Medusa** (pass #2): Vulnerability exploitation (generic), BYOVD EDR disabling, service-disruption impact
- **Rhysida** (pass #3): Credential-first entry, RDP lateral movement, SILENTKILL defense disabling
- **Hunters International** (pass #4): Public-facing app exploitation → web-layer persistence → domain-controller targeting

#### 2. Evidence Boundary Clarity

Each step produces defensible, independently reportable evidence:

- **Step 1 (WebLogic):** Vulnerability indicators found = "potential exposure identified" (not "exploited")
- **Step 2 (China Chopper):** Deployment pattern detected = "unauthorized behavior detected" (not "backdoor installed and functional")
- **Step 4 (Zerologon):** Vulnerability indicators + configuration evidence = "potential DC exposure identified" (not "exploitation attempted")
- **Step 5 (DCSync):** Safe simulation detected = "credential-access behavior recognized" (not "actual replication abuse executed")
- **Step 9 (Encryption):** Lab-only destructive action = "environment exploitable under those conditions" (not "ransomware deployed on production")

#### 3. Safety Contracts

**No production system impact:**
- Oracle WebLogic: Assessment only, no exploit delivery
- China Chopper: Simulation or controlled lab, no functional backdoor on customer infrastructure
- Zerologon: Enumeration only, no DC password reset
- DCSync: Lab simulation or benign signal, no actual replication
- Shadow copy deletion: Enumeration step safe; deletion only in authorized, isolated lab
- Encryption: Simulated or lab-only, no actual file encryption outside test environment

**Fallback isolation:**
- Where lab-based testing is needed (Zerologon exploit attempt, shadow copy deletion, encryption), use explicitly authorized, isolated lab environments with disposable recovery artifacts
- Never claim prevention without actual testing in controlled environment

---

## 4. Technique Domain Mappings

All nine techniques require existing or new domain mappings in `orchestrator/internal/rwtaxonomy/mapping.go`:

| Technique ID | Technique Name | Domain | Status |
|--------------|---|--------|--------|
| T1190 | Exploit Public-Facing Application | DomainInitialAccess | Pre-existing |
| T1505.003 | Web Shell | DomainPreparationAndPersistence | **New (verify if T1505 parent exists)** |
| T1087.002 | Account Discovery: Domain Account | DomainPreparationAndPersistence | Pre-existing |
| T1556 | Impair Defenses: Modify Authentication Process | DomainDefenseEvasion | **New** |
| T1003.006 | OS Credential Dumping: DCSync | DomainCredentialAccess | **New** |
| T1021.001 | Remote Services: RDP | DomainLateralMovement | Pre-existing |
| T1020 | Automated Exfiltration | DomainExfiltration | Pre-existing |
| T1490 | Inhibit System Recovery | DomainRecoveryInhibition | Pre-existing |
| T1486 | Data Encrypted for Impact | DomainEncryptionAndDestruction | Pre-existing |

**Pre-flight verification:** Run mapping.go grep to confirm T1505.003, T1556, T1003.006 status before scenario authoring. Expected: 3 new domain mappings needed (same pattern as Rhysida's T1078 + T1562.008).

---

## 5. Action Keys and Execution Classification

All nine steps use existing `action_keys` from `orchestrator/internal/execclass/execclass.go`:

| Step | Action Key | Classification | Rationale |
|------|------------|-----------------|-----------|
| 1 | `vulnerability_assessment` | Reconnaissance | Non-invasive exposure check |
| 2 | `web_shell_detection` | Persistence/C2 | Detection of unauthorized software |
| 3 | `enumerate` | Discovery | Safe enumeration, no modification |
| 4 | `vulnerability_assessment` | Reconnaissance | Enumeration of vulnerable indicators |
| 5 | `credential_access_sim` | Credential Access | Safe simulation, no actual replication |
| 6 | `lateral_movement_rdp` | Lateral Movement | Valid credentials in test environment |
| 7 | `exfil_sim` or `data_staging` | Exfiltration | Synthetic data, test destination |
| 8 | `enumerate` | Discovery | Safe enumeration only |
| 9 | `ransomware_sim_sandboxed` | Impact | Lab-only destructive action |

**Pre-flight check:** Verify `action_keys` exist in execclass.go. If `credential_access_sim`, `web_shell_detection`, `exfil_sim`, or `vulnerability_assessment` are missing, add them as part of scenario smoke-test task.

---

## 6. Scenario Structure

### File Location
`scenarios/hunters-international-kill-chain.yaml`

### Provenance Fields (Required)

```yaml
id: hunters-international-kill-chain
name: "Hunters International Kill Chain — Oracle WebLogic to Ransomware"
description: "9-step attack chain modeling Hunters International RaaS operations: Oracle WebLogic exploitation, China Chopper web shell deployment, Zerologon domain-controller targeting, credential access, lateral movement, exfiltration, recovery inhibition, and encryption."
family_attribution: Hunters International
family_attribution_confidence: confirmed
threat_intel_sources:
  - "Barracuda Security Blog: Hunters International (2024)"
  - "AttackIQ Emulation Report: Emulating the Splintered Hunters (2025)"
  - "Forescout: Anatomy of an Attack — Hunters International"
  - "BlackPoint Cyber: Hunters International Threat Profile"
  - "Brandefense Technical Analysis"
  - "Orange CERT Polska CTI Report"
  - "Vectra Threat Actor Profile"
last_reviewed: "2026-10-12"
platform: windows
```

### Scenario Smoke Test

**Test name:** `TestHuntersInternationalKillChain_ParsesWithNineStepsWindowsOnlyFullyGrounded`

**Assertions:**
- Scenario parses without error
- 9 steps defined
- All steps present and in sequence (T1190, T1505.003, T1087.002, T1556, T1003.006, T1021.001, T1020, T1490×2)
- Platform is Windows-only
- All provenance fields present (family_attribution, threat_intel_sources, last_reviewed)
- All action_keys valid (matched against execclass.go)

---

## 7. Registration Touchpoints

Hunters International scenario must be registered across **8 touchpoints** (matching Black Basta/Medusa/Rhysida pattern):

1. `orchestrator/internal/api/rwevidence_dispatch.go` — `ransomwareScenarioIDs` map
2. `orchestrator/internal/rwdetect/profiles_test.go` — corpus test file list
3. `orchestrator/internal/rwevidence/realcorpus_test.go` — corpus test file list
4. `orchestrator/internal/rwtaxonomy/mapping_corpus_test.go` — corpus test file list
5. `orchestrator/internal/contentregistry/realcorpus_test.go` — corpus test file list
6. `orchestrator/internal/api/rwevidence_dispatch_corpus_test.go` — corpus test file list
7. `orchestrator/web/src/features/ransomware.js` — `RR_SCENARIO_IDS` array
8. `orchestrator/internal/rwtaxonomy/mapping.go` — technique domain mappings (3 new entries)

**Verification gate:** `TestRansomwareScenarioIDs_MatchesRealCorpus` and `TestTechniqueDomain_MatchesRealCorpus` must both pass after registration.

---

## 8. Signing and Verification

**Signing gate:** All scenario signatures must pass `verify-all` before merge.

- Create: `scenarios/hunters-international-kill-chain.yaml.sig` via `go run scripts/signer.go sign private_key.pem ../scenarios/hunters-international-kill-chain.yaml`
- Verify: `cd orchestrator && go run scripts/signer.go verify-all`
- Expected: `ok=<N+1> fail=0` (adding Hunters to existing scenario corpus)

---

## 9. Regression Testing

**Test suite validation:**

1. `./internal/scenario` — Hunters smoke test (RED → GREEN cycle)
2. `./internal/contentregistry` — Corpus compatibility
3. `./internal/rwdetect` — Ransomware detection corpus validation
4. `./internal/rwevidence` — Evidence dispatch corpus validation
5. `./internal/rwtaxonomy` — Technique domain mapping validation
6. `./internal/api` — Full regression suite (long-running, expected ~20-25 min)

**Expected outcome:** All suites PASS. Pre-existing API test failures (if any) are out-of-scope; focus on Hunters-specific test coverage.

---

## 10. Comparison to Prior Family Passes

| Attribute | Black Basta | Medusa | Rhysida | Hunters International |
|-----------|-------------|--------|---------|----------------------|
| Entry vector | T1566 Spear-phishing | T1190 Exploit | T1078 Valid Accounts | T1190 Oracle WebLogic |
| Entry distinctive | Phishing attachment | Generic CVE | Credential-first | Public-facing app targeting |
| Lateral movement | RDP (T1021.001) | RDP (T1021.001) | RDP (T1021.001) | RDP (T1021.001) |
| Defense evasion | T1562.001 (SILENTKILL) | T1489 (service stop) | T1562.001/008/070 (SILENTKILL) | T1556 (Zerologon), T1505.003 (backdoor) |
| Credential access | T1003.001 (LSASS) | T1003.001 (LSASS) | T1003.001 (LSASS) | T1003.006 (DCSync) |
| Exfiltration | T1020 RClone | T1020 RClone | T1020 RClone | T1020 Software Storage |
| Recovery inhibition | T1490 Enumeration | T1490 Enumeration + Delete | T1490 Enumeration + Delete | T1490 Enumeration + Delete |
| Impact | T1486 Encryption | T1486 Encryption | T1486 Encryption | T1486 Encryption |
| Total steps | 8 | 10 | 11 | 9 |
| Distinct validation focus | Phishing detection | Exploit prevention | Identity controls | Vulnerability exposure + DC targeting |

---

## 11. Success Criteria

✅ **Scenario authoring:**
- 9-step YAML scenario, Windows-only, fully grounded in threat intelligence
- All provenance fields populated
- All action_keys valid (existing or added as part of smoke test)

✅ **Registration:**
- Registered across 8 touchpoints
- All corpus tests pass
- Technique domain mappings in place (3 new entries)

✅ **Signing & verification:**
- Scenario signed with RSA-4096 key
- All scenario signatures valid (`verify-all` ok=N fail=0)

✅ **Regression testing:**
- Smoke test RED → GREEN → COMMIT
- All Hunters-specific test suites PASS
- No regressions in pre-existing test coverage

✅ **Evidence boundary clarity:**
- Each step's validation objective is clearly stated
- Evidence outcomes distinguished (exposure vs. detection vs. prevention)
- No overstated claims about compromise or prevention

---

## 12. Known Limitations & Deferred Work

**Out of scope for this scenario:**

1. **ESXi/Linux variants** — Hunters also targeted Linux/ESXi; scope limited to Windows for this pass
2. **Reverse-engineered tool internals** — China Chopper and Software Storage tool behaviors simulated at documented behavior level, not full tool recreation
3. **Full incident timeline** — Attack chain compressed to representative 9-step sequence; actual dwell time 2–14 days per reports
4. **C2 protocol details** — Only Application Layer Protocol (T1071) and TLS (T1573) confirmed; full protocol analysis deferred
5. **World Leaks post-closure operations** — Hunters rebranded as extortion-only model after November 2024; post-closure tactics deferred to separate family pass

---

## 13. Author Notes

This specification follows the established pattern from Black Basta (pass #1), Medusa (pass #2), and Rhysida (pass #3), with Hunters International contributing a distinctive public-facing app exploitation + domain-controller targeting vertical. The scenario is grounded in 7 public threat intelligence sources and designed with explicit evidence boundaries to avoid overstating what controls actually prevent vs. detect vs. expose.

The three-layer vulnerability sequence (WebLogic → China Chopper → Zerologon) provides a meaningful test of security monitoring across application, web, and directory-service boundaries — a combination not represented in prior family passes.
