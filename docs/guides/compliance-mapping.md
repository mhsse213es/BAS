# Audspect BAS — Compliance Mapping Guide

**Platform Version:** v1.7.3

---

## Overview

Audspect BAS maps simulation results to regulatory and security framework requirements, enabling continuous compliance evidence generation. Every simulation run that tests a technique mapped to a framework control automatically updates the compliance score for that control.

Compliance scores represent **control effectiveness** (does the control block the technique?) — not configuration compliance. Audspect BAS tests runtime behavior, not configuration snapshots.

---

## Supported Frameworks

| Framework | Coverage Type | Report Support |
|---|---|---|
| MITRE ATT&CK v14 | Tactic and technique coverage | HTML, PDF |
| RBI Cyber Security Framework | MII continuous control validation | HTML, PDF |
| SEBI Cybersecurity Circular | Control mapping | HTML, PDF |
| CIS Benchmarks v8 (Level 1) | Configuration hardening checks | HTML, PDF |
| NIST SP 800-53 Rev 5 | Control family mapping via techniques | HTML, PDF |
| ISO 27001:2022 | Annex A control mapping | HTML, PDF |

---

## MITRE ATT&CK v14

### Coverage approach

Every scenario step is mapped to a MITRE ATT&CK technique (e.g., T1003.001) and tactic (e.g., credential-access). Simulation results populate the ATT&CK technique matrix with PASS/FAIL/NOT TESTED overlays.

The compliance report shows:
- Techniques tested across all agents
- Techniques with failures (adversary success)
- Techniques not yet tested (coverage gap)
- Pass rate per tactic

### ATT&CK Navigator export

```
GET /api/scenarios/runs/{runId}/attackflow
```

Returns a MITRE ATT&CK Navigator layer JSON. Import this into the ATT&CK Navigator at https://mitre-attack.github.io/attack-navigator/ to visualize coverage.

### Technique-to-tactic mapping

All technique-to-tactic mappings use the bundled ATT&CK STIX data (authoritative). Custom mappings are never invented or auto-generated.

---

## RBI Cyber Security Framework (Banks)

### Overview

The RBI CSF requires banks to demonstrate the effectiveness of cybersecurity controls through continuous testing. Audspect BAS provides a specific scenario — **RBI CSCRF / SEBI MII Drill** — mapped to the RBI framework's control categories.

### Mapped control categories

| RBI Control Category | Mapped Techniques | BAS Test Coverage |
|---|---|---|
| IT Governance | Configuration management checks | Custom posture steps |
| Security Operations | EDR effectiveness, SIEM alerting | ART + custom steps |
| Vulnerability Management | Exploit technique blocking | ART atomics |
| Incident Response | Detection and containment | ART + Caldera |
| Data Protection | Credential theft, DLP bypass | ART credential-access |
| Access Management | Privilege escalation blocking | ART privilege-esc |
| Network Security | Lateral movement blocking | ART lateral-movement |

### Generating an RBI compliance report

1. Run the **RBI CSCRF / SEBI MII Drill** scenario on your target agents
2. Navigate to **Compliance** → **RBI Cyber Security Framework**
3. Click **Download Report** (HTML or PDF)

The report shows: control category → tested techniques → pass/fail results → compliance score → gaps.

---

## SEBI Cybersecurity Circular (MII)

The SEBI cybersecurity circular for Market Infrastructure Institutions (MII) requires continuous control monitoring. The SEBI scenario in Audspect BAS is structurally similar to the RBI drill but mapped to SEBI's circular categories.

Run the same RBI/SEBI scenario — it produces separate reports for each framework.

---

## CIS Benchmarks v8 (Level 1)

### Scope

The CIS Ubuntu L1 scenario tests 25+ configuration hardening checks from CIS Benchmarks v8, Level 1, for Ubuntu Linux endpoints. Checks include:

- Filesystem configuration
- Software package management
- Services configuration
- Network configuration
- Logging and auditing
- Access, authentication, and authorization
- Warning banners

### Generating a CIS compliance report

1. Run the **CIS Ubuntu L1** scenario on Linux agents
2. Navigate to **Compliance** → **CIS Benchmarks**
3. Download the compliance report

The report shows each CIS control ID, the check result, and remediation guidance for failures.

**Note:** CIS L1 checks are configuration-only (custom posture steps). They verify current configuration state, not runtime attack blocking.

---

## NIST SP 800-53 Rev 5

### Mapping approach

NIST SP 800-53 controls are mapped to MITRE ATT&CK techniques via a curated overlay. For example:

| NIST Control | Description | Mapped Techniques |
|---|---|---|
| AC-2 | Account Management | T1078, T1087, T1136 |
| AC-6 | Least Privilege | T1548, T1068 |
| AU-2 | Audit Events | T1070, T1562 |
| IA-5 | Authenticator Management | T1003, T1552, T1555 |
| SC-7 | Boundary Protection | T1048, T1041, T1571 |
| SI-3 | Malicious Code Protection | T1059, T1055, T1027 |

The compliance report shows: NIST control → mapped techniques → test results → effective rating (Effective / Partially Effective / Not Tested / Failing).

**Important:** This mapping is curated and maintained by Audspect — it is not auto-generated. Only techniques where a reliable control-effectiveness relationship exists are mapped.

---

## ISO 27001:2022

### Mapping approach

ISO 27001 Annex A controls are mapped to ATT&CK technique families:

| Annex A Control | Title | Technique Examples |
|---|---|---|
| A.5.23 | Information security for cloud services | T1530, T1537 |
| A.8.2 | Privileged access rights | T1068, T1548 |
| A.8.7 | Protection against malware | T1059, T1566 |
| A.8.16 | Monitoring activities | T1070, T1562.001 |
| A.8.22 | Segregation of networks | T1021, T1090 |
| A.8.29 | Security testing in development | Not BAS scope |

---

## Compliance Scores

Compliance scores are available at:
```
GET /api/compliance/scores
```

Response:
```json
{
  "mitre_attack": {
    "tacticsCovered": 11,
    "tacticsTotal": 14,
    "techniquesTested": 148,
    "techniquesPassed": 121,
    "techniquesFailed": 27,
    "coveragePercent": 73.1,
    "effectivenessPercent": 81.8
  },
  "rbi_csf": {
    "controlsTotal": 22,
    "controlsTested": 18,
    "controlsEffective": 14,
    "compliancePercent": 63.6
  },
  "cis_l1": {
    "checksTotal": 27,
    "checksPassed": 21,
    "checksFailed": 6,
    "compliancePercent": 77.8
  }
}
```

---

## Coverage vs. Effectiveness

Two distinct metrics appear in compliance reports:

| Metric | Meaning |
|---|---|
| **Coverage** | Percentage of framework controls that have at least one BAS test mapped to them |
| **Effectiveness** | Percentage of tested controls where the security control blocked the technique |

A 100% coverage score with 0% effectiveness means every technique is tested but no controls are working. A 50% coverage score with 100% effectiveness means only half the framework is tested, but every tested technique is blocked.

Both metrics together tell the complete story.

---

## Evidence for Audit

Compliance reports serve as audit evidence for:
- Regulatory examinations (RBI, SEBI)
- Third-party security assessments
- Board-level security reporting
- Cyber insurance applications

The PDF compliance report includes:
- Report generation timestamp (tamper-evident)
- SHA-256 integrity hash
- Run IDs for each tested technique (cross-reference to raw evidence)
- Operator who authorized the simulation runs

---

*© Audspect — Confidential — Customer Distribution*
