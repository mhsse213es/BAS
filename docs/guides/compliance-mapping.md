# Audspect BAS — Compliance Mapping Guide

**Platform Version:** v1.7.3

---

## Overview

Audspect BAS maps simulation results to regulatory and security framework requirements, enabling continuous control-effectiveness evidence. Every simulation run that tests a technique mapped to a framework control automatically updates the evidence for that control.

The figures represent **control resistance** (did the control stop the techniques that were executed?). They are **not a determination of compliance**: a control can resist the techniques tested and still not meet its requirement. Audspect BAS tests runtime behavior, not configuration snapshots.

The technique-to-control mappings are Audspect's own work. They have not been certified by any regulator. The RBI mapping carries an explicit warning in the product: it has not been verified against the paragraph numbering of the 2026 directions.

---

## Supported Frameworks

| Framework | Coverage Type | Report Support |
|---|---|---|
| SEBI CSCRF (`SEBI_CSCRF`) | Control mapping | CSV, JSON, HTML, PDF |
| RBI CSF (`RBI_CSF`) | Control mapping (commercial banks) | CSV, JSON, HTML, PDF |
| CERT-In (`CERT_IN`) | Control mapping | CSV, JSON, HTML, PDF |
| IRDAI CSF (`IRDAI_CSF`) | Control mapping | CSV, JSON, HTML, PDF |
| ISO/IEC 27001:2022 (`ISO_27001_2022`) | Annex A control mapping | CSV, JSON, HTML, PDF |
| NIST CSF 2.0 (`NIST_CSF_2`) | Control mapping (Govern, Identify, Protect, Detect, Respond, Recover) | CSV, JSON, HTML, PDF |
| PCI DSS v4 (`PCI_DSS_V4`) | Control mapping | CSV, JSON, HTML, PDF |

The framework list is served by `GET /api/compliance/frameworks`.

---

## RBI Cyber Security Framework (Banks)

### Overview

The RBI CSF requires banks to demonstrate the effectiveness of cybersecurity controls through continuous testing. Audspect BAS provides the **SEBI CSCRF-MII Continuous Control Validation (Three-Tier)** scenario (`cscrf-mii-drill.yaml`), whose controls are mapped to the RBI and SEBI frameworks.

### Mapped control categories

The RBI CSF mapping covers these control categories:

| RBI Control Category | Examples |
|---|---|
| Privileged Access | PAM controls for admin and service accounts |
| Authentication | MFA for privileged and remote access |
| Access Control | Least-privilege enforcement and access reviews |
| Credential Management | Secure storage and rotation of credentials |
| Segmentation | Isolation of critical systems from the general network |
| Perimeter Security | Firewall and perimeter filtering |
| Anti-Malware, Detection, SIEM, Monitoring, Log Management, Intrusion Detection, Response, Execution Control, Data Leakage Prevention, Encryption, Backup, Disaster Recovery, Remote Access, Data Classification, Application Protection | See the mapping file for each control |

### Generating an RBI compliance report

1. Run the **SEBI CSCRF-MII Continuous Control Validation (Three-Tier)** scenario on your target agents
2. Navigate to **Reports** → **Compliance Report**, select the RBI framework, and click **Generate**
3. Click **↓ PDF** or **↗ HTML**

The report shows: control category → tested techniques → results → control status and coverage → gaps.

---

## SEBI Cybersecurity Circular (MII)

The SEBI cybersecurity circular for Market Infrastructure Institutions (MII) requires continuous control monitoring. The SEBI scenario in Audspect BAS is structurally similar to the RBI drill but mapped to SEBI's circular categories.

Run the same RBI/SEBI scenario — it produces separate reports for each framework.

---

## ISO 27001:2022

### Mapping approach

ISO 27001 Annex A controls are mapped to ATT&CK technique families:

| Annex A Control | Title | Mapped Techniques |
|---|---|---|
| A.5.23 | Information security for cloud services | T1567, T1195 |
| A.8.2 | Privileged access rights | T1134, T1548, T1078 |
| A.8.7 | Protection against malware | T1059, T1047, T1566, T1204, T1027 |
| A.8.16 | Monitoring activities | T1003, T1055, T1134, T1036 |
| A.8.22 | Segregation of networks | T1021, T1550 |
| A.8.29 | Security testing in development and acceptance | T1190, T1203 |

---

## Control Scores

Compliance scores for all configured frameworks are available at:
```
GET /api/compliance/scores
```

The response is a list with one entry per framework. Each entry includes `frameworkId`, `frameworkName`, `shortName`, `regulator`, `totalControls`, `testableControls`, `manualControls`, `testedControls`, `passingControls`, `failingControls`, `untestedControls`, `coveragePct`, `compliancePct` (the resistance rate), `sufficientCoverage`, `coverageNote`, `mappingWarning`, `runCount` and `snapshotAt`. Add `?agentId=<id>` to scope the scores to one agent; without it the scores are fleet-wide.

---

## Control status, resistance rate and coverage

Each testable control gets a status **derived from technique-level evidence**. The raw execution results are never changed.

| Status | Meaning |
|---|---|
| **Resisted** | Every mapped technique was executed and none succeeded |
| **Failed** | At least one executed technique succeeded. This wins over every other state |
| **Partial** | Some, but not all, mapped techniques were executed, and none succeeded |
| **Inconclusive** | Nothing ran cleanly: the attempts errored or were vetoed |
| **Untested** | No mapped technique was executed |
| **Manual** | A governance or policy control that a simulation cannot test; it needs attestation and is never scored |

A technique counts as tested only when a step ran and gave a verdict (pass, blocked or fail). Errored, vetoed and skipped steps are never evidence. A base technique such as T1003 is covered by a run of any of its sub-techniques; a sub-technique such as T1003.001 only by itself.

Two numbers are always shown together:

| Metric | Meaning |
|---|---|
| **Resistance rate** | Tested controls where no executed technique succeeded, divided by tested controls (`passingControls` / `testedControls`; the API field is still `compliancePct`) |
| **Control coverage** | Tested controls divided by testable controls (`testedControls` / `testableControls`). Manual controls are excluded |

The resistance rate says nothing about controls that were not tested. One resisted control out of 117 is a 100% rate at 0.85% coverage, and the report says "Insufficient coverage for framework-level conclusions" until coverage reaches 50% of the testable controls. Each control also shows how many of its mapped techniques were tested ("2 of 3").

Do not present the resistance rate as framework compliance.

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
- The run ID the report is scoped to, when it is scoped to a single run
- The user who generated the report (`generatedBy` in the attestation)

---

*© Audspect — Confidential — Customer Distribution*
