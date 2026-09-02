# DLP Content-Type Diversity Design

**Date:** 2026-09-02
**Author:** Audspect Research
**Status:** Design Phase
**Scope:** Scenario-authoring addition across all 8 existing sink-verified DLP exfiltration channels
**Architecture:** No engine, schema, or scoring changes — pure content-diversity addition to existing scenario YAML files

---

## Overview

The 8-channel sink-verified DLP exfiltration program (HTTPS, DNS tunneling, SFTP, SMTP, cloud storage, webhook, code repository, telnet) achieves ~94-95% *channel/protocol* coverage against `data_exfiltration_csv_report.csv`, a 5,000+ row real-world DLP benchmark. Every existing scenario step, regardless of channel, sends exactly one synthetic payload shape: a fabricated BFSI record (PAN/Aadhaar/SWIFT/UPI/credit-card).

The benchmark CSV's `Phrase Title` column (its actual content-classification taxonomy — distinct from `Attack Type`, the channel, and `Content Type`, which is really file *format*: Word/PDF/Zip/OCR/etc.) shows ~30 distinct content classifications: cloud credentials, database connection strings, source code in seven languages, PII of several jurisdictions, five credit-card brands, and legal/financial documents. None of these are exercised today — every channel only ever sends the one BFSI shape.

This spec adds content-type diversity: representative payloads from each of these classifications, distributed across the existing 8 channels in a way that mirrors real-world plausibility (source code over code-repo channels, DB connection strings over file-transfer channels, etc.) without attempting a full 30×8 cross-product.

---

## Critical Architectural Finding: Evidence Is Keyed By `technique_id`, Not Content Type

Before scoping the payload work, the verification pipeline was inspected (`internal/reporting/detection_validation.go`):

- `evidenceByTechnique` collapses every `SimulationResult` sharing a `technique_id` down to **one** evidence object per run (its own comment: *"If multiple steps share a technique, prefer the one that actually fired a detection"*) — any other steps sharing that technique_id have their evidence discarded.
- `ComputeAutomaticVerifications` looks up evidence by `spec.TechniqueID` (the step's own technique), then verifies **every** `expected_detection` entry the step's referenced profile carries using that single evidence object.

**Consequence:** the platform's scoring grain is `Run → Technique → Evidence → Pass/Fail`, not `Run → Technique → Content Type → Pass/Fail`. If N content-type-variant steps share one channel's technique_id (e.g. five payload shapes all riding SFTP under T1048.002), only one of their outcomes survives into the report, chosen by an internal heuristic — not all five independently.

**Decision (confirmed with the user):** content-type diversity in this iteration is **traffic-shape diversity only** — it exists to give a *real* customer DLP/CASB product on the wire more varied content to pattern-match against, not to produce new per-content-type findings in Audspect's own report. Every new step still rolls up to the *existing* per-channel finding (e.g. `dlp-sftp-block`). Report/scenario language must say "exercised with representative payload diversity," never "classification coverage" or "per-content-type verdict" — the backend cannot honestly back that claim without a separate, larger verification-model change (a new `content_family`/`variant` dimension alongside `technique_id`, touching `dlp_sink_tokens`, `dlp_sink_receipts`, expected-detection matching, and `evidenceByTechnique`). That model change is explicitly **out of scope** here — a candidate future project if a customer ever asks "show me my DLP catches AWS credentials over SFTP but misses PII over SFTP," not something to build speculative hooks for now.

---

## Content Family Taxonomy

The ~30 CSV `Phrase Title` values collapse into 6 families. Each variant below is fabricated, `[BAS-SIM-DLP]`-tagged, and uses well-known non-functional placeholder values (the same convention the CSV's own AWS example already follows: `AKIAIOSFODNN7EXAMPLE` is AWS's own published, non-functional documentation key).

### Cloud Credentials

| Variant | Payload |
|---|---|
| AWS | `[default]\naws_access_key_id=AKIAIOSFODNN7EXAMPLE\naws_secret_access_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY` |
| Azure | `{"appId":"00000000-1111-0000-0000-000000000000","displayName":"BAS-SIM-DLP-ServicePrincipal","password":"df111111-0000-0000-0000-100000000000","tenant":"11111111-0000-0000-0000-000000000000"}` |
| GCP | `{"type":"service_account","project_id":"bas-sim-dlp-project","private_key_id":"0000000000000000000000000000000000dead","client_email":"bas-sim@bas-sim-dlp-project.iam.gserviceaccount.com"}` |

### DB Connection Strings

| Variant | Payload |
|---|---|
| Oracle | `Data Source=BAS-SIM-ORACLE;User Id=bas_sim_user;Password=BAS-SIM-DLP-Placeholder1;` |
| MS SQL | `Server=bas-sim-mssql;Database=BAS_SIM_DLP;User Id=bas_sim_user;Password=BAS-SIM-DLP-Placeholder2;` |
| MongoDB | `mongodb://bas_sim_user:BAS-SIM-DLP-Placeholder3@bas-sim-mongo:27017/bas_sim_dlp` |
| PostgreSQL | `postgresql://bas_sim_user:BAS-SIM-DLP-Placeholder4@bas-sim-postgres:5432/bas_sim_dlp` |
| DB2 | `DATABASE=BASSIMDLP;HOSTNAME=bas-sim-db2;PORT=50000;PROTOCOL=TCPIP;UID=bas_sim_user;PWD=BAS-SIM-DLP-Placeholder5;` |

### Source Code

| Variant | Payload |
|---|---|
| Python | `# [BAS-SIM-DLP]\nAWS_SECRET = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"  # test fixture` |
| Java | `// [BAS-SIM-DLP]\nString dbPassword = "BAS-SIM-DLP-Placeholder6"; // test fixture` |
| C# | `// [BAS-SIM-DLP]\nstring apiKey = "BAS-SIM-DLP-Placeholder7"; // test fixture` |
| Go | `// [BAS-SIM-DLP]\nconst dbPassword = "BAS-SIM-DLP-Placeholder8" // test fixture` |
| PHP | `<?php // [BAS-SIM-DLP]\n$db_password = "BAS-SIM-DLP-Placeholder9"; ?>` |
| Perl | `# [BAS-SIM-DLP]\nmy $secret = "BAS-SIM-DLP-Placeholder10"; # test fixture` |

### PII (beyond the existing BFSI anchor)

The existing PAN/Aadhaar/SWIFT/UPI/credit-card record already present in every channel's original step **stays untouched** and remains the PII anchor for most channels. These are additional variants for the handful of channels getting a *second* PII-family step:

| Variant | Payload |
|---|---|
| US SSN | `[BAS-SIM-DLP] Name,SSN\nJohn BasSim,000-12-3456` (the `000` area is never issued by SSA — permanently invalid/safe) |
| UK National Insurance | `[BAS-SIM-DLP] Name,NINO\nJohn BasSim,QQ123456C` (`QQ` prefix is officially reserved invalid/test-only by HMRC) |
| Israeli ID | `[BAS-SIM-DLP] Name,ID\nJohn BasSim,000000000` (all-zero, fails checksum, non-issuable) |
| Medical record | `[BAS-SIM-DLP] Patient,MRN,Diagnosis\nBAS-SIM-Patient,MRN-000000,Synthetic-Test-Diagnosis` |

### Payment Cards

Standard, publicly documented test-mode card numbers (used by every payment processor's own sandbox — non-functional in production):

| Variant | Number |
|---|---|
| Visa | `4111111111111111` (already used in the existing BFSI record) |
| Mastercard | `5555555555554444` |
| American Express | `378282246310005` |
| Discover | `6011111111111117` |
| Maestro | `6759649826438453` |

### Legal / Financial Documents

| Variant | Payload |
|---|---|
| Financial Statement | `[BAS-SIM-DLP] Financial Statement (Synthetic)\nCompany: BAS-SIM-Corp\nRevenue: $0.00 (synthetic)\nNet Income: $0.00 (synthetic)` |
| Employment Contract | `[BAS-SIM-DLP] Employment Contract (Synthetic)\nEmployee: BAS-SIM-Employee\nSalary: $0.00 (synthetic, test fixture only)` |
| Partnership Agreement | `[BAS-SIM-DLP] Partnership Agreement (Synthetic)\nParty A: BAS-SIM-Corp-A\nParty B: BAS-SIM-Corp-B (test fixture only)` |

---

## Channel → Family → Variant Mapping

Curated per channel for real-world plausibility, not a full cross-product. Existing steps and their technique_ids are unchanged; these are additional steps appended to each scenario file. Variants repeat across channels where that's realistic (e.g. leaked AWS credentials plausibly travel over many channels) rather than forcing artificial uniqueness.

| Scenario file | New steps (family → variant) | Count |
|---|---|---|
| `dlp-exfiltration-sink-https.yaml` | Cloud Credentials→AWS, DB Strings→Oracle, Source Code→Python, PII→US SSN, Payment Cards→Visa | 5 |
| `dlp-exfiltration-dns-tunnel.yaml` | Cloud Credentials→Azure, PII→UK NINO, Payment Cards→Mastercard | 3 |
| `dlp-exfiltration-sftp.yaml` | DB Strings→MS SQL, Source Code→Java, Legal/Financial→Financial Statement, PII→Israeli ID, Payment Cards→Amex | 5 |
| `dlp-exfiltration-smtp.yaml` | PII→Medical record, Payment Cards→Discover, Cloud Credentials→GCP, Legal/Financial→Employment Contract, Source Code→Go | 5 |
| `dlp-exfiltration-cloud-storage.yaml` | Cloud Credentials→AWS (attached to the existing S3 step), DB Strings→MongoDB (attached to Azure Blob step), Source Code→C# (attached to Google Drive step), Legal/Financial→Partnership Agreement (attached to OneDrive step) | 4 |
| `dlp-exfiltration-webhook.yaml` | Cloud Credentials→AWS, DB Strings→PostgreSQL, Payment Cards→Maestro | 3 |
| `dlp-exfiltration-coderepo.yaml` | Source Code→PHP, Source Code→Perl, Cloud Credentials→Azure, DB Strings→DB2 | 4 |
| `dlp-exfiltration-telnet.yaml` | Cloud Credentials→AWS, Payment Cards→Discover, DB Strings→Oracle | 3 |

**Total: 32 new steps** across the 8 existing scenario files, all existing steps unchanged. Every one of the ~30 catalog variants appears at least once somewhere in the suite.

---

## Implementation Approach

**No Go code changes.** No new package, no scenario schema field, no new detection-profile entries, no new placeholder types. This is scenario-authoring work only, following the exact pattern every existing DLP step already uses:

- Same `{{SINK_TOKEN}}` / `{{SINK_<CHANNEL>_HOST}}` / `{{SINK_<CHANNEL>_PORT}}` placeholders, substituted by the existing `issueSinkTokensAndSubstitute` (unchanged).
- Same `detection_profiles: [windows_dlp_exfiltration]` reference and the channel's existing `technique_id` — unchanged, so these new steps roll into the same finding their channel's existing step already reports to.
- Same PowerShell executor conventions per channel (`Invoke-RestMethod`, `Invoke-WebRequest`, etc., matching whatever the channel's existing step already uses).
- Same `[BAS-SIM-DLP]` tagging and `DLP_OBSERVATION:` marker convention.
- Step names follow the existing pattern with the content family appended, e.g. `"DLP Validation — HTTPS Exfiltration of AWS Cloud Credentials (T1567)"`, so the report distinguishes *which payload shape* a step exercised even though all steps for a channel still roll up to one finding.

Each new step's description explicitly states it is testing traffic-shape/content diversity, not claiming a new classification-level verdict — matching the reporting-honesty decision above.

---

## Payload Safety

All payloads reuse the program's existing conventions:
- `[BAS-SIM-DLP]` tag on every synthetic record.
- No real credentials, keys, or personal data — every value is either an officially-documented non-functional test value (AWS's own EXAMPLE key, standard payment-processor test card numbers, HMRC's reserved `QQ` NINO prefix, SSA's unissued `000` SSN area) or an obviously fabricated `BAS-SIM-*` placeholder.
- Every destination remains this same on-prem orchestrator's own sink endpoints — no external service is ever contacted, identical to every existing channel.

---

## Files Affected

**Modify (append steps only, no structural changes):**
- `orchestrator/scenarios/dlp-exfiltration-sink-https.yaml` (+5 steps)
- `orchestrator/scenarios/dlp-exfiltration-dns-tunnel.yaml` (+3 steps)
- `orchestrator/scenarios/dlp-exfiltration-sftp.yaml` (+5 steps)
- `orchestrator/scenarios/dlp-exfiltration-smtp.yaml` (+5 steps)
- `orchestrator/scenarios/dlp-exfiltration-cloud-storage.yaml` (+4 steps)
- `orchestrator/scenarios/dlp-exfiltration-webhook.yaml` (+3 steps)
- `orchestrator/scenarios/dlp-exfiltration-coderepo.yaml` (+4 steps)
- `orchestrator/scenarios/dlp-exfiltration-telnet.yaml` (+3 steps)
- Corresponding `.sig` files re-signed for each

**Not touched:** any Go source file, `windows_dlp_exfiltration.yaml` (no new expected_detection entries — every new step maps to an *existing* finding), any test file (no Go code changed, nothing new to unit-test).

---

## Testing Strategy

No new Go tests are needed since no Go code changes. Verification is scenario-level:
1. Each modified scenario YAML parses and loads via the existing scenario loader (`go test ./internal/scenario/...`).
2. Re-sign each modified scenario `.sig` (`go run scripts/signer.go sign private_key.pem <file>`) — signature verification is already covered by existing tests.
3. `TestRBACMatrix_NoDrift` and the full `internal/api` suite continue passing unmodified (no new routes).
4. Spot-check one step per channel manually (or via a live run) to confirm the new payload substitutes placeholders correctly and a receipt is written to `dlp_sink_receipts`, exactly as the existing steps already do.

---

## Success Criteria

1. All 8 scenario YAML files parse and load without errors after the additions.
2. All `.sig` files re-signed and verify correctly.
3. `go test ./internal/scenario/... ./internal/api/...` passes with no regressions.
4. Every one of the 6 content families and ~30 CSV-derived variants is represented by at least one concrete step somewhere in the suite.
5. No step's description or the detection profile claims per-content-type scoring — report language stays honest about the technique-level scoring grain.

---

## Explicit Non-Goals

- **Per-content-type scored findings.** Deliberately deferred — requires a separate verification-model change (new `content_family`/`variant` evidence dimension). Not started, no hooks added for it here.
- **Full 30×8 cross-product.** Deliberately avoided — curated, plausibility-driven mapping only.
- **A runtime-loaded payload library / new scenario schema field.** Payloads are literal, hand-authored step content, matching every existing DLP scenario's convention — no engine change.
- **New content types beyond the CSV's own taxonomy.** Scope is bounded to what `data_exfiltration_csv_report.csv` actually contains.
