# WAF BAS Mastery Phase 9: Industry and Regional Profiles — Design Spec

## 1. Scope

Per `waf.txt` lines 174-177, Phase 9 is: **"Industry and regional profiles — Build evidence-backed profiles for BFSI, NBFCs, manufacturing, healthcare, India and UAE."**

New package: `orchestrator/internal/wafprofile`. Six seed profiles: 4 industry (BFSI, NBFC, manufacturing, healthcare) + 2 regional (India, UAE), each bundling a subset of `wafcatalog`'s existing, real attack-vector IDs with the compliance/regulatory frameworks that make those vectors relevant to that industry or region.

## 2. The evidence problem this phase ran into, and how it's resolved

Before writing any code, real web research was run (this session, 2026-10-16) on the specific regulatory instruments plausibly relevant here: RBI's cyber-security framework for banks/NBFCs, CERT-In's directions for critical infrastructure/manufacturing, India's DPDP Act + ABDM for healthcare, and UAE's NESA/Information Assurance Standards. Every result was a vendor blog or compliance-consultancy page; none offered a primary-source-confirmed citation (an exact circular number, rule number, or standard clause) that could be verified against the regulator's own text in this session. This matches a documented prior incident in this same project ([[project_emailgw_mastery_initiative]]'s stale/repealed RBI circular) — citing a specific regulatory clause without primary-source verification is a real, previously-realized failure mode here, not a hypothetical one.

**Resolution:** this phase never encodes an unverified regulatory citation as if it were settled fact. The type system (`ComplianceReference`, §4.2) forces every compliance claim to carry an explicit `VerificationStatus`, and the seed catalog (§6) marks every entry `Unverified` with a `Note` stating plainly that only the framework's name and general scope are asserted — never a specific clause, circular number, or control ID — and that the claim has not been confirmed against the regulator's primary text. This is the same fixture-backed-and-disclosed discipline already used throughout this session for lab-gated technical validation (e.g. [[project_azure_real_discovery_integration]]), applied here to regulatory-fact accuracy risk instead of infrastructure-availability risk.

## 3. Dependency

`wafprofile` depends on `internal/wafcatalog` only (to validate that every attack-vector ID a profile references actually exists in the real catalog) — not on `wafval` (no evidence-evaluation logic here; this phase is a bundling/reference layer, not a claim evaluator) and not on any other WAF-phase package (`wafpolicygap`, `wafevasion`, `wafapiflow`, `wafbotabuse`, `waforigin`, `wafdetection`). This mirrors `waforigin`'s precedent of a read-only, ID-level cross-reference into `wafcatalog` without re-deriving any of its content.

## 4. Types

### 4.1 Profile

```go
type ProfileKind string
const (
    ProfileIndustry ProfileKind = "industry"
    ProfileRegional ProfileKind = "regional"
)

type Profile struct {
    ID                   string
    Name                 string
    Kind                 ProfileKind
    AttackVectorIDs      []string
    ComplianceReferences []ComplianceReference
    Rationale            string
    Provenance           string
}

func NewProfile(id string, name string, kind ProfileKind, attackVectorIDs []string, complianceReferences []ComplianceReference, rationale string, provenance string) (Profile, error)
```
Validation: `id`/`name`/`rationale`/`provenance` non-empty; `kind` is `ProfileIndustry` or `ProfileRegional`; `attackVectorIDs` has at least 1 entry and no empty/duplicate ID; `complianceReferences` has at least 1 entry and each one must itself be valid (§4.2's own validation, re-checked here so a caller cannot assemble an invalid `ComplianceReference` by struct-literal and skip `NewComplianceReference`).

### 4.2 ComplianceReference

```go
type VerificationStatus string
const (
    Verified   VerificationStatus = "verified"
    Unverified VerificationStatus = "unverified"
)

type ComplianceReference struct {
    Framework          string
    VerificationStatus VerificationStatus
    Note               string
    SourceURL          string
}

func NewComplianceReference(framework string, status VerificationStatus, note string, sourceURL string) (ComplianceReference, error)
```
Validation: `framework` non-empty; `status` is `Verified` or `Unverified`; `note` non-empty (every claim must say what is and is not being asserted, regardless of status); `sourceURL` optional (empty allowed — not every framework reference has a single canonical URL). No separate rule forces `Unverified` specifically to explain itself more than `Verified` does — `note` is mandatory either way, so the discipline is structural rather than status-conditional (simpler to validate, and nothing stops a future `Verified` entry from needing its own explanation of what was checked).

### 4.3 Catalog cross-reference

```go
func ValidateAgainstCatalog(profile Profile, catalog []wafcatalog.AttackVector) error
```
Builds a set of `catalog`'s real `AttackVector.ID` values and returns an error naming the first `profile.AttackVectorIDs` entry that is not in that set (a typo'd or retired vector ID). Returns `nil` when every referenced ID exists.

## 5. Seed catalog

`AudspectWAFProfileCatalog() ([]Profile, error)` calls `wafcatalog.AudspectWAFAttackCatalog()` for the real vector list, builds the 6 profiles below referencing only IDs confirmed to exist in that catalog (cross-checked directly against `orchestrator/internal/wafcatalog/catalog_*.go` in this session: `SQLI-001..003`, `XSS-001..003`, `PATHTRAV-001..002`, `SSRF-001..002`, `FILEUP-001..002`, `HTTPPARSE-001..002`, `API-001..003`, `AUTH-001..003`, `RATE-001..002`, `CACHE-001..002`, `POLICY-001..002`), validates each via `ValidateAgainstCatalog`, and returns an error if validation fails for any of them (a defensive check against the catalog changing underneath this package, not expected to ever fire against the seed data itself).

Every `ComplianceReference` below is `Unverified`. Framework names and general scope are drawn from this session's research; specific clause/circular/rule numbers surfaced by that research are deliberately omitted from the catalog data (they appear only in this spec's own citations, as research provenance, never as an asserted fact inside a `ComplianceReference.Note`).

| ID | Kind | Name | AttackVectorIDs | ComplianceReferences (framework — note) |
|---|---|---|---|---|
| WAFPROFILE-BFSI | industry | Banking, Financial Services and Insurance | SQLI-001, AUTH-001, AUTH-003, API-001, RATE-001 | "RBI Cyber Security Framework for banks" — framework name and general existence only, drawn from secondary/vendor sources in this session's research; no specific circular number or clause verified against RBI's own text. / "PCI-DSS" — framework name only; payment-card-data scope not independently verified in this session. |
| WAFPROFILE-NBFC | industry | Non-Banking Financial Companies | API-002, AUTH-001, SQLI-002, FILEUP-001 | "RBI IT Governance requirements for NBFCs" — framework name and general applicability (asset-threshold-gated) only, from secondary sources; no specific circular number verified against RBI's own text. |
| WAFPROFILE-MANUFACTURING | industry | Manufacturing and OT-adjacent critical infrastructure | SSRF-002, PATHTRAV-001, HTTPPARSE-001 | "CERT-In Cyber Security Directions" — framework name and the widely-reported 6-hour incident-reporting requirement only; this session's research found no manufacturing-specific or WAF-specific clause, and that gap is itself disclosed, not filled in. |
| WAFPROFILE-HEALTHCARE | industry | Healthcare | AUTH-002, API-003, CACHE-001, SQLI-003 | "India DPDP Act 2023 (+ Rules)" — framework name and general existence of technical-safeguard rules only; specific rule numbers and retention periods surfaced by research are not asserted here, pending primary-source confirmation. / "Ayushman Bharat Digital Mission (ABDM)" — framework name only; specific technical-specification clauses not verified. |
| WAFPROFILE-INDIA | regional | India (cross-industry baseline) | SQLI-001, XSS-001, AUTH-001, RATE-002 | "India DPDP Act 2023" — nationwide applicability asserted at the framework-name level only. / "CERT-In Cyber Security Directions" — nationwide incident-reporting framework, name-level only. |
| WAFPROFILE-UAE | regional | United Arab Emirates (cross-industry baseline) | SQLI-002, XSS-002, SSRF-001, API-002 | "UAE Information Assurance Standards (NESA-origin)" — framework name only; this session's research found disagreement across sources on the current overseeing authority's name, which is disclosed here rather than resolved by picking one. |

## 6. Acceptance gate

1. `NewComplianceReference` rejects empty `framework`/`note`, and a `status` that is not `Verified`/`Unverified`.
2. `NewProfile` rejects empty `id`/`name`/`rationale`/`provenance`, an invalid `kind`, an empty/duplicate-containing `attackVectorIDs`, and an empty `complianceReferences`; it also rejects a `complianceReferences` entry that is itself invalid (empty `framework` or `note`), re-validating rather than trusting the caller already called `NewComplianceReference`.
3. `ValidateAgainstCatalog` returns `nil` for a profile whose every `AttackVectorIDs` entry exists in the given catalog slice, and a non-nil error naming the first missing ID otherwise.
4. `AudspectWAFProfileCatalog` returns exactly 6 profiles (4 `ProfileIndustry` + 2 `ProfileRegional`), each constructing without error and passing `ValidateAgainstCatalog` against the real `wafcatalog.AudspectWAFAttackCatalog()` output.
5. Every seed profile's every `ComplianceReference` has `VerificationStatus == Unverified` and a non-empty `Note` — the catalog never asserts a framework claim as `Verified` in this phase, since this session was unable to confirm any of them against a primary regulatory source.

## 7. Deferred

- Primary-source verification of any specific regulatory clause, circular number, or control ID — explicitly left for a future pass that can access and cite the regulator's own text directly (RBI, CERT-In, UAE Cybersecurity Council / TDRA, MeitY), not fabricated here.
- Cross-referencing `wafpolicygap`/`wafevasion`/`wafapiflow`/`wafbotabuse`/`waforigin` vector-shaped scenarios into profiles — this phase scopes to `wafcatalog`'s core attack-vector catalog only, kept deliberately narrow given the dependency-minimalism pattern established by every prior phase.
- Any scoring/weighting of profiles against actual assessment results — this phase is a reference/bundling layer only, with no evaluation function of its own.
- Expanding beyond the 6 named profiles from `waf.txt`.
