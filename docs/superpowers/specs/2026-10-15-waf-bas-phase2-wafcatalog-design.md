# WAF BAS Mastery Phase 2: Versioned Attack-Test Catalog — Design Spec

## 1. Goal

Phase 2 is the second slice of the WAF BAS Mastery roadmap (`waf.txt`, §3, Phase 2: "Core attack-prevention mastery — build a comprehensive, versioned attack test library mapped to OWASP and relevant CWE/ATT&CK references where applicable"). It builds the **attack-test catalog** that sits on top of Phase 1's vendor-neutral evidence contract (`internal/wafval`, merged, `c3b8acff`): a versioned, standards-mapped library of attack vectors, each carrying a malicious request and — wherever one legitimately exists — its benign lookalike, so that both missed attacks and false positives can be measured from the same catalog entry.

Phase 1 deliberately deferred two things: the full attack-payload library (this phase) and the lab adapter that would drive real requests at a controlled application (`docs/superpowers/specs/2026-10-15-waf-bas-phase1-wafval-design.md`, §14). Phase 2 stays fixture-backed, same as Phase 1 — it proves the catalog's own correctness and its wiring into `wafval`'s evidence contract, not that a real WAF blocks anything. That second claim stays a distinct, later milestone with its own acceptance gate.

The core discipline, carried over from Phase 1 and restated here because it governs this phase's own validation claims: **fixture tests prove the catalog and its evidence-processing logic behave correctly; they do not prove that a real WAF blocks the attacks.** Nothing in this phase's output may be read or reported as empirically verified WAF effectiveness.

## 2. Scope Boundary

| Component | Phase 2 decision |
|---|---|
| Attack catalog | Build: versioned, standards-mapped, vendor-neutral |
| Standards mapping | OWASP WSTG, OWASP Top 10, OWASP API Security Top 10, CWE; ATT&CK only where genuinely relevant |
| Coverage breadth | Injection, XSS, path traversal, SSRF, file upload, HTTP parser discrepancies, API abuse, auth abuse, rate limiting, cache weaknesses, policy misconfiguration |
| Known-good/known-bad pairing | Structural: an `AttackVector` owns both legs |
| Evidence-contract integration | Each leg resolves to a `wafval.Expectation`; catalog never derives a verdict itself |
| Validation | Fixture-backed only — deterministic `[]wafval.CollectionResult` fixtures |
| Real execution | Out of scope — ModSecurity/OWASP CRS deployment, real HTTP, any WAF vendor adapter |
| Claims this phase may support | "The catalog is internally correct and wired correctly into the evidence contract" — never "a real WAF blocks these" |

## 3. Package and Dependency Direction

New sibling package `internal/wafcatalog`, same tier as `internal/wafval`. It depends *on* `wafval` (`ClaimType`, `Expectation`, `EvaluateClaim`, `Result`) for the evidence-contract types; `wafval` never depends on it — the same one-way relationship `adefficacy` has with `controlval`. Pure Go: stdlib only, no HTTP client, no vendor SDK, no ModSecurity/CRS-specific code. This keeps Phase 2 as fixture-provable as Phase 1 and keeps the eventual lab adapter free to depend on both `wafval` and `wafcatalog` without either depending back on it.

## 4. The Catalog Entry Model

A single `AttackVector` is one versioned, standards-mapped test definition. It owns both the malicious request and — wherever one legitimately exists — its benign counterpart, as a structural guarantee rather than a convention two separate catalog entries could drift out of.

```go
package wafcatalog

// AttackFamily is one of the eleven breadth categories this phase's seed
// catalog must cover (waf.txt §3, Phase 2 coverage breadth).
type AttackFamily string

const (
	FamilySQLInjection    AttackFamily = "sql_injection"
	FamilyXSS             AttackFamily = "xss"
	FamilyPathTraversal   AttackFamily = "path_traversal"
	FamilySSRF            AttackFamily = "ssrf"
	FamilyFileUpload      AttackFamily = "file_upload"
	FamilyHTTPParser      AttackFamily = "http_parser_discrepancy"
	FamilyAPIAbuse        AttackFamily = "api_abuse"
	FamilyAuthAbuse       AttackFamily = "auth_abuse"
	FamilyRateLimit       AttackFamily = "rate_limit"
	FamilyCacheWeakness   AttackFamily = "cache_weakness"
	FamilyPolicyMisconfig AttackFamily = "policy_misconfig"
)

type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
)

// RequestTemplate describes one request shape without executing it: enough
// for a human to audit the test case, and enough for a future lab adapter to
// build the real HTTP request from. It never carries live infrastructure
// details (hostnames, credentials, environment-specific paths).
type RequestTemplate struct {
	Method          string // e.g. "GET", "POST"
	Path            string
	PayloadLocation string // e.g. "query:q", "body:json:username", "header:X-Forwarded-For" -- empty when the request shape itself is the test (e.g. verb tampering)
	Payload         string
	Description     string // required: what this request represents and why
}

// StandardsMapping ties a vector to the external references waf.txt requires.
// At least one of CWEIDs/WSTGCategory/Top10Category/APITop10Category must be
// non-empty -- every vector must map to something. ATTACKTechniques is always
// optional, used only where the mapping is genuinely relevant (waf.txt §3).
type StandardsMapping struct {
	CWEIDs           []string // e.g. []string{"CWE-89"} -- each must match `CWE-\d+`
	WSTGCategory     string   // OWASP Web Security Testing Guide, e.g. "WSTG-INPV-05"
	Top10Category    string   // OWASP Top 10, e.g. "A03:2021-Injection"
	APITop10Category string   // OWASP API Security Top 10, e.g. "API3:2023-Broken Object Property Level Authorization"
	ATTACKTechniques []string // e.g. []string{"T1190"} -- optional
}

// AttackVector is one versioned catalog entry. BenignCounterpart is nil only
// when NoBenignCounterpartReason explains why no legitimate lookalike exists
// for this vector -- never a silent omission.
type AttackVector struct {
	ID                        string // stable, e.g. "SQLI-001"
	Version                   int    // >= 1
	Family                    AttackFamily
	Name                      string
	Severity                  Severity
	Preconditions             string // what must be true about the target for this test to apply
	Malicious                 RequestTemplate
	BenignCounterpart         *RequestTemplate
	NoBenignCounterpartReason string
	Standards                 StandardsMapping
	Provenance                string // e.g. "OWASP CRS rule 942100" or "manually authored from CWE-89"
}
```

## 5. Construction-Time Validation

`NewAttackVector(...) (AttackVector, error)` validates at construction, never at render time — same discipline as `webgwefficacy.NewIndustryProfile`:

- `ID` non-empty.
- `Version >= 1`.
- `Family` is one of the eleven known constants.
- `Severity` is one of the four known constants.
- `Malicious.Method`, `Malicious.Path`, and `Malicious.Description` non-empty. (`PayloadLocation`/`Payload` may be empty — a verb-tampering or HTTP-parser-discrepancy vector's "attack" can be the request shape itself, not a payload value.)
- Every `Standards.CWEIDs` entry matches `^CWE-\d+$`.
- `Standards` has at least one of `CWEIDs`, `WSTGCategory`, `Top10Category`, `APITop10Category` non-empty.
- `Provenance` non-empty.
- Exactly one of `BenignCounterpart != nil` or `NoBenignCounterpartReason != ""` holds — never both, never neither. When `BenignCounterpart != nil`, its `Method`, `Path`, and `Description` are validated the same as `Malicious`'s.

## 6. Known-Good/Known-Bad Pairing

waf.txt (§5) requires measuring both missed attacks and false positives from "known-good and known-bad test pairs." Rather than two separately-tracked catalog entries linked by a soft ID reference (which two entries could drift apart on independent edits), one `AttackVector` owns both legs directly (§4). A vector that has no legitimate lookalike — some SSRF probes, for instance, have no benign equivalent worth testing — declares that explicitly via `NoBenignCounterpartReason` rather than by omission, so a catalog audit can distinguish "no counterpart needed, here's why" from "someone forgot."

## 7. Evidence-Contract Integration

The catalog never derives a verdict itself — that stays `wafval`'s job entirely. Each leg of an `AttackVector` resolves to one `wafval.Expectation`: the malicious leg always maps to `wafval.ClaimPrevention` ("should be blocked"); the benign counterpart, when present, always maps to `wafval.ClaimFalsePositive` ("should be allowed"). `policyBasis` is supplied by the caller (the fixture harness today, a lab adapter later) because the catalog is deployment-neutral and cannot know what policy is actually in force; `PolicyVerified` is always returned `false` from the catalog, since only the actual evidence-collecting adapter can confirm a policy was in force.

```go
type AttackLeg string

const (
	LegMalicious AttackLeg = "malicious"
	LegBenign    AttackLeg = "benign"
)

// LegExpectation pairs one leg's request template with the wafval.Expectation
// it resolves to, so a test harness can build the request, collect evidence,
// and call wafval.EvaluateClaim without re-deriving the claim mapping itself.
type LegExpectation struct {
	VectorID    string
	Leg         AttackLeg
	Request     RequestTemplate
	Expectation wafval.Expectation
}

// Expectations returns the malicious leg's LegExpectation, plus the benign
// leg's when BenignCounterpart is set. policyBasis is caller-supplied -- the
// catalog does not know what policy is actually deployed.
func (v AttackVector) Expectations(policyBasis string) []LegExpectation
```

Phase 3 (`waf.txt` §3, "Configuration and policy-gap testing") reuses `wafval.Pair`/`EvaluatePolicyGap` for baseline-vs-weakened-policy comparisons — a two-leg comparison already built in Phase 1. Phase 2's `policy_misconfig` family vectors stay single-leg (`ClaimPrevention`/`ClaimFalsePositive`, same as every other family): a detection-only-mode misconfiguration already surfaces as a plain `DetectedButAllowed` verdict under `ClaimPrevention`, with no need for the pair machinery. Supplying both legs of an actual baseline/weakened comparison is Phase 3's job, not this phase's.

## 8. Catalog-Wide Validation

`NewAttackVector` cannot see sibling entries, so uniqueness is checked once, across the whole catalog:

```go
// ValidateCatalog rejects a catalog containing two entries with the same ID.
// A catalog snapshot holds exactly one version per ID; Version documents how
// many times that ID's definition has evolved, not a invitation to keep
// multiple versions live simultaneously.
func ValidateCatalog(vectors []AttackVector) error
```

"Deterministic test results" (`waf.txt`'s quality-gate list) is not a separate runtime gate — it falls out of `AttackVector`/`LegExpectation`/`wafval.EvaluateClaim` all being pure functions over their inputs. It is proven by test assertion (same fixture evidence run twice produces an identical `Result`), not by construction-time validation code.

## 9. Seed Catalog Breadth

This phase ships **2–3 hand-authored vectors per family**, across all eleven families named in §2 — roughly 25–30 `AttackVector` entries total, assembled by `AudspectWAFAttackCatalog() ([]AttackVector, error)` (mirrors `webgwefficacy.AudspectWebGWCoverageReport`), validated via `ValidateCatalog` before being returned. This proves every family's standards-mapping and evidence-contract wiring genuinely works; it is not a claim of exhaustive coverage. "Comprehensive" (`waf.txt`'s own word) stays the long-run target of later catalog-expansion work, not this phase's exit bar — the same honesty Phase 1 held about its own minimal attack-library slice.

One worked example (SQL injection, with its benign counterpart):

```go
NewAttackVector(
	"SQLI-001", 1, FamilySQLInjection,
	"Classic UNION-based SQL injection in a search parameter", SeverityCritical,
	"Target exposes a search endpoint backed by a SQL database",
	RequestTemplate{
		Method: "GET", Path: "/search",
		PayloadLocation: "query:q",
		Payload:         "' UNION SELECT NULL,NULL,NULL--",
		Description:     "UNION-based injection attempting column enumeration via a search query parameter",
	},
	&RequestTemplate{
		Method: "GET", Path: "/search",
		PayloadLocation: "query:q",
		Payload:         "laptop stand",
		Description:     "Ordinary search term a legitimate user would submit",
	},
	"", // NoBenignCounterpartReason unused -- BenignCounterpart is set
	StandardsMapping{
		CWEIDs:        []string{"CWE-89"},
		WSTGCategory:  "WSTG-INPV-05",
		Top10Category: "A03:2021-Injection",
	},
	"Manually authored from CWE-89 / OWASP WSTG-INPV-05",
)
```

An example with no legitimate counterpart (an SSRF probe against cloud metadata, where no benign request shares that shape):

```go
NewAttackVector(
	"SSRF-002", 1, FamilySSRF,
	"Cloud metadata endpoint SSRF via URL-fetch parameter", SeverityCritical,
	"Target exposes a URL-fetch/webhook/import feature that accepts a user-supplied URL",
	RequestTemplate{
		Method: "POST", Path: "/api/fetch-url",
		PayloadLocation: "body:json:url",
		Payload:         "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
		Description:     "Attempts to reach cloud-provider instance metadata via a user-controlled URL-fetch feature",
	},
	nil,
	"No legitimate client request targets the cloud metadata address range; there is no meaningful benign lookalike for this vector",
	StandardsMapping{
		CWEIDs:        []string{"CWE-918"},
		WSTGCategory:  "WSTG-INPV-19",
		Top10Category: "A10:2021-Server-Side Request Forgery",
	},
	"Manually authored from CWE-918 / OWASP WSTG-INPV-19",
)
```

## 10. Testing Approach

Fixture-backed, mirroring `wafval`'s own test style: hand-built `[]wafval.CollectionResult` per scenario, feeding a `LegExpectation`'s `Expectation` into `wafval.EvaluateClaim`, asserting the derived `Result.Verdict`/`Completeness`/`Confidence`. No real HTTP, no ModSecurity, no `httptest` server — this phase proves the catalog and its wiring, not a live control.

## 11. Acceptance Gate

1. `NewAttackVector` rejects an empty `ID`, a `Version < 1`, an unknown `Family`, an unknown `Severity`, and a malformed CWE ID.
2. `NewAttackVector` rejects a vector with both `BenignCounterpart` set and `NoBenignCounterpartReason` non-empty, and one with neither set.
3. `NewAttackVector` rejects a vector whose `Standards` has none of `CWEIDs`/`WSTGCategory`/`Top10Category`/`APITop10Category` set.
4. `NewAttackVector` rejects an empty `Provenance`.
5. `ValidateCatalog` rejects two entries sharing the same `ID`.
6. `AttackVector.Expectations(policyBasis)` returns exactly one `LegExpectation` (malicious, `ClaimPrevention`) when `BenignCounterpart` is nil, and exactly two (malicious + benign, `ClaimPrevention` + `ClaimFalsePositive`) when it is set.
7. A malicious leg's `LegExpectation.Expectation`, fed into `wafval.EvaluateClaim` against fixture evidence showing the request blocked, yields `VerdictBlocked`.
8. The same vector's benign leg, fed into `wafval.EvaluateClaim` against fixture evidence showing the request allowed, yields `VerdictAllowed`.
9. A malicious leg against fixture evidence showing the request allowed and undetected yields `VerdictMissed` — a real catalog-driven negative finding, not merely an evaluator unit test.
10. A benign leg against fixture evidence showing the request blocked yields `VerdictIncorrectlyBlocked` — the catalog genuinely surfaces a false positive.
11. `AudspectWAFAttackCatalog()` returns entries covering all eleven families, passes `ValidateCatalog`, and every entry individually passes `NewAttackVector`'s own validation (proven by construction, since the seed function builds entries through `NewAttackVector`).
12. Running the same fixture scenario twice produces identical `Result` values (determinism).

## 12. Explicitly Deferred

- ModSecurity/OWASP CRS deployment and real HTTP execution against the catalog.
- Any commercial WAF vendor adapter.
- Any customer-targeted execution.
- Claims that any vector in this catalog has been empirically verified against a real WAF.
- The two-leg baseline/weakened policy-gap comparison itself (Phase 3; `wafval.Pair`/`EvaluatePolicyGap` already exist for it).
- Expanding the seed catalog toward genuinely comprehensive breadth (ongoing catalog-expansion work, not this phase's exit bar).
