# DLP-CLS — Classification Efficacy Design

## Intent and why

DLP Mastery's DLP-POL slice proved whether a DLP policy is *configured* as declared. It never asked, and cannot answer, whether the underlying content was *classified* correctly in the first place — a correctly configured policy applied to a misclassified document still produces the wrong outcome. `reporting/dlp.go`'s own doc comment says this outright: "Classification/telemetry/response outcomes are deliberately absent, not empty placeholders: they require evidence sources that don't exist yet." DLP-CLS builds that evidence source.

Per the user's locked execution order (`dlp.txt`), DLP-CLS is the second of three DLP evaluation dimensions sharing one foundation: DLP-POL (done), DLP-CLS (this spec), DLP-ENF (not started). The objective, carried over unchanged from DLP-POL: not to maximize scenario count, but to make Audspect capable of proving whether a classification engine works, where it fails, and how confidently that conclusion can be defended.

The headline deliverable `dlp.txt` names directly: *"Precision, recall and false-negative rate on a representative, labeled synthetic test corpus. Report unsupported and untested formats separately."*

## Goals

All six concerns from `dlp.txt`'s DLP-CLS list get a testable behavior, explicit evidence requirements, and explicit verdict criteria in this spec:

1. Known-sensitive samples, benign near-matches, and ambiguous samples — the ground-truth corpus's own content model.
2. Exact-data matching and custom Indian/UAE identifier patterns — a corpus content requirement, not a separate evaluator.
3. Missing, incorrect, inherited, and manually changed sensitivity labels — **label lifecycle**, kept structurally separate from classifier accuracy (Slice 2).
4. OCR, supported archives, nested documents, and multilingual content — a corpus content requirement plus the Unsupported/coverage outcome path (Slice 1).
5. Classification confidence thresholds and unsupported formats — the coverage/eligibility model (Slice 1).
6. False negatives, false positives, and inconsistent classification between channels — the per-sample accuracy model and its aggregate metrics (Slice 1). Cross-channel consistency is scoped as a Slice-1 corpus-level comparison, not a new evaluator: the same sample submitted through two channels produces two independent `ClassificationEvidence` records, compared as an ordinary pair of per-sample verdicts.

## Non-goals

- Building a real classification engine, OCR pipeline, or pattern-matching library. DLP-CLS evaluates a third-party product's classification decisions against known ground truth; it never classifies anything itself.
- Driving classification from a live vendor connector in this spec's buildable scope. Exactly like DLP-POL, no vendor tenant access exists today — every provider shipped here is fixture-backed (`SourceFixture`), never `SourceLive`.
- Policy evaluation (DLP-POL's job) or enforcement action (DLP-ENF's, not started). A classification failure must never be inferred from an enforcement outcome, and a blocked transfer must never be read as proof classification was correct — the four dimensions (classification / policy / enforcement / telemetry) stay strictly separable, per the user's own locked boundary table.
- Wiring DLP-CLS into the scenario engine's per-step automatic-verification pipeline (`scenario.ExpectedDetection`/`reporting.StepEvidence`/`dlpVerifier`). That pipeline verifies a live simulation step's outcome; DLP-CLS benchmarks a corpus against a classification engine's decisions, a different shape of question entirely. Consumption (an API handler, a report) is deferred, exactly like DLP-POL's own vendor-connector consumption wiring — logged as a known gap, not built here.

## Anti-goals

- Never let a vendor's observed classification influence ground truth. Ground truth is fixed at corpus-authoring time; contaminating it with the thing being measured would invalidate every metric this package produces.
- Never collapse "no sensitive label applied" into a single meaning. The product might explicitly classify as benign, fail to inspect the file, lack format support, fail to return evidence, or apply a label without exposing the underlying decision — five different evidence states, each requiring its own path, never auto-resolved to a false negative or true negative.
- Never let an unsupported-format sample improve a product's apparent accuracy by exiting the evaluation silently. Unsupported/Inconclusive/NotTested samples are excluded from the precision/recall/confusion-matrix denominator, but their counts are always reported alongside the metrics — a product that simply refuses to inspect difficult files must never look more accurate for it.
- Never force DLP-CLS into `internal/dlppolicy`'s types because the pattern looks similar. The architectural discipline (Expectation/Evidence/Verify quartets, an independently-defined verdict vocabulary, fixture-only `EvidenceSource`, provenance tracking) is reused; the domain model is not. `internal/dlpclassify` imports nothing from `internal/dlppolicy`, and vice versa.
- Never report a rate (precision, recall, false-positive rate, false-negative rate) computed from a zero denominator as if it were a real 0% or defined value. A product that never fired a positive classification at all is a fundamentally different finding from "fired many positives and all were wrong" — collapsing both into `0.0` would misrepresent the first as the second.

## Constraints

- New standalone package `internal/dlpclassify`. No import of `internal/dlppolicy`, `internal/dlpfixture`, `internal/scenario`, or `internal/reporting`. Borrows the structural pattern (`Expectation`/`Evidence`/`EvidenceProvider`/`Verify...` quartets, fixture-labeling discipline, provenance) from `dlppolicy`; defines its own independent types throughout, per the user's explicit instruction.
- Fixtures prove evaluator correctness, not real product accuracy. Every provider shipped in this spec's buildable scope sets `Source: SourceFixture`; a `SourceLive` value is reserved, unused, same convention as `dlppolicy`.
- Multi-class, not binary-only. `SensitivityClass` is an open string type (corpus-author-defined values like `"pii-aadhaar"`, `"pii-emirates-id"`, `"pci"`, `"phi"`), not a closed binary enum — a product that classifies a PCI sample as PII is a confusion-matrix off-diagonal cell (`Misclassified`), never silently counted as a correct positive.
- Missing evidence is not a pass. `LabelOnly`, `InspectionFailed`, `NoEvidenceReturned`, and an ambiguous-by-design sample all resolve to `Inconclusive`; `UnsupportedFormat` resolves to its own `Unsupported` outcome, distinct from `Inconclusive` — a coverage finding, not an accuracy finding, per `dlp.txt`'s own instruction to "report a coverage limitation rather than falsely claiming a broken control."
- Only `Evaluated` samples (outcomes `TruePositive`/`FalsePositive`/`FalseNegative`/`TrueNegative`/`Misclassified`) enter the accuracy denominator. `Inconclusive`/`Unsupported`/`NotTested` counts are always reported alongside the metrics, never silently dropped.
- Corpus quality is independently testable. A `ValidateCorpus` function (mirroring `dlpfixture.ValidateCatalog`'s precedent) rejects duplicate sample IDs, dangling transformation references, and duplicate-content leakage (two different sample IDs sharing one content hash) before any evaluation runs.

## Builder's call

### Package layout

```
internal/dlpclassify/
  types.go        -- SensitivityClass, ClassificationDecision, DLPCLSOutcome, DLPCLSVerdict,
                     EvidenceSource, Provenance, Rate (independently defined; no cross-import)
  corpus.go        -- GroundTruth, NewGroundTruth (validating constructor), ValidateCorpus (Slice 1)
  sample.go        -- ClassificationEvidence, ClassificationEvidenceProvider,
                     FixtureClassificationEvidenceProvider, VerifyClassificationSample (Slice 1)
  aggregate.go      -- CorpusMetrics, AggregateCorpusMetrics (Slice 1)
  labellifecycle.go -- LabelExpectation, LabelEvidence, VerifyLabelExpectation (Slice 2)
```

### Foundation types (`types.go`)

```go
package dlpclassify

import "time"

// SensitivityClass is an open, corpus-author-defined classification
// label -- never a closed enum, so a confusion matrix can distinguish
// "classified as the wrong sensitive type" from "classified correctly."
// SensitivityClassNone means the sample is intentionally benign.
// SensitivityClassAmbiguous is reserved for a sample whose own ground
// truth declares it cannot be scored against a single right answer.
type SensitivityClass string

const (
	SensitivityClassNone      SensitivityClass = "none"
	SensitivityClassAmbiguous SensitivityClass = "ambiguous"
)

// ClassificationDecision is what the evaluated product actually
// reported for one sample -- never collapsed to a bare label, because
// "no sensitive label applied" has five distinguishable causes.
type ClassificationDecision string

const (
	// DecisionExplicitSensitive: the product applied a sensitive
	// classification and exposed it. The only decision that can
	// produce a TruePositive/FalsePositive/Misclassified outcome.
	DecisionExplicitSensitive ClassificationDecision = "explicit-sensitive"
	// DecisionExplicitBenign: the product explicitly classified the
	// sample as non-sensitive. The only decision that can produce a
	// TrueNegative/FalseNegative outcome.
	DecisionExplicitBenign ClassificationDecision = "explicit-benign"
	// DecisionLabelOnly: a label was applied but the underlying
	// classification decision/rationale was never exposed -- cannot
	// be scored as a classifier outcome.
	DecisionLabelOnly ClassificationDecision = "label-only"
	// DecisionInspectionFailed: the product attempted but failed to
	// inspect the file (parse error, timeout, corruption, etc.).
	DecisionInspectionFailed ClassificationDecision = "inspection-failed"
	// DecisionUnsupportedFormat: the product explicitly does not
	// support this format or operation -- a coverage limitation, not
	// a classification failure.
	DecisionUnsupportedFormat ClassificationDecision = "unsupported-format"
	// DecisionNoEvidenceReturned: the product gave no usable evidence
	// either way.
	DecisionNoEvidenceReturned ClassificationDecision = "no-evidence-returned"
)

// DLPCLSOutcome is this package's own independently-defined verdict
// vocabulary -- structurally parallel to dlppolicy.DLPPOLVerdict, but
// never the same type, and never imported from there.
type DLPCLSOutcome string

const (
	OutcomeTruePositive  DLPCLSOutcome = "true-positive"
	OutcomeFalsePositive DLPCLSOutcome = "false-positive"
	OutcomeFalseNegative DLPCLSOutcome = "false-negative"
	OutcomeTrueNegative  DLPCLSOutcome = "true-negative"
	// OutcomeMisclassified: a confusion-matrix off-diagonal cell --
	// the sample IS sensitive, the product DID classify it as
	// sensitive, but as the wrong SensitivityClass. Never collapsed
	// into TruePositive.
	OutcomeMisclassified DLPCLSOutcome = "misclassified"
	OutcomeInconclusive  DLPCLSOutcome = "inconclusive"
	OutcomeUnsupported   DLPCLSOutcome = "unsupported"
	OutcomeNotTested     DLPCLSOutcome = "not-tested"
)

// evaluated reports whether outcome counts toward the accuracy
// denominator (precision/recall/confusion matrix).
func (o DLPCLSOutcome) evaluated() bool {
	switch o {
	case OutcomeTruePositive, OutcomeFalsePositive, OutcomeFalseNegative, OutcomeTrueNegative, OutcomeMisclassified:
		return true
	default:
		return false
	}
}

type DLPCLSVerdict struct {
	Outcome DLPCLSOutcome `json:"outcome"`
	Reason  string        `json:"reason,omitempty"` // required whenever Outcome is not TruePositive/TrueNegative
}

type EvidenceSource string

const (
	SourceFixture EvidenceSource = "recorded-fixture"
	SourceLive    EvidenceSource = "live" // reserved; unused by any provider in this spec's buildable scope
)

type ProvenanceKind string

const (
	ProvenanceObserved ProvenanceKind = "observed"
	ProvenanceInferred ProvenanceKind = "inferred"
)

type Confidence string

const (
	ConfidenceHigh   Confidence = "high"
	ConfidenceMedium Confidence = "medium"
	ConfidenceLow    Confidence = "low"
)

type Provenance struct {
	Kind       ProvenanceKind `json:"kind"`
	Confidence Confidence     `json:"confidence"`
	Basis      string         `json:"basis,omitempty"`
}

// Rate is a ratio that may be undefined (zero denominator). A rate
// with Defined == false must never be reported as 0 -- "never fired a
// positive classification" and "fired many, all wrong" are different
// findings that a bare 0.0 would conflate.
type Rate struct {
	Value   float64 `json:"value"`
	Defined bool    `json:"defined"`
}

type TimeWindow struct{ Start, End time.Time }
```

### Ground truth and corpus validation (`corpus.go`)

```go
package dlpclassify

// GroundTruth is one labeled sample's fixed, corpus-authored truth --
// established once at authoring time, never influenced by any
// product's observed classification. Mirrors dlpfixture.Fixture's
// validate-at-construction discipline.
type GroundTruth struct {
	SampleID  string `json:"sampleId"`
	ContentHash string `json:"contentHash"` // hash of the actual sample bytes, computed once at authoring time -- enables duplicate-leakage detection without the corpus storing real file content in Go source
	IntendedClass       SensitivityClass `json:"intendedClass"`
	Rationale           string           `json:"rationale"`           // required: why this sample belongs to IntendedClass
	Format              string           `json:"format"`              // e.g. "pdf", "scanned-image", "zip-nested", "csv"
	TransformationOf    string           `json:"transformationOf,omitempty"` // SampleID this is a transformed/split/reformatted variant of; empty if this IS a source sample
	AdjudicationPolicy  string           `json:"adjudicationPolicy,omitempty"` // required, non-empty, when IntendedClass == SensitivityClassAmbiguous
	Note                string           `json:"note,omitempty"`
}

// NewGroundTruth validates at construction, never at verify time:
// SampleID/ContentHash/Rationale/Format non-empty; AdjudicationPolicy
// non-empty iff IntendedClass == SensitivityClassAmbiguous.
func NewGroundTruth(sampleID, contentHash string, intendedClass SensitivityClass, rationale, format, transformationOf, adjudicationPolicy, note string) (GroundTruth, error)

// ValidateCorpus checks cross-sample invariants NewGroundTruth cannot
// see alone: a duplicate SampleID, a TransformationOf reference to a
// SampleID absent from the corpus, and duplicate-content leakage (two
// different SampleIDs sharing one ContentHash -- flagged whether their
// IntendedClass agrees, a sheer duplicate, or disagrees, a
// contradictory label on the same underlying content).
func ValidateCorpus(truths []GroundTruth) error
```

**Scope boundary (what corpus validation can and cannot assess):** `ValidateCorpus` checks structural invariants over metadata it holds. It cannot detect "unintended exposure of sensitive-looking test markers" in the actual sample bytes, because `GroundTruth` is metadata only and never stores real file content in Go source — the same synthetic-value discipline `dlpfixture` already follows. Ensuring every authored sample is synthetic, not realistic-looking production data, is a corpus-authoring review responsibility, not a runtime check this package performs.

### Per-sample evaluator (`sample.go`)

```go
package dlpclassify

import "time"

type ClassificationEvidence struct {
	SampleID           string           `json:"sampleId"`
	// Channel names which submission path produced this evidence --
	// e.g. "web-upload", "email-attachment", "endpoint-usb". Empty
	// when the corpus's evaluation doesn't distinguish channels.
	// Carries Concern 6 (cross-channel consistency): the SAME
	// SampleID evaluated through two channels produces two
	// independent ClassificationEvidence records, one per Channel --
	// never two different SampleIDs (which ValidateCorpus's
	// duplicate-content check would correctly reject as leakage).
	Channel            string           `json:"channel,omitempty"`
	Decision           ClassificationDecision `json:"decision"`
	ObservedClass       SensitivityClass `json:"observedClass,omitempty"` // populated only when Decision == DecisionExplicitSensitive
	MatchedPattern      string           `json:"matchedPattern,omitempty"`
	Confidence          float64          `json:"confidence,omitempty"`
	ConfidenceReported  bool             `json:"confidenceReported"` // distinguishes "0.0 confidence reported" from "no confidence value available"
	Timestamp           time.Time        `json:"timestamp"`
	Source              EvidenceSource   `json:"source"`
	Provenance          Provenance       `json:"provenance"`
}

type ClassificationEvidenceProvider interface {
	ClassificationEvidenceFor(sampleID, channel string, window TimeWindow) ([]ClassificationEvidence, error)
}

type FixtureClassificationEvidenceProvider struct{ /* wraps []ClassificationEvidence, same shape as dlppolicy's Fixture...Provider */ }

func NewFixtureClassificationEvidenceProvider(events []ClassificationEvidence) *FixtureClassificationEvidenceProvider

// VerifyClassificationSample compares one sample's ground truth
// against the evidence from one channel. Unlike dlppolicy's Verify
// functions, there is no asOf -- a classification decision has no
// time-based expiry concept of its own; only window bounds evidence
// relevance. Cross-channel consistency (Concern 6) is not a separate
// evaluator: call this once per channel for the same SampleID and
// compare the resulting DLPCLSVerdicts -- see "What's left to the
// builder" for the comparison helper.
func VerifyClassificationSample(truth GroundTruth, channel string, provider ClassificationEvidenceProvider, window TimeWindow) DLPCLSVerdict
```

Verify order (first match wins):

1. No evidence records for `truth.SampleID`+`channel` in the window → `OutcomeNotTested`, reason `"sample was never submitted for evaluation on this channel in this window"`.
2. Provider error → `OutcomeInconclusive`, reason naming the error (mirrors `dlppolicy`'s own `fmt.Sprintf` pattern).
3. Latest (by `Timestamp`) record's `Decision == DecisionUnsupportedFormat` → `OutcomeUnsupported`, reason naming `truth.Format`.
4. `Decision` is `DecisionLabelOnly` / `DecisionInspectionFailed` / `DecisionNoEvidenceReturned` → `OutcomeInconclusive`, reason naming which of the three and why (see the three distinct Reason strings in Constraints above).
5. `truth.IntendedClass == SensitivityClassAmbiguous` → `OutcomeInconclusive`, reason `fmt.Sprintf("sample is ambiguous by design: %s", truth.AdjudicationPolicy)`.
6. `truth.IntendedClass == SensitivityClassNone` (benign ground truth):
   - `Decision == DecisionExplicitBenign` → `OutcomeTrueNegative`.
   - `Decision == DecisionExplicitSensitive` → `OutcomeFalsePositive`, reason naming `ObservedClass`.
7. `truth.IntendedClass` is a real sensitive class:
   - `Decision == DecisionExplicitBenign` → `OutcomeFalseNegative`, reason naming `truth.IntendedClass`.
   - `Decision == DecisionExplicitSensitive && ObservedClass == truth.IntendedClass` → `OutcomeTruePositive`.
   - `Decision == DecisionExplicitSensitive && ObservedClass != truth.IntendedClass` → `OutcomeMisclassified`, reason naming both classes.

### Corpus aggregator (`aggregate.go`)

```go
package dlpclassify

type CorpusMetrics struct {
	TotalSamples      int                                         `json:"totalSamples"`
	Evaluated         int                                         `json:"evaluated"` // TP+FP+FN+TN+Misclassified
	Inconclusive      int                                         `json:"inconclusive"`
	Unsupported       int                                         `json:"unsupported"`
	NotTested         int                                         `json:"notTested"`
	TruePositives     int                                         `json:"truePositives"`
	FalsePositives    int                                         `json:"falsePositives"`
	FalseNegatives    int                                         `json:"falseNegatives"`
	TrueNegatives     int                                         `json:"trueNegatives"`
	Misclassified     int                                         `json:"misclassified"`
	Precision         Rate                                        `json:"precision"`         // TP / (TP+FP)
	Recall            Rate                                        `json:"recall"`            // TP / (TP+FN)
	FalseNegativeRate Rate                                        `json:"falseNegativeRate"` // FN / (FN+TP)
	FalsePositiveRate Rate                                        `json:"falsePositiveRate"` // FP / (FP+TN)
	ConfusionMatrix   map[SensitivityClass]map[SensitivityClass]int `json:"confusionMatrix"`   // [intended][observed] -> count, Evaluated samples only
}

// SampleResult pairs one sample's verdict with the observed class its
// evidence actually carried -- a bare DLPCLSVerdict never carries
// ObservedClass (only ClassificationEvidence does), so the caller who
// ran VerifyClassificationSample passes both along here, rather than
// AggregateCorpusMetrics trying to recover ObservedClass by parsing
// Verdict.Reason.
type SampleResult struct {
	SampleID      string           `json:"sampleId"`
	Verdict       DLPCLSVerdict    `json:"verdict"`
	ObservedClass SensitivityClass `json:"observedClass,omitempty"`
}

// AggregateCorpusMetrics rolls per-sample results into corpus-level
// metrics. Only Evaluated outcomes enter Precision/Recall/the
// confusion matrix's denominators; Inconclusive/Unsupported/NotTested
// are always counted and reported, never silently dropped.
func AggregateCorpusMetrics(samples []SampleResult, truths map[string]GroundTruth) CorpusMetrics
```

`Misclassified` samples count toward `Evaluated` and populate the confusion matrix's off-diagonal cell, but are deliberately excluded from the binary `TruePositives`/`FalsePositives`/`FalseNegatives`/`TrueNegatives` counters and from `Precision`/`Recall` — a product that detects sensitivity but names the wrong class is neither a clean true positive nor a false negative; the confusion matrix is where that finding lives, never silently absorbed into either binary bucket.

The confusion matrix's observed-axis key for any `DecisionExplicitBenign` evidence (the `TrueNegative`/`FalseNegative` rows) is `SensitivityClassNone`, never the empty string — `ClassificationEvidence.ObservedClass` itself stays empty for a benign decision (per its own doc comment), but `AggregateCorpusMetrics` substitutes `SensitivityClassNone` when keying the matrix, so the observed axis's "benign" column lines up with the intended axis's `SensitivityClassNone` value rather than producing a mismatched blank key.

### Label lifecycle (`labellifecycle.go`) — Slice 2

Structurally parallel to `dlppolicy.DLPPolicyRuleExpectation` (a declared-vs-observed state check), but for a labeled document's sensitivity-label metadata, not a policy rule — its own independent types, no cross-import.

```go
package dlpclassify

import "time"

type LabelExpectation struct {
	DocumentID         string           `json:"documentId"`
	ScopeID             string           `json:"scopeId"` // OU/site identifier, plain string -- dlppolicy.ScopeID is not reused
	ExpectedLabel       SensitivityClass `json:"expectedLabel"`
	ExpectedInheritedFrom string         `json:"expectedInheritedFrom,omitempty"` // non-empty when the label is expected to be inherited from a parent container, not set directly
	LabelAppliedAt      *time.Time       `json:"labelAppliedAt,omitempty"`
	MaxLabelAge         time.Duration    `json:"maxLabelAge,omitempty"` // 0 = staleness not checked
	Note                string           `json:"note,omitempty"`
}

type LabelEvidence struct {
	DocumentID        string           `json:"documentId"`
	ScopeID            string           `json:"scopeId"`
	ObservedLabel      SensitivityClass `json:"observedLabel"` // empty = no label present
	ObservedInheritedFrom string        `json:"observedInheritedFrom,omitempty"`
	LastModifiedAt     time.Time        `json:"lastModifiedAt"`
	Timestamp          time.Time        `json:"timestamp"`
	Source             EvidenceSource   `json:"source"`
	Provenance         Provenance       `json:"provenance"`
}

type LabelEvidenceProvider interface {
	LabelEvidenceFor(documentID, scopeID string, window TimeWindow) ([]LabelEvidence, error)
}

func VerifyLabelExpectation(exp LabelExpectation, provider LabelEvidenceProvider, window TimeWindow, asOf time.Time) DLPCLSVerdict
```

Verify order (first match wins), closing the four label-lifecycle failure modes `dlp.txt` names:

1. No evidence → `OutcomeInconclusive`, "no label evidence found for this document/scope in the window."
2. `ObservedLabel == ""` while `exp.ExpectedLabel != SensitivityClassNone` → a **missing label** finding, reported via a dedicated Reason (not reused from the classification-accuracy branches below — missing-label is a lifecycle defect, not a classifier miss).
3. `ObservedLabel != exp.ExpectedLabel` → an **incorrect label** finding, naming both labels.
4. `exp.ExpectedInheritedFrom != "" && ObservedInheritedFrom != exp.ExpectedInheritedFrom` → an **inheritance** finding (covers "missing, incorrect, inherited" together: a label that is present and even matches by value but came from the wrong source is still a lifecycle defect).
5. `exp.MaxLabelAge > 0 && asOf.Sub(latest.LastModifiedAt) > exp.MaxLabelAge` → a **stale label** finding ("manually changed" sensitivity labels that were never refreshed surface here).
6. Otherwise → a passing verdict.

This spec fixes the type signatures and Verify order; exact `DLPCLSOutcome`/Reason-string mapping for each of the five branches above, and the fixture matrix proving each one, are left to Slice 2's own implementation plan — the same division DLP-POL used between its spec (fixing shape) and its plans (fixing exact values).

## What's left to the builder

- A small `CompareChannelVerdicts(a, b DLPCLSVerdict) bool` (or equivalent) helper for Concern 6 — given two per-channel verdicts for the same `SampleID`, report whether they agree. Exact signature and whether it lives in `sample.go` or its own file is left to the implementer; the type contracts above (per-channel `ClassificationEvidence`/`VerifyClassificationSample`) are what the plan must preserve.
- Exact Go file layout within `internal/dlpclassify` is this design's own suggestion, not a hard requirement, as long as the type/function contracts above are preserved.
- Fixture corpus content for Slice 1's buildable tests (specific sample IDs, formats, and ground-truth classes demonstrating each Verify branch and each `ValidateCorpus` rejection) — built via TDD, one failing test per branch, per the established DLP Mastery convention.
- Slice 2's exact Reason strings and fixture matrix, deferred to its own implementation plan per the note above.
- Consumption wiring (an API handler or report surface that calls `AggregateCorpusMetrics` and renders it) is out of scope for this spec's buildable slices, logged as a deferred gap exactly like DLP-POL's vendor-connector consumption wiring.
