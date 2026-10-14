# Family Content Metadata & Validation Infrastructure — Design

Sub-project #10 of the ransomware-mastery master roadmap: "Family content
pipeline (Black Basta/Medusa/Rhysida/Hunters International, versioned+
evidence-backed)". This pass is **infrastructure only** — the metadata
schema and its validation — not the four families' actual content. Each
family is deliberately a separate, individually-vetted later pass, so a
quality/safety problem in one family's content is never confused with a
defect in this infrastructure.

## A. Problem statement

ransomware.txt §8 lists six things "every technique should have." Checking
each against what `internal/contentregistry` (the already-merged TCF
Content Registry, Phase 1) already derives automatically from scenario
YAML:

| Requirement | Status |
|---|---|
| ATT&CK mapping and platform applicability | Already derived (`analysis.techniqueIDs`/`supportedOS`) — reuse, no new work |
| Safety classification and required permissions | Already derived (`analysis.safety` via `execclass`, plus each step's own `risk`/`requires_priv`/`production_safe`) — reuse, no new work |
| A regression test before content publication | Already an established process this session (smoke test + real-corpus tests, same discipline applied to every prior sub-project) — a process requirement, not a missing capability |
| Threat-intelligence source and last-reviewed date | **Genuine gap** — today only exists as free-text prose in a scenario's `description:` field |
| Family attribution confidence | **Genuine gap** — same free-text-only situation |

Only the last two are real gaps. Both become new structured fields on
`scenario.Step` (per-technique, matching the roadmap's own "every
*technique*" framing and the existing per-step convention `telemetry:`/
`detection:` already use) — **not new database columns**. No new TCF
registry pipeline, no persistence project: `contentregistry.Intake`'s
existing `SourceBuiltin` path already auto-registers any scenario whose
`.sig` verifies as `LifecyclePublished`/`TrustVendorSigned`/`OriginVendor`
(`intake.go:125-135`) — the exact mechanism `scripts/signer.go` already
produces. Nothing about execution eligibility changes in this pass.

**Load-bearing fact, confirmed by reading the code:** `analysis.structural`
and `analysis.safety` are stored as diagnostic records (`content_validations`
rows) and are **never read back** to gate `createVersion`'s lifecycle/trust
assignment (confirmed: `store.go`'s only consumers of `nv.analysis.structural`/
`nv.analysis.safety` are write-only inserts; `intake.go`'s `SourceBuiltin`
branch decides `LifecyclePublished` purely from `f.SignatureVerified`). This
pass's new validation rules preserve that distinction unchanged: a structural
check failure is recorded for review, never a runtime block on registration
or execution. Passing these new checks does not and must not make content
approved or executable — that remains solely the signature-verification and
lifecycle machinery TCF already owns.

## B. Schema: three new `scenario.Step` fields

Added to `orchestrator/internal/scenario/types.go`'s `Step` struct, after
the existing `DetectionProfiles`/`ExpectedDetections` block:

```go
// ThreatIntelSource is one citation backing a step's claimed behavior:
// an advisory/report identifier (mandatory) and an optional URL.
type ThreatIntelSource struct {
	Reference string `yaml:"reference"      json:"reference"`
	URL       string `yaml:"url,omitempty"   json:"url,omitempty"`
}
```

Three new fields on `Step` (mandatory-for-specific-content-sets
enforcement lives outside this package entirely — see section E):

```go
ThreatIntelSources []ThreatIntelSource `yaml:"threat_intel_sources,omitempty" json:"threatIntelSources,omitempty"`

// LastReviewed is an explicit date (YYYY-MM-DD) this step's claimed
// behavior was last checked against current threat intelligence --
// distinct from the YAML file's own publication or last-modified time,
// which reflect editing activity, not intelligence freshness.
LastReviewed string `yaml:"last_reviewed,omitempty" json:"lastReviewed,omitempty"`

// FamilyAttributionConfidence is how strongly ThreatIntelSources link
// THIS SPECIFIC BEHAVIOR to the family this scenario models -- not
// confidence that the behavior occurs at all, and not confidence that
// some ransomware family exhibits it. One of FamilyAttribution*.
FamilyAttributionConfidence string `yaml:"family_attribution_confidence,omitempty" json:"familyAttributionConfidence,omitempty"`
```

Confidence vocabulary (closed 4-value enum, new consts alongside `Step`):

```go
const (
	// FamilyAttributionUnsourced: author assertion, no citation.
	FamilyAttributionUnsourced = "unsourced"
	// FamilyAttributionInferred: consistent with the family's documented
	// toolset/TTPs generally, but the cited source(s) don't specifically
	// tie this behavior to this family.
	FamilyAttributionInferred = "inferred"
	// FamilyAttributionReported: at least one credible source specifically
	// attributes this behavior to this family.
	FamilyAttributionReported = "reported"
	// FamilyAttributionConfirmed: multiple sources, or a definitive
	// government advisory, specifically attribute this behavior to this
	// family. The structural validator enforces only a minimum citation
	// COUNT (≥2) as a floor -- it cannot verify that two citations are
	// genuinely independent, or assess source credibility. That judgment
	// belongs to the human authoring/review step of each family's later
	// content pass, documented in the scenario's own description when the
	// attribution rests on a single definitive government advisory rather
	// than multiple independent sources.
	FamilyAttributionConfirmed = "confirmed"
)
```

## C. Validation: extending `contentregistry.structuralCheck`

`structuralCheck` (`internal/contentregistry/analyze.go:147-170`) is
extended with new, **universal** rules — they apply to any scenario that
uses these fields, regardless of which content set it belongs to. This
keeps `contentregistry` generic: it never needs to know about ransomware,
families, or this sub-project's specific scenario IDs.

For every step with a non-empty `FamilyAttributionConfidence`:

1. The value must be one of the four closed constants — else `"invalid
   family_attribution_confidence value"`.
2. If the value is anything other than `FamilyAttributionUnsourced`,
   `ThreatIntelSources` must be non-empty — else `"non-unsourced
   family_attribution_confidence requires at least one threat_intel_sources
   entry"`. (The reverse is never checked: a step may cite sources while
   still rating itself `unsourced` for family-attribution purposes
   specifically — citing a source doesn't by itself establish *family*
   attribution, per the distinction in section B's doc comment.)
3. If the value is `FamilyAttributionConfirmed`, `ThreatIntelSources` must
   have at least 2 entries — else `"confirmed family_attribution_confidence
   requires at least 2 threat_intel_sources entries"`. This is a **minimum
   count floor only** — it is not, and cannot be, a check that the sources
   are independent or credible; that judgment is a human authoring/review
   decision for each family's later content pass, not something
   `structuralCheck` can establish by counting YAML entries.

For every `ThreatIntelSource` entry, on any step:

4. `Reference` must be non-empty — else `"threat_intel_sources entry
   missing reference"`.

For every step with a non-empty `LastReviewed`:

5. The value must parse as `2006-01-02` (Go's `time.Parse` layout) — else
   `"last_reviewed is not a valid date"`.

None of these rules fire for a step that sets none of the three fields —
the existing 9 scenarios, which set none of them, produce zero new
structural problems and are completely unaffected.

## D. Compatibility: the existing 9 scenarios are untouched

No existing scenario YAML is modified. `structuralCheck`'s new rules are
additive and only ever evaluate fields that are present; a step with an
empty `ThreatIntelSources`/`LastReviewed`/`FamilyAttributionConfidence`
(the zero value, exactly what every existing step already has) triggers
none of the five new rules. A compatibility test proves this directly: all
9 existing scenarios still parse via `scenario.ParseYAML` and still produce
a `structuralCheck` outcome of `"PASS"` (assuming they already passed
before this change — they do, confirmed by the existing, unmodified
`TestRansomwareRelevantProfiles_MatchesRealCorpus`-style real-corpus tests
staying green throughout this session).

## E. Mandatory-for-new-content enforcement: deliberately not built yet

The roadmap's intent — these three fields are **mandatory** for the four
new family scenarios specifically, never retrofitted onto the existing 9 —
is enforced by a **closed-list corpus test**, the same pattern every
sub-project this session has used for its own scenario-list touchpoints
(`rwdetect`/`rwevidence`/`rwtaxonomy`'s real-corpus tests, sub-project #9's
new `ransomwareScenarioIDs` test). Critically, this enforcement test
**lives outside `contentregistry`** (which must stay generic, never
hardcoding which scenario IDs are "the family content set") and is added
**when the first family file exists**, not now: a test asserting properties
of four files that do not yet exist on disk would either fail permanently
or have to be written against fictional content, neither of which is real
verification. This pass documents the intended test shape (for whichever
family's pass writes it first) without creating it:

```go
// (written in a later family pass, once at least one target file exists)
var familyContentScenarioFiles = []string{
	"black-basta-kill-chain.yaml", // added as each family's pass lands
}

func TestFamilyContent_EveryTechniqueStepHasRequiredProvenance(t *testing.T) {
	for _, file := range familyContentScenarioFiles {
		sc := parseRealScenario(t, file) // same os.ReadFile + scenario.ParseYAML as existing corpus tests
		for _, step := range sc.Steps {
			if step.TechniqueID == "" {
				continue
			}
			if len(step.ThreatIntelSources) == 0 {
				t.Errorf("%s step %q: technique-tagged step missing threat_intel_sources", file, step.Name)
			}
			if step.LastReviewed == "" {
				t.Errorf("%s step %q: technique-tagged step missing last_reviewed", file, step.Name)
			}
			if step.FamilyAttributionConfidence == "" {
				t.Errorf("%s step %q: technique-tagged step missing family_attribution_confidence", file, step.Name)
			}
		}
	}
}
```

## F. Testing strategy for this pass

- **Struct/round-trip tests** (`internal/scenario`): a `Step` with all three
  new fields set parses from YAML and serializes back correctly (field
  names, nesting of `ThreatIntelSources`).
- **Structural-check tests** (`internal/contentregistry`), one per rule in
  section C: all four confidence values individually valid when correctly
  sourced; invalid confidence string rejected; `inferred`/`reported` with
  zero sources rejected; `confirmed` with exactly 1 source rejected;
  `confirmed` with 2 sources accepted; `unsourced` with zero sources
  accepted; `unsourced` **with** sources present still accepted (the
  one-directional rule from point 2); a source entry with an empty
  `Reference` rejected; a malformed `LastReviewed` value rejected; a
  well-formed one accepted.
- **Compatibility test**: all 9 existing scenario files (the same list
  sub-project #9 already registers in five places) still parse via
  `scenario.ParseYAML` and still produce `structuralCheck` outcome `"PASS"`
  after this change, unmodified.

## G. Explicitly deferred (not this pass)

- The four family scenarios themselves (Black Basta, Medusa, Rhysida,
  Hunters International) — each is its own later pass, with its own
  threat-intel grounding, distinct techniques, safety review, and
  regression tests, signed and admitted through the existing TCF path
  exactly like every other builtin scenario.
- The closed-list mandatory-enforcement test from section E — written in
  whichever family pass introduces the first real file.
- Any database schema change, any new registry table or column, any second
  publication mechanism alongside TCF's existing one.
- Phase 2A actor/threat identity resolution (unmerged branch) — structured
  family attribution via these three fields does not require it, and
  nothing in this design creates a dependency on it.
- Retrofitting these fields onto any of the existing 9 scenarios.
