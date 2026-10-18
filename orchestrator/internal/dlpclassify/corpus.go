package dlpclassify

import (
	"fmt"
	"strings"
)

// GroundTruth is one labeled sample's fixed, corpus-authored truth --
// established once at authoring time, never influenced by any
// product's observed classification. Mirrors dlpfixture.Fixture's
// validate-at-construction discipline.
type GroundTruth struct {
	SampleID           string           `json:"sampleId"`
	ContentHash        string           `json:"contentHash"` // hash of the actual sample bytes, computed once at authoring time -- enables duplicate-leakage detection without the corpus storing real file content in Go source
	IntendedClass      SensitivityClass `json:"intendedClass"`
	Rationale          string           `json:"rationale"`                    // required: why this sample belongs to IntendedClass
	Format             string           `json:"format"`                       // e.g. "pdf", "scanned-image", "zip-nested", "csv"
	TransformationOf   string           `json:"transformationOf,omitempty"`   // SampleID this is a transformed/split/reformatted variant of; empty if this IS a source sample
	AdjudicationPolicy string           `json:"adjudicationPolicy,omitempty"` // required, non-empty, when IntendedClass == SensitivityClassAmbiguous
	Note               string           `json:"note,omitempty"`
}

// NewGroundTruth validates at construction, never at verify time:
// SampleID/ContentHash/Rationale/Format non-empty; AdjudicationPolicy
// non-empty iff IntendedClass == SensitivityClassAmbiguous.
func NewGroundTruth(sampleID, contentHash string, intendedClass SensitivityClass, rationale, format, transformationOf, adjudicationPolicy, note string) (GroundTruth, error) {
	if sampleID == "" {
		return GroundTruth{}, fmt.Errorf("sampleID must not be empty")
	}
	if contentHash == "" {
		return GroundTruth{}, fmt.Errorf("contentHash must not be empty")
	}
	if rationale == "" {
		return GroundTruth{}, fmt.Errorf("rationale must not be empty")
	}
	if format == "" {
		return GroundTruth{}, fmt.Errorf("format must not be empty")
	}
	if intendedClass == SensitivityClassAmbiguous && strings.TrimSpace(adjudicationPolicy) == "" {
		return GroundTruth{}, fmt.Errorf("adjudicationPolicy must not be empty when intendedClass is ambiguous")
	}
	return GroundTruth{
		SampleID:           sampleID,
		ContentHash:        contentHash,
		IntendedClass:      intendedClass,
		Rationale:          rationale,
		Format:             format,
		TransformationOf:   transformationOf,
		AdjudicationPolicy: adjudicationPolicy,
		Note:               note,
	}, nil
}

// ValidateCorpus checks cross-sample invariants NewGroundTruth cannot
// see alone: a duplicate SampleID, a TransformationOf reference to a
// SampleID absent from the corpus, and duplicate-content leakage (two
// different SampleIDs sharing one ContentHash -- flagged whether their
// IntendedClass agrees, a sheer duplicate, or disagrees, a
// contradictory label on the same underlying content).
func ValidateCorpus(truths []GroundTruth) error {
	seenID := make(map[string]bool, len(truths))
	hashOwner := make(map[string]string, len(truths))
	for _, t := range truths {
		if seenID[t.SampleID] {
			return fmt.Errorf("duplicate sample ID %q", t.SampleID)
		}
		seenID[t.SampleID] = true
		if owner, ok := hashOwner[t.ContentHash]; ok {
			return fmt.Errorf("content hash %q claimed by both sample %q and %q", t.ContentHash, owner, t.SampleID)
		}
		hashOwner[t.ContentHash] = t.SampleID
	}
	for _, t := range truths {
		if t.TransformationOf != "" && !seenID[t.TransformationOf] {
			return fmt.Errorf("sample %q declares TransformationOf %q, which is not in the corpus", t.SampleID, t.TransformationOf)
		}
	}
	return nil
}
