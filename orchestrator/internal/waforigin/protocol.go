package waforigin

import (
	"fmt"
	"regexp"

	"github.com/audspect/bas/internal/wafval"
)

var cweIDPattern = regexp.MustCompile(`^CWE-\d+$`)

// RequestTemplate describes one request shape without executing it.
type RequestTemplate struct {
	Method          string
	Path            string
	PayloadLocation string
	Payload         string
	Description     string
}

// StandardsMapping ties a vector to external references. At least one of
// CWEIDs/WSTGCategory/Top10Category/APITop10Category must be non-empty.
type StandardsMapping struct {
	CWEIDs           []string
	WSTGCategory     string
	Top10Category    string
	APITop10Category string
	ATTACKTechniques []string
}

// ProtocolBehaviorVector is this package's single Kind-B (protocol-claim)
// catalog entry: a probe of TLS/proxy-trust behavior, not a cross-reference
// to an existing wafcatalog vector.
type ProtocolBehaviorVector struct {
	ID                        string
	Version                   int
	Name                      string
	Preconditions             string
	Malicious                 RequestTemplate
	BenignCounterpart         *RequestTemplate
	NoBenignCounterpartReason string
	Standards                 StandardsMapping
	Provenance                string
}

func validateRequestTemplate(r RequestTemplate, label string) error {
	if r.Method == "" {
		return fmt.Errorf("%s.Method must not be empty", label)
	}
	if r.Path == "" {
		return fmt.Errorf("%s.Path must not be empty", label)
	}
	if r.Description == "" {
		return fmt.Errorf("%s.Description must not be empty", label)
	}
	return nil
}

func validateStandards(s StandardsMapping) error {
	for _, id := range s.CWEIDs {
		if !cweIDPattern.MatchString(id) {
			return fmt.Errorf("CWE ID %q does not match ^CWE-\\d+$", id)
		}
	}
	if len(s.CWEIDs) == 0 && s.WSTGCategory == "" && s.Top10Category == "" && s.APITop10Category == "" {
		return fmt.Errorf("Standards must set at least one of CWEIDs, WSTGCategory, Top10Category, APITop10Category")
	}
	return nil
}

// NewProtocolBehaviorVector validates at construction time, never at render
// time. Validation is identical in substance to wafbotabuse.NewBotAbuseVector,
// minus a category check -- this kind has exactly one named item.
func NewProtocolBehaviorVector(
	id string,
	version int,
	name string,
	preconditions string,
	malicious RequestTemplate,
	benignCounterpart *RequestTemplate,
	noBenignCounterpartReason string,
	standards StandardsMapping,
	provenance string,
) (ProtocolBehaviorVector, error) {
	if id == "" {
		return ProtocolBehaviorVector{}, fmt.Errorf("id must not be empty")
	}
	if version < 1 {
		return ProtocolBehaviorVector{}, fmt.Errorf("version must be >= 1, got %d", version)
	}
	if err := validateRequestTemplate(malicious, "Malicious"); err != nil {
		return ProtocolBehaviorVector{}, err
	}
	if err := validateStandards(standards); err != nil {
		return ProtocolBehaviorVector{}, err
	}
	if provenance == "" {
		return ProtocolBehaviorVector{}, fmt.Errorf("provenance must not be empty")
	}
	hasBenign := benignCounterpart != nil
	hasReason := noBenignCounterpartReason != ""
	if hasBenign == hasReason {
		return ProtocolBehaviorVector{}, fmt.Errorf("exactly one of benignCounterpart or noBenignCounterpartReason must be set, got benignCounterpart set=%v, reason set=%v", hasBenign, hasReason)
	}
	if hasBenign {
		if err := validateRequestTemplate(*benignCounterpart, "BenignCounterpart"); err != nil {
			return ProtocolBehaviorVector{}, err
		}
	}
	return ProtocolBehaviorVector{
		ID: id, Version: version, Name: name, Preconditions: preconditions, Malicious: malicious,
		BenignCounterpart: benignCounterpart, NoBenignCounterpartReason: noBenignCounterpartReason,
		Standards: standards, Provenance: provenance,
	}, nil
}

// ProtocolLeg names which half of a ProtocolBehaviorVector a leg's
// expectation came from.
type ProtocolLeg string

const (
	LegMaliciousProtocol ProtocolLeg = "malicious"
	LegBenignProtocol    ProtocolLeg = "benign"
)

// ProtocolLegExpectation pairs one leg's request template with the
// wafval.Expectation it resolves to.
type ProtocolLegExpectation struct {
	VectorID    string
	Leg         ProtocolLeg
	Request     RequestTemplate
	Expectation wafval.Expectation
}

// Expectations returns the malicious leg's ProtocolLegExpectation, plus
// the benign leg's when BenignCounterpart is set -- never a padded slice.
func (v ProtocolBehaviorVector) Expectations(policyBasis string) []ProtocolLegExpectation {
	legs := []ProtocolLegExpectation{
		{
			VectorID: v.ID,
			Leg:      LegMaliciousProtocol,
			Request:  v.Malicious,
			Expectation: wafval.Expectation{
				Claim: wafval.ClaimPrevention, PolicyBasis: policyBasis, PolicyVerified: false,
			},
		},
	}
	if v.BenignCounterpart != nil {
		legs = append(legs, ProtocolLegExpectation{
			VectorID: v.ID,
			Leg:      LegBenignProtocol,
			Request:  *v.BenignCounterpart,
			Expectation: wafval.Expectation{
				Claim: wafval.ClaimFalsePositive, PolicyBasis: policyBasis, PolicyVerified: false,
			},
		})
	}
	return legs
}
