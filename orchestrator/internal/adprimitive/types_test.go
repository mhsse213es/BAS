package adprimitive

import (
	"encoding/json"
	"reflect"
	"testing"
)

// twoChainedPrimitives is Kerberoasting (AD.txt's own worked example,
// lines 349-360) followed by a second primitive that CONSUMES the
// DOMAIN_USER capability every domain principal already starts with --
// exercising a host-agnostic capability, a host-scoped one, an empty
// TechniqueID, and prerequisite/postcondition capability matching, all in
// one fixture.
func twoChainedPrimitives() []Primitive {
	return []Primitive{
		{
			ID: "kerberoast", Name: "Kerberoasting", TechniqueID: "T1558.003",
			Prerequisites: Prerequisites{
				DomainJoined: true,
				Privileges:   []string{"domain_user"},
				Capabilities: []Capability{{Kind: CapDomainUser}},
				Conditions:   map[string]bool{"spn_account_exists": true},
			},
			Postconditions: []Capability{{Kind: CapServiceAccountCredential}},
		},
		{
			// AD.txt lines 144-156: ADCS sub-steps like template discovery
			// have no dedicated MITRE technique ID -- TechniqueID empty here
			// on purpose.
			ID: "adcs-template-discovery", Name: "ADCS Certificate Template Discovery",
			Prerequisites: Prerequisites{
				DomainJoined: true,
				Capabilities: []Capability{{Kind: CapServiceAccountCredential}},
			},
			Postconditions: []Capability{
				{Kind: CapLocalAdmin, Target: "SERVER01"},
			},
		},
	}
}

func TestPrimitive_JSONRoundTrip_FullyPopulated(t *testing.T) {
	prims := twoChainedPrimitives()

	data, err := json.Marshal(prims)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var got []Primitive
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if !reflect.DeepEqual(prims, got) {
		t.Fatalf("round-trip mismatch:\n got  %+v\n want %+v", got, prims)
	}
}

func TestPrimitive_JSONRoundTrip_ZeroValue(t *testing.T) {
	var p Primitive

	data, err := json.Marshal(p)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var got Primitive
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if !reflect.DeepEqual(p, got) {
		t.Fatalf("zero-value round-trip mismatch:\n got  %+v\n want %+v", got, p)
	}
}

func TestPrimitive_PostconditionMatchesNextPrerequisite(t *testing.T) {
	prims := twoChainedPrimitives()
	// The planner's core operation (AD-M05, not implemented here): can
	// primitive B run after primitive A, because A's postcondition
	// satisfies one of B's required capabilities? Prove the TYPE supports
	// this match by plain equality, with no translation step.
	kerberoast, adcs := prims[0], prims[1]
	satisfied := false
	for _, have := range kerberoast.Postconditions {
		for _, need := range adcs.Prerequisites.Capabilities {
			if have == need {
				satisfied = true
			}
		}
	}
	if !satisfied {
		t.Fatalf("expected kerberoast's postcondition %+v to satisfy adcs-template-discovery's prerequisite %+v by equality", kerberoast.Postconditions, adcs.Prerequisites.Capabilities)
	}
}
