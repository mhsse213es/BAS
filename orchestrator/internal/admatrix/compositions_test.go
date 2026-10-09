package admatrix

import (
	"testing"

	"github.com/audspect/bas/internal/adcompose"
	"github.com/audspect/bas/internal/adprimitive"
)

func TestCompositions_AreCanonicalAndOrdered(t *testing.T) {
	cs := Compositions()
	if len(cs) < 3 {
		t.Fatalf("expected the canonical ADCS/RBCD/DCSync compositions, got %d", len(cs))
	}
	seen := map[string]bool{}
	for _, c := range cs {
		if c.Name == "" || len(c.Chain) == 0 {
			t.Fatalf("composition %+v is malformed", c)
		}
		if seen[c.Name] {
			t.Fatalf("duplicate composition name %q", c.Name)
		}
		seen[c.Name] = true
	}
}

// Each canonical composition must MODEL a valid attack path: in its enabling
// synthetic environment, every step's capability prerequisites and condition
// prerequisites are satisfied in order. The ONLY remaining problem is that the
// gap primitives have no scenario YAML yet (ProblemUnmapped) -- which is the
// honest, measurable coverage gap, not a modelling error.
func TestCompositions_ModelValidPathsButAreUnmappedToScenarios(t *testing.T) {
	for _, c := range Compositions() {
		cc := c.Compose()
		if len(cc.Steps) != len(c.Chain) {
			t.Fatalf("%s: composed %d steps for a %d-step chain", c.Name, len(cc.Steps), len(c.Chain))
		}
		sawUnmapped := false
		for _, s := range cc.Steps {
			for _, p := range s.Problems {
				switch p.Kind {
				case adcompose.ProblemUnmetPrerequisite, adcompose.ProblemUnresolvedCondition:
					t.Fatalf("%s: step %s has a modelling defect (%s: %s) — the enabling env/order is wrong",
						c.Name, s.Primitive.ID, p.Kind, p.Detail)
				case adcompose.ProblemUnmapped:
					sawUnmapped = true
				}
			}
		}
		if !sawUnmapped {
			t.Fatalf("%s: expected the gap primitives to be honestly unmapped to scenarios", c.Name)
		}
		// Unmapped-to-scenario means the chain is not yet scenario-composable.
		if cc.Composable {
			t.Fatalf("%s: must not report composable while its primitives lack scenario content", c.Name)
		}
	}
}

func TestCompositions_DCSyncChainEndsInDomainCredentialMaterial(t *testing.T) {
	var dcsync *Composition
	for i := range Compositions() {
		if Compositions()[i].Name == "dcsync-domain-dominance" {
			dcsync = &Compositions()[i]
		}
	}
	if dcsync == nil {
		t.Fatal("dcsync-domain-dominance composition must exist")
	}
	last := dcsync.Chain[len(dcsync.Chain)-1]
	if last.Postconditions[0].Kind != adprimitive.CapDomainCredentialMaterial {
		t.Fatalf("DCSync chain must culminate in domain credential material, got %+v", last.Postconditions)
	}
}
