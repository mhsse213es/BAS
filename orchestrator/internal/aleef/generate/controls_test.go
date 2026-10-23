package generate

import (
	"strings"
	"testing"

	"github.com/audspect/bas/internal/aleef/model"
	"github.com/audspect/bas/internal/aleef/property"
)

func TestGenerateEmitsValidatedControls(t *testing.T) {
	tests := gen(t, Options{Seed: 1})
	if len(tests) == 0 {
		t.Fatal("no tests")
	}
	for _, x := range tests {
		if strings.HasSuffix(x.ID, "-OC") || strings.HasSuffix(x.ID, "-NC") {
			t.Fatalf("a control is a top-level test: %s", x.ID)
		}
		if x.ControlsBlocked || x.OwnerControl == nil || x.NegativeControl == nil {
			t.Fatalf("%s: controls missing (blocked=%v)", x.ID, x.ControlsBlocked)
		}
		for suffix, c := range map[string]*Test{"-OC": x.OwnerControl, "-NC": x.NegativeControl} {
			if c.ID != x.ID+suffix || c.Scenario.ID != c.ID {
				t.Fatalf("control id %s, want %s", c.ID, x.ID+suffix)
			}
			if err := c.Scenario.Validate(); err != nil {
				t.Fatalf("%s: %v", c.ID, err)
			}
			if !c.Template.ExpectSuccess || c.OwnerControl != nil || c.NegativeControl != nil || c.Covered {
				t.Fatalf("%s: bad control shape", c.ID)
			}
			if c.Scenario.Preconditions.Fixture != x.Scenario.Preconditions.Fixture {
				t.Fatalf("%s: control runs against another fixture", c.ID)
			}
		}
	}
}

func TestControlsDoNotCountTowardMaxTestsAndAreNotTopLevel(t *testing.T) {
	cut := gen(t, Options{Seed: 3, Variations: AllVariations(), MaxTests: 4})
	if len(cut) != 4 {
		t.Fatalf("MaxTests 4 gave %d tests", len(cut))
	}
	for _, x := range cut {
		if x.OwnerControl == nil || x.NegativeControl == nil {
			t.Fatalf("%s lost its controls under MaxTests", x.ID)
		}
	}
	_, rep, err := GenerateWithReport(toyModel(), toyFixture(), toyAccounts(), Options{Catalogue: emptyCat, Seed: 3, Variations: AllVariations(), MaxTests: 4})
	if err != nil {
		t.Fatal(err)
	}
	if rep.BaseTests+rep.Variants-rep.Truncated != 4 {
		t.Fatalf("report counts controls? %+v", rep)
	}
}

func TestVariationTestsReuseTheBaseTemplateControls(t *testing.T) {
	n := 0
	for _, x := range gen(t, Options{Seed: 1, Variations: AllVariations()}) {
		if x.Params["variation"] == "" {
			continue
		}
		n++
		if x.OwnerControl == nil || x.NegativeControl == nil || x.OwnerControl.ID != x.ID+"-OC" {
			t.Fatalf("variation %s (%s) has no controls", x.ID, x.Params["variation"])
		}
	}
	if n == 0 {
		t.Fatal("no variation tests")
	}
}

func TestControlsBlockedWhenAControlStepIsNotRunnable(t *testing.T) {
	// P-AUTH-1's test (execute without approval) has only safe steps, but its
	// controls need the approval step, which is a money operation.
	m := toyModel()
	m.Operations = append(m.Operations,
		mkOp("authz", "POST", "/api/v2/items/{id}/authorize", idP(),
			&model.Schema{Type: "object", Properties: map[string]*model.Schema{"comment": strS()}}, model.ClassMoney),
		mkOp("exec", "POST", "/api/v2/items/{id}/execute", idP(),
			&model.Schema{Type: "object", Properties: map[string]*model.Schema{"comment": strS()}}, model.ClassReversible))
	opt := Options{Catalogue: emptyCat, Workflow: &property.Workflow{Name: "approval", Steps: []property.WorkflowStep{
		{Op: "authz", Kind: property.StepAuthorize},
		{Op: "exec", Kind: property.StepExecute},
	}}}
	out, rep, err := GenerateWithReport(m, toyFixture(), toyAccounts(), opt)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, x := range out {
		if x.Property != "P-AUTH-1" {
			continue
		}
		found = true
		if !x.ControlsBlocked || x.OwnerControl != nil || x.NegativeControl != nil {
			t.Fatalf("P-AUTH-1 must be marked ControlsBlocked without controls: %+v", x.ControlsBlocked)
		}
	}
	if !found {
		t.Fatal("the primary test must still be emitted")
	}
	if rep.ControlsBlocked == 0 {
		t.Fatalf("report = %+v", rep)
	}
}
