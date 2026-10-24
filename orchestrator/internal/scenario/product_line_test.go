package scenario

import (
	"path/filepath"
	"testing"

	"github.com/audspect/bas/internal/license"
)

// Every shipped scenario loads with a product line the licence knows. A scenario with no product
// line, or an unknown one, must never reach the run paths.
func TestBuiltinScenarios_AllHaveValidProductLine(t *testing.T) {
	eng := NewEngine(filepath.Join("..", "..", "..", "scenarios"))
	if err := eng.Load(); err != nil {
		t.Fatalf("load: %v", err)
	}
	list := eng.List()
	if len(list) != 108 {
		t.Fatalf("loaded %d scenarios, want 108", len(list))
	}
	for _, sc := range list {
		if !license.ValidProductLine(sc.ProductLine) {
			t.Fatalf("%s: product_line %q is not a licensed product line", sc.ID, sc.ProductLine)
		}
	}
}

// A Core licence cannot reach an Enterprise scenario through the engine, by lookup or by listing.
// Common and Core scenarios stay reachable.
func TestLicenceGate_CoreRefusesKillChain(t *testing.T) {
	eng := NewEngine(filepath.Join("..", "..", "..", "scenarios"))
	if err := eng.Load(); err != nil {
		t.Fatalf("load: %v", err)
	}
	core, err := license.TierProducts(license.TierCore)
	if err != nil {
		t.Fatal(err)
	}
	eng.SetLicence(func(p license.ProductLine) bool { return core[p] })
	if _, ok := eng.Get("apt29-kill-chain"); ok {
		t.Fatal("Core licence reached an Enterprise kill chain through Get")
	}
	if _, ok := eng.Get("av-ngav-assessment"); !ok {
		t.Fatal("Core licence was refused an AV scenario")
	}
	for _, sc := range eng.List() {
		if sc.ProductLine == string(license.ProductKillChain) {
			t.Fatalf("Core licence listed %s", sc.ID)
		}
	}
}

// ResolveExecutable is an execution path (campaign start uses it). It must refuse a scenario the
// licence does not permit, and it fails closed for a scenario that is not loaded at all.
func TestRequireLicensed_RefusesUnlicensedAndUnknown(t *testing.T) {
	eng := NewEngine(filepath.Join("..", "..", "..", "scenarios"))
	if err := eng.Load(); err != nil {
		t.Fatalf("load: %v", err)
	}
	core, err := license.TierProducts(license.TierCore)
	if err != nil {
		t.Fatal(err)
	}
	eng.SetLicence(func(p license.ProductLine) bool { return core[p] })
	if err := eng.requireLicensed("apt29-kill-chain"); err == nil {
		t.Fatal("Core licence resolved an Enterprise scenario for execution")
	}
	if err := eng.requireLicensed("av-ngav-assessment"); err != nil {
		t.Fatalf("Core licence refused an AV scenario: %v", err)
	}
	if err := eng.requireLicensed("no-such-scenario"); err == nil {
		t.Fatal("an unloaded scenario was allowed through")
	}
}
