package api

import (
	"go/parser"
	"go/token"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

// The AD planning/simulation pipeline. Production scenario dispatch (this
// package) must never import any of it. This is the hard wall between composed
// AD chains -- which are metadata/plan only, gated by adgate, and "executed"
// only by the fake-backed adlabrt runtime -- and REAL execution, which happens
// solely through dispatchRun on committed scenarios.
//
// A composed AD chain may cross into real execution only through a future P5
// verified-lab bridge carrying a genuine VerifiedControlledLab provenance; it
// must never be routed into real-exec status via this dispatch path, and a
// sim/plan result must never be persisted as a real run. This test fails closed
// the moment someone wires the sim pipeline into the API package.
var adSimPipeline = map[string]string{
	"github.com/audspect/bas/internal/adcompose":  "chain composition (metadata-only, no runnable field)",
	"github.com/audspect/bas/internal/adrehearse": "hypothetical plan producer (executes nothing)",
	"github.com/audspect/bas/internal/adgate":     "AD-sim execution decision point",
	"github.com/audspect/bas/internal/adlabrt":    "fake-backed AD lab runtime",
}

// scanProdImports returns the set of packages imported by the non-test Go files
// in dir (ImportsOnly parse -- cheap). It globs + ParseFiles rather than using
// the deprecated parser.ParseDir.
func scanProdImports(t *testing.T, dir string) map[string]bool {
	t.Helper()
	files, err := filepath.Glob(filepath.Join(dir, "*.go"))
	if err != nil {
		t.Fatalf("glob %s: %v", dir, err)
	}
	fset := token.NewFileSet()
	imports := map[string]bool{}
	for _, path := range files {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
		for _, imp := range f.Imports {
			if p, err := strconv.Unquote(imp.Path.Value); err == nil {
				imports[p] = true
			}
		}
	}
	if len(files) == 0 {
		t.Fatalf("no Go files found in %s", dir)
	}
	return imports
}

func TestProductionDispatchDoesNotImportADSimPipeline(t *testing.T) {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot resolve test file path")
	}
	apiDir := filepath.Dir(thisFile)
	internalDir := filepath.Dir(apiDir)

	// Self-validation: the detector must actually catch a real importer, so a
	// vacuous pass (e.g. a broken parse) can't masquerade as the wall holding.
	// adrehearse genuinely imports adcompose and adgate.
	rehearseImports := scanProdImports(t, filepath.Join(internalDir, "adrehearse"))
	if !rehearseImports["github.com/audspect/bas/internal/adcompose"] ||
		!rehearseImports["github.com/audspect/bas/internal/adgate"] {
		t.Fatal("import scanner is broken: it failed to see adrehearse's real imports of adcompose/adgate")
	}

	// The wall: internal/api imports none of the AD-sim pipeline.
	apiImports := scanProdImports(t, apiDir)
	for pkg, why := range adSimPipeline {
		if apiImports[pkg] {
			t.Errorf("production dispatch (internal/api) must not import %s (%s): this risks routing a composed/simulated AD chain into real execution, bypassing adgate and the supported dispatch controls. A real-execution bridge belongs behind a P5 verified-lab, not here.", pkg, why)
		}
	}
}
