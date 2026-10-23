package aleef_test

// Isolation guard: the generator side (model, property, generate, novelty,
// verify, export) must never depend on the benchmark side (bank, bank/sealed,
// bench) and must never read hidden labels. Packages that do not exist yet are
// skipped and are covered automatically once their directory appears.

import (
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

const modulePath = "github.com/audspect/bas"

var generatorPkgs = []string{"model", "property", "generate", "novelty", "verify", "export"}

var forbiddenImports = []string{
	modulePath + "/internal/aleef/bank",
	modulePath + "/internal/aleef/bench",
}

var hExpr = regexp.MustCompile(`\bH[1-8]\b`)

func isForbidden(path string) bool {
	for _, f := range forbiddenImports {
		if path == f || strings.HasPrefix(path, f+"/") {
			return true
		}
	}
	return false
}

// goFiles returns non-test .go files under dir (recursive); nil if dir is absent.
func goFiles(dir string) []string {
	var out []string
	_ = filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		if strings.HasSuffix(p, ".go") && !strings.HasSuffix(p, "_test.go") {
			out = append(out, p)
		}
		return nil
	})
	return out
}

// existingPkgDirs returns aleef/<pkg> dirs under root that exist and hold Go files.
func existingPkgDirs(root string, pkgs []string) []string {
	var out []string
	for _, p := range pkgs {
		d := filepath.Join(root, "internal", "aleef", p)
		if len(goFiles(d)) > 0 {
			out = append(out, d)
		}
	}
	return out
}

// sourceImportViolations parses direct imports (used for fixtures).
func sourceImportViolations(root string, pkgs []string) []string {
	var v []string
	for _, d := range existingPkgDirs(root, pkgs) {
		for _, f := range goFiles(d) {
			af, err := parser.ParseFile(token.NewFileSet(), f, nil, parser.ImportsOnly)
			if err != nil {
				v = append(v, f+": parse error: "+err.Error())
				continue
			}
			for _, imp := range af.Imports {
				p, _ := strconv.Unquote(imp.Path.Value)
				if isForbidden(p) {
					v = append(v, f+" imports "+p)
				}
			}
		}
	}
	return v
}

// depImportViolations uses `go list -deps` (transitive) from the module root.
func depImportViolations(t *testing.T, root string, pkgs []string) []string {
	var v []string
	for _, d := range existingPkgDirs(root, pkgs) {
		rel, _ := filepath.Rel(root, d)
		cmd := exec.Command("go", "list", "-deps", "-f", "{{.ImportPath}}", "./"+filepath.ToSlash(rel)+"/...")
		cmd.Dir = root
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("go list %s: %v\n%s", rel, err, out)
		}
		for _, line := range strings.Fields(string(out)) {
			if isForbidden(line) {
				v = append(v, rel+" transitively imports "+line)
			}
		}
	}
	return v
}

// labelViolations scans non-test sources for labels.json and H1..H8.
func labelViolations(root string, pkgs []string) []string {
	var v []string
	for _, d := range existingPkgDirs(root, pkgs) {
		for _, f := range goFiles(d) {
			b, err := os.ReadFile(f)
			if err != nil {
				v = append(v, f+": "+err.Error())
				continue
			}
			s := string(b)
			if strings.Contains(s, "labels.json") {
				v = append(v, f+" mentions labels.json")
			}
			if m := hExpr.FindString(s); m != "" {
				v = append(v, f+" mentions "+m)
			}
		}
	}
	return v
}

func moduleRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		t.Fatalf("module root not found at %s: %v", root, err)
	}
	return root
}

func TestGeneratorSideNeverImportsBenchmark(t *testing.T) {
	if v := depImportViolations(t, moduleRoot(t), generatorPkgs); len(v) > 0 {
		t.Fatalf("isolation violations:\n%s", strings.Join(v, "\n"))
	}
}

func TestNoHiddenLabelReads(t *testing.T) {
	if v := labelViolations(moduleRoot(t), generatorPkgs); len(v) > 0 {
		t.Fatalf("hidden label reads:\n%s", strings.Join(v, "\n"))
	}
}

func writeFixture(t *testing.T, root string) {
	t.Helper()
	dir := filepath.Join(root, "internal", "aleef", "generate")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	imp := "package generate\n\nimport _ \"" + modulePath + "/internal/aleef/bank/sealed\"\n"
	lbl := "package generate\n\nvar x = \"labels.json\"\nvar y = \"H3\"\n"
	for name, body := range map[string]string{"imp.go": imp, "lbl.go": lbl} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func TestGuardDetectsViolation(t *testing.T) {
	root := t.TempDir()
	writeFixture(t, root)
	if v := sourceImportViolations(root, generatorPkgs); len(v) == 0 {
		t.Fatal("expected import violation")
	}
	if v := labelViolations(root, generatorPkgs); len(v) < 2 {
		t.Fatalf("expected label violations, got %v", v)
	}
	// absent packages are skipped, not errors
	if v := labelViolations(t.TempDir(), generatorPkgs); len(v) != 0 {
		t.Fatalf("empty root should be clean: %v", v)
	}
}
