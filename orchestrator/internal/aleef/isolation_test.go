package aleef_test

// Isolation guard: the generator side (model, property, generate, novelty,
// verify, export) must never depend on the benchmark side (bank, bank/sealed,
// bench) and must never read hidden labels. Packages that do not exist yet are
// skipped and are covered automatically once their directory appears.

import (
	"fmt"
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

var generatorPkgs = []string{"model", "property", "generate", "novelty", "verify", "export", "exec", "safety", "campaign"}

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

// goFiles returns .go files under dir (recursive). A missing dir yields nil, nil;
// any other walk error is returned (fail closed).
func goFiles(dir string, includeTests bool) ([]string, error) {
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		return nil, nil
	}
	var out []string
	err := filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(p, ".go") {
			return nil
		}
		if !includeTests && strings.HasSuffix(p, "_test.go") {
			return nil
		}
		out = append(out, p)
		return nil
	})
	return out, err
}

// existingPkgDirs returns aleef/<pkg> dirs under root holding any .go file (tests included).
func existingPkgDirs(root string, pkgs []string) ([]string, error) {
	var out []string
	for _, p := range pkgs {
		d := filepath.Join(root, "internal", "aleef", p)
		fs, err := goFiles(d, true)
		if err != nil {
			return nil, err
		}
		if len(fs) > 0 {
			out = append(out, d)
		}
	}
	return out, nil
}

// checkImports reports forbidden imports: direct imports of every .go file
// (tests and external _test packages included) and the transitive closure via
// `go list -deps -test` run from moduleRoot.
func checkImports(moduleRoot string, pkgs []string) ([]string, error) {
	dirs, err := existingPkgDirs(moduleRoot, pkgs)
	if err != nil {
		return nil, err
	}
	var v []string
	for _, d := range dirs {
		files, err := goFiles(d, true)
		if err != nil {
			return nil, err
		}
		for _, f := range files {
			af, err := parser.ParseFile(token.NewFileSet(), f, nil, parser.ImportsOnly)
			if err != nil {
				return nil, err
			}
			for _, imp := range af.Imports {
				p, _ := strconv.Unquote(imp.Path.Value)
				if isForbidden(p) {
					v = append(v, f+" imports "+p)
				}
			}
		}
		rel, _ := filepath.Rel(moduleRoot, d)
		cmd := exec.Command("go", "list", "-deps", "-test", "-f", "{{.ImportPath}}", "./"+filepath.ToSlash(rel)+"/...")
		cmd.Dir = moduleRoot
		cmd.Env = append(os.Environ(), "GOFLAGS=", "GOWORK=off")
		out, err := cmd.CombinedOutput()
		if err != nil {
			return nil, fmt.Errorf("go list %s: %v\n%s", rel, err, out)
		}
		for _, line := range strings.Split(string(out), "\n") {
			line = strings.TrimSpace(line)
			if i := strings.Index(line, " ["); i >= 0 {
				line = line[:i]
			}
			if line != "" && isForbidden(line) {
				v = append(v, rel+" transitively imports "+line)
			}
		}
	}
	return v, nil
}

// checkLabels scans NON-TEST sources for labels.json and H1..H8.
func checkLabels(moduleRoot string, pkgs []string) ([]string, error) {
	dirs, err := existingPkgDirs(moduleRoot, pkgs)
	if err != nil {
		return nil, err
	}
	var v []string
	for _, d := range dirs {
		files, err := goFiles(d, false)
		if err != nil {
			return nil, err
		}
		for _, f := range files {
			b, err := os.ReadFile(f)
			if err != nil {
				return nil, err
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
	return v, nil
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
	v, err := checkImports(moduleRoot(t), generatorPkgs)
	if err != nil {
		t.Fatal(err)
	}
	if len(v) > 0 {
		t.Fatalf("isolation violations:\n%s", strings.Join(v, "\n"))
	}
}

func TestNoHiddenLabelReads(t *testing.T) {
	v, err := checkLabels(moduleRoot(t), generatorPkgs)
	if err != nil {
		t.Fatal(err)
	}
	if len(v) > 0 {
		t.Fatalf("hidden label reads:\n%s", strings.Join(v, "\n"))
	}
}

func writeFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

// tempModule builds a stub module (same module path) with bank, bank/sealed,
// bench stubs plus the given files under internal/aleef/generate.
func tempModule(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "go.mod"), "module "+modulePath+"\n\ngo 1.21\n")
	a := filepath.Join(root, "internal", "aleef")
	writeFile(t, filepath.Join(a, "bank", "b.go"), "package bank\n")
	writeFile(t, filepath.Join(a, "bank", "sealed", "s.go"), "package sealed\n")
	writeFile(t, filepath.Join(a, "bench", "b.go"), "package bench\n")
	for name, body := range files {
		writeFile(t, filepath.Join(a, "generate", name), body)
	}
	return root
}

func TestGuardDetectsViolation(t *testing.T) {
	imp := func(pkg, path string) string {
		return "package " + pkg + "\n\nimport _ \"" + modulePath + "/internal/aleef/" + path + "\"\n"
	}
	cases := []struct {
		name  string
		files map[string]string
	}{
		{"nontest imports bank", map[string]string{"g.go": imp("generate", "bank")}},
		{"nontest imports bank/sealed", map[string]string{"g.go": imp("generate", "bank/sealed")}},
		{"in-package test imports bank", map[string]string{"g.go": "package generate\n", "g_test.go": imp("generate", "bank")}},
		{"external test imports bench", map[string]string{"g.go": "package generate\n", "g_test.go": imp("generate_test", "bench")}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			root := tempModule(t, c.files)
			v, err := checkImports(root, generatorPkgs)
			if err != nil {
				t.Fatal(err)
			}
			if len(v) == 0 {
				t.Fatal("expected violation, got none")
			}
			var transitive bool
			for _, s := range v {
				transitive = transitive || strings.Contains(s, "transitively")
			}
			if !transitive {
				t.Fatalf("go list path did not report: %v", v)
			}
		})
	}
	t.Run("clean", func(t *testing.T) {
		root := tempModule(t, map[string]string{"g.go": "package generate\n", "g_test.go": "package generate_test\n"})
		v, err := checkImports(root, generatorPkgs)
		if err != nil || len(v) != 0 {
			t.Fatalf("expected clean, got %v / %v", v, err)
		}
	})
	t.Run("test-only package counts as existing", func(t *testing.T) {
		root := tempModule(t, map[string]string{"g_test.go": imp("generate", "bank")})
		v, err := checkImports(root, generatorPkgs)
		if err != nil || len(v) == 0 {
			t.Fatalf("expected violation, got %v / %v", v, err)
		}
	})
	t.Run("labels", func(t *testing.T) {
		root := tempModule(t, map[string]string{"g.go": "package generate\n\nvar x = \"labels.json\"\nvar y = \"H3\"\n"})
		v, err := checkLabels(root, generatorPkgs)
		if err != nil || len(v) < 2 {
			t.Fatalf("expected 2 label violations, got %v / %v", v, err)
		}
		root = tempModule(t, map[string]string{"g.go": "package generate\n", "g_test.go": "package generate\n\nvar y = \"H3\"\n"})
		if v, err := checkLabels(root, generatorPkgs); err != nil || len(v) != 0 {
			t.Fatalf("test files should be exempt: %v / %v", v, err)
		}
	})
	t.Run("absent packages skipped", func(t *testing.T) {
		v, err := checkImports(t.TempDir(), generatorPkgs)
		if err != nil || len(v) != 0 {
			t.Fatalf("%v / %v", v, err)
		}
	})
}
