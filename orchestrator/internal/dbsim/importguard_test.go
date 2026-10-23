package dbsim

import (
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Ruling R-AG: internal/dbsim (reached by internal/db and testutil) must never
// import detectverify or dbcorrelate. detectverify imports internal/verification
// whose tests import testutil -> db -> dbsim, a test-only import cycle that
// `go build ./...` does not reveal.
var forbiddenForDBSim = []string{"internal/detectverify", "internal/dbsim/dbcorrelate", "internal/dbsim/dbrun"}

func TestDBSimDoesNotImportDetectverify(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		af, err := parser.ParseFile(fset, f, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatal(err)
		}
		for _, imp := range af.Imports {
			p := strings.Trim(imp.Path.Value, `"`)
			for _, bad := range forbiddenForDBSim {
				if strings.HasSuffix(p, bad) {
					t.Errorf("%s imports %s (forbidden, ruling R-AG)", f, p)
				}
			}
		}
	}
}

func TestDBSimTransitiveDepsExcludeDetectverify(t *testing.T) {
	goBin, err := exec.LookPath("go")
	if err != nil {
		t.Skip("go tool not on PATH")
	}
	cmd := exec.Command(goBin, "list", "-deps", ".")
	cmd.Env = os.Environ()
	out, err := cmd.Output()
	if err != nil {
		t.Skipf("go list failed: %v", err)
	}
	for _, l := range strings.Split(string(out), "\n") {
		l = strings.TrimSpace(l)
		for _, bad := range forbiddenForDBSim {
			if strings.HasSuffix(l, bad) {
				t.Errorf("internal/dbsim transitively depends on %s", l)
			}
		}
	}
}
