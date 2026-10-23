package bench

import (
	"context"
	"errors"
	"fmt"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/audspect/bas/internal/aleef/store"
)

// All labels, operations and ids below are SYNTHETIC.

func synthLabels(n int) []Label {
	var ls []Label
	for i := 1; i <= n; i++ {
		ls = append(ls, Label{ID: fmt.Sprintf("T%d", i), Operation: fmt.Sprintf("op_%d", i), Note: "synthetic"})
	}
	return ls
}

func goodFinding(i int) (Finding, string) {
	id := fmt.Sprintf("f%d", i)
	return Finding{Finding: store.Finding{ID: id, TestID: fmt.Sprintf("tt%d", i), Property: "p"}, Operation: fmt.Sprintf("op_%d", i)}, id
}

// vulnOutcome builds an outcome in which flaws 1..k are fully evidenced.
func vulnOutcome(k int) RunOutcome {
	o := RunOutcome{
		TestsGenerated: 40, TestsRun: 38,
		CoveragePerOperation: map[string]int{},
		SafetyChecks:         map[string]bool{"no_prod_target": true, "engagement_enforced": true},
		ControlsOK:           map[string]bool{}, RegressionSaved: map[string]bool{}, Reproductions: map[string]int{},
	}
	for i := 1; i <= 8; i++ {
		o.CoveragePerOperation[fmt.Sprintf("op_%d", i)] = 3
	}
	for i := 1; i <= k; i++ {
		f, id := goodFinding(i)
		o.Findings = append(o.Findings, f)
		o.ControlsOK[id], o.RegressionSaved[id], o.Reproductions[id] = true, true, 3
	}
	return o
}

func fixedOutcome() RunOutcome {
	return RunOutcome{TestsGenerated: 40, TestsRun: 40, CoveragePerOperation: map[string]int{"op_1": 5},
		SafetyChecks: map[string]bool{"no_prod_target": true, "engagement_enforced": true}}
}

func stub(fixed, vuln RunOutcome) func(string) (RunOutcome, error) {
	return func(b string) (RunOutcome, error) {
		if b == BuildFixed {
			return fixed, nil
		}
		if b == BuildVulnerable {
			return vuln, nil
		}
		return RunOutcome{}, errors.New("bad build " + b)
	}
}

func TestEvaluateReportsPerFlawResults(t *testing.T) {
	rep, err := Evaluate(context.Background(), synthLabels(8), stub(fixedOutcome(), vulnOutcome(6)))
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.PerFlaw) != 8 {
		t.Fatalf("per flaw %d", len(rep.PerFlaw))
	}
	for i, fr := range rep.PerFlaw {
		want := i < 6
		if fr.Verified != want {
			t.Fatalf("flaw %s verified=%v want %v (%s)", fr.ID, fr.Verified, want, fr.Reason)
		}
		if want && (len(fr.FindingIDs) != 1 || fr.Reproductions != 3 || !fr.Controls || !fr.Regression) {
			t.Fatalf("flaw %s details %+v", fr.ID, fr)
		}
		if !want && fr.Reason != ReasonNotFound {
			t.Fatalf("flaw %s reason %q", fr.ID, fr.Reason)
		}
	}
	if rep.Verified != 6 || rep.Recall != 0.75 || !rep.Pass {
		t.Fatalf("verified=%d recall=%v pass=%v %v", rep.Verified, rep.Recall, rep.Pass, rep.PassReasons)
	}
}

func TestEvaluateFailsMilestoneOnAnyFixedBuildVerifiedFinding(t *testing.T) {
	fx := fixedOutcome()
	f, id := goodFinding(1)
	fx.Findings = []Finding{f}
	fx.ControlsOK = map[string]bool{id: true}
	rep, err := Evaluate(context.Background(), synthLabels(8), stub(fx, vulnOutcome(8)))
	if err != nil {
		t.Fatal(err)
	}
	if rep.FixedBuildVerified != 1 || rep.Pass || len(rep.FixedBuildFindings) != 1 {
		t.Fatalf("fixed=%d pass=%v list=%v", rep.FixedBuildVerified, rep.Pass, rep.FixedBuildFindings)
	}
	if !strings.Contains(strings.Join(rep.PassReasons, "\n"), "FAIL") {
		t.Fatal("reasons lack FAIL")
	}
}

func TestEvaluatePassRequiresSixOfEightAndAllControls(t *testing.T) {
	ctx := context.Background()
	if rep, _ := Evaluate(ctx, synthLabels(8), stub(fixedOutcome(), vulnOutcome(6))); !rep.Pass {
		t.Fatalf("6/8 should pass: %v", rep.PassReasons)
	}
	if rep, _ := Evaluate(ctx, synthLabels(8), stub(fixedOutcome(), vulnOutcome(5))); rep.Pass || rep.Verified != 5 {
		t.Fatalf("5/8 should fail: %d %v", rep.Verified, rep.Pass)
	}
	for name, mutate := range map[string]func(*RunOutcome){
		"no regression":  func(o *RunOutcome) { o.RegressionSaved["f6"] = false },
		"control failed": func(o *RunOutcome) { o.ControlsOK["f6"] = false },
		"two repros":     func(o *RunOutcome) { o.Reproductions["f6"] = 2 },
	} {
		v := vulnOutcome(6)
		mutate(&v)
		rep, _ := Evaluate(ctx, synthLabels(8), stub(fixedOutcome(), v))
		if rep.Pass || rep.Verified != 5 {
			t.Fatalf("%s: pass=%v verified=%d", name, rep.Pass, rep.Verified)
		}
		if rep.PerFlaw[5].Verified || rep.PerFlaw[5].Reason != ReasonIncompleteEvidence {
			t.Fatalf("%s: flaw 6 %+v", name, rep.PerFlaw[5])
		}
	}
	v := vulnOutcome(8)
	v.SafetyChecks["engagement_enforced"] = false
	if rep, _ := Evaluate(ctx, synthLabels(8), stub(fixedOutcome(), v)); rep.Pass {
		t.Fatal("failed safety check must fail")
	}
	v = vulnOutcome(8)
	v.SafetyChecks = nil
	if rep, _ := Evaluate(ctx, synthLabels(8), stub(fixedOutcome(), v)); rep.Pass {
		t.Fatal("missing safety checks must fail")
	}
}

func TestRequiredDetections(t *testing.T) {
	for n, want := range map[int]int{8: 6, 4: 3, 1: 1, 10: 8} {
		if got := RequiredDetections(n); got != want {
			t.Fatalf("n=%d got %d want %d", n, got, want)
		}
	}
}

func TestEvaluateReportsExactCoverageNotJustRecall(t *testing.T) {
	v := vulnOutcome(6)
	v.CoveragePerOperation["op_zero"] = 0
	rep, _ := Evaluate(context.Background(), synthLabels(8), stub(fixedOutcome(), v))
	if n, ok := rep.CoveragePerOperation["op_zero"]; !ok || n != 0 {
		t.Fatalf("zero op missing: %v", rep.CoveragePerOperation)
	}
	if rep.TestsGenerated != 40 || rep.TestsRun != 38 {
		t.Fatalf("totals %d/%d", rep.TestsGenerated, rep.TestsRun)
	}
	md := rep.Markdown()
	if !strings.Contains(md, "op_zero") || !strings.Contains(md, "NO TESTS") {
		t.Fatalf("markdown lacks explicit zero-test op:\n%s", md)
	}
}

func TestCandidateDoesNotCountAsDetected(t *testing.T) {
	v := vulnOutcome(5)
	v.Candidates = []Finding{{Finding: store.Finding{ID: "c6", TestID: "tt6"}, Operation: "op_6"}}
	rep, _ := Evaluate(context.Background(), synthLabels(8), stub(fixedOutcome(), v))
	if rep.Verified != 5 || rep.Pass {
		t.Fatalf("candidate counted: %d", rep.Verified)
	}
	if fr := rep.PerFlaw[5]; fr.Verified || fr.Reason != ReasonCandidateOnly {
		t.Fatalf("flaw 6: %+v", fr)
	}
}

func TestUnlabelledVerifiedFindingIsFlaggedNotScored(t *testing.T) {
	v := vulnOutcome(5)
	v.Findings = append(v.Findings, Finding{Finding: store.Finding{ID: "fx", TestID: "ttx"}, Operation: "op_unlabelled"})
	v.ControlsOK["fx"], v.RegressionSaved["fx"], v.Reproductions["fx"] = true, true, 3
	rep, _ := Evaluate(context.Background(), synthLabels(8), stub(fixedOutcome(), v))
	if rep.Verified != 5 || rep.Pass {
		t.Fatalf("unlabelled scored: %d", rep.Verified)
	}
	if len(rep.Unlabelled) != 1 || rep.Unlabelled[0].Operation != "op_unlabelled" {
		t.Fatalf("unlabelled %+v", rep.Unlabelled)
	}
	if !strings.Contains(rep.Markdown(), "human review") {
		t.Fatal("markdown must flag for human review")
	}
}

func TestOperationAliasMatchesMethodPath(t *testing.T) {
	labels := []Label{{ID: "T1", Operation: "get /thing/{id}"}}
	v := vulnOutcome(0)
	v.Findings = []Finding{{Finding: store.Finding{ID: "f1"}, Operation: "get_thing_by_id"}}
	v.ControlsOK["f1"], v.RegressionSaved["f1"], v.Reproductions["f1"] = true, true, 3
	v.OperationAliases = map[string]string{"get_thing_by_id": "GET /thing/{id}"}
	rep, _ := Evaluate(context.Background(), labels, stub(fixedOutcome(), v))
	if rep.Verified != 1 {
		t.Fatalf("alias not matched: %+v", rep.PerFlaw)
	}
}

func TestOneFindingCreditsOneFlaw(t *testing.T) {
	labels := []Label{{ID: "T1", Operation: "op_1"}, {ID: "T2", Operation: "op_1"}}
	rep, _ := Evaluate(context.Background(), labels, stub(fixedOutcome(), vulnOutcome(1)))
	if rep.Verified != 1 {
		t.Fatalf("one finding credited %d flaws", rep.Verified)
	}
}

func TestEvaluateRunErrorIsAnError(t *testing.T) {
	_, err := Evaluate(context.Background(), synthLabels(8), func(string) (RunOutcome, error) { return RunOutcome{}, errors.New("boom") })
	if err == nil {
		t.Fatal("want error")
	}
}

func TestMarkdownContainsLimitationsAndNoRealBankClaim(t *testing.T) {
	rep, _ := Evaluate(context.Background(), synthLabels(8), stub(fixedOutcome(), vulnOutcome(6)))
	md := rep.Markdown()
	for _, want := range []string{"Summary", "Per flaw", "Coverage per operation", "Safety checks", "Unlabelled verified findings", "Fixed-build findings", "Limitations", "lab", "synthetic", "No real-bank readiness"} {
		if !strings.Contains(md, want) {
			t.Fatalf("markdown lacks %q", want)
		}
	}
}

func TestFixedOnlyMarkdown(t *testing.T) {
	md := FixedOnlyMarkdown(fixedOutcome())
	if !strings.Contains(md, "Fixed-build rehearsal") || !strings.Contains(md, "op_1") || !strings.Contains(md, "No real-bank readiness") {
		t.Fatal(md)
	}
}

// ---- labels ----

func writeLabels(t *testing.T, dir, body string) string {
	t.Helper()
	p := filepath.Join(dir, "labels.json")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoadLabelsValidation(t *testing.T) {
	dir := t.TempDir()
	good := `[{"id":"T1","operation":"op_a","note":"n"},{"id":"T2","operation":"GET /x"}]`
	ls, err := LoadLabels(writeLabels(t, dir, good))
	if err != nil || len(ls) != 2 {
		t.Fatalf("good: %v %v", ls, err)
	}
	for name, body := range map[string]string{
		"dup id":        `[{"id":"T1","operation":"a"},{"id":"T1","operation":"b"}]`,
		"empty id":      `[{"id":"","operation":"a"}]`,
		"empty op":      `[{"id":"T1","operation":" "}]`,
		"empty list":    `[]`,
		"not json":      `nope`,
		"unknown field": `[{"id":"T1","operation":"a","trigger":"x"}]`,
	} {
		if _, err := LoadLabels(writeLabels(t, dir, body)); err == nil {
			t.Fatalf("%s: want error", name)
		}
	}
	if _, err := LoadLabels(filepath.Join(dir, "missing.json")); err == nil {
		t.Fatal("missing file must error")
	}
}

func TestLoadLabelsRefusesPathInsideRepo(t *testing.T) {
	repo := t.TempDir()
	if err := os.Mkdir(filepath.Join(repo, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	sub := filepath.Join(repo, "deep", "dir")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	p := writeLabels(t, sub, `[{"id":"T1","operation":"a"}]`)
	_, err := LoadLabels(p)
	if err == nil || !strings.Contains(err.Error(), "repository") {
		t.Fatalf("want repo refusal, got %v", err)
	}
	// a worktree-style .git FILE also counts
	repo2 := t.TempDir()
	if err := os.WriteFile(filepath.Join(repo2, ".git"), []byte("gitdir: x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadLabels(writeLabels(t, repo2, `[{"id":"T1","operation":"a"}]`)); err == nil {
		t.Fatal("want refusal for .git file")
	}
}

// ---- repo hygiene ----

func repoRoot(t *testing.T) string {
	t.Helper()
	d, _ := filepath.Abs(".")
	for {
		if _, err := os.Stat(filepath.Join(d, ".git")); err == nil {
			return d
		}
		p := filepath.Dir(d)
		if p == d {
			t.Fatal("repo root not found")
		}
		d = p
	}
}

func TestNoRealLabelsFileInRepo(t *testing.T) {
	root := repoRoot(t)
	var bad []string
	_ = filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "node_modules", "testdata":
				if p != root {
					return filepath.SkipDir
				}
			}
			return nil
		}
		if strings.EqualFold(d.Name(), "labels.json") {
			bad = append(bad, p)
		}
		return nil
	})
	if len(bad) > 0 {
		t.Fatalf("labels.json must never be in the repo: %v", bad)
	}
	hExpr := regexp.MustCompile(`\bH[1-8]\b`)
	files, _ := filepath.Glob("*.go")
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		b, _ := os.ReadFile(f)
		if m := hExpr.FindString(string(b)); m != "" {
			t.Fatalf("%s mentions %s", f, m)
		}
	}
}

func TestBenchLibraryDoesNotImportBank(t *testing.T) {
	files, _ := filepath.Glob("*.go")
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		af, err := parser.ParseFile(token.NewFileSet(), f, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatal(err)
		}
		for _, imp := range af.Imports {
			p, _ := strconv.Unquote(imp.Path.Value)
			if strings.Contains(p, "/aleef/bank") || strings.Contains(p, "/aleef/campaign") {
				t.Fatalf("%s imports %s: cmd wires the bank in", f, p)
			}
		}
	}
}
