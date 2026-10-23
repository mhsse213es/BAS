package verify

import (
	"context"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/audspect/bas/internal/aleef/exec"
	"github.com/audspect/bas/internal/aleef/generate"
)

func stable(int) bool { return true }

func ownTest(t *testing.T) generate.Test   { return generatedFor(t, "P-OWN-1", "getV2") }
func roleTest_(t *testing.T) generate.Test { return generatedFor(t, "P-ROLE-1", "archive") }

func run(t *testing.T, env *fakeEnv, rec *fakeRec, opt Options, x generate.Test) Verdict {
	t.Helper()
	v, err := New(env, rec, opt).Verify(context.Background(), x)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	return v
}

func TestStableFlawBecomesVerified(t *testing.T) {
	ty := newToy()
	ty.readFlaw = stable
	env, rec := newEnv(t, ty), newRec()
	x := ownTest(t)
	v := run(t, env, rec, Options{RunID: "r1"}, x)
	if v.State != StateVerified || v.Reproductions != 3 || !v.OwnerControl || !v.NegativeControl || v.EvidenceHash == "" {
		t.Fatalf("verdict %+v", v)
	}
	if len(rec.findings) != 1 || rec.states["f-1"] != "verified" || rec.hash["f-1"] != v.EvidenceHash {
		t.Fatalf("recorder: %+v %+v", rec.states, rec.hash)
	}
	if got := strings.Join(rec.history, ","); got != "f-1:candidate,f-1:verified" {
		t.Fatalf("history %s", got)
	}
	// execution numbering: test 1..3, owner control 4..6, negative control 7..9
	want := []string{
		x.ID + "#1", x.OwnerControl.ID + "#4", x.NegativeControl.ID + "#7",
		x.ID + "#2", x.OwnerControl.ID + "#5", x.NegativeControl.ID + "#8",
		x.ID + "#3", x.OwnerControl.ID + "#6", x.NegativeControl.ID + "#9",
	}
	if strings.Join(rec.results, ",") != strings.Join(want, ",") {
		t.Fatalf("results %v\nwant %v", rec.results, want)
	}
}

func TestFlakyFlawIsNotVerified(t *testing.T) {
	ty := newToy()
	ty.readFlaw = func(n int) bool { return n%2 == 1 } // fails 1 in 2
	env, rec := newEnv(t, ty), newRec()
	v := run(t, env, rec, Options{}, ownTest(t))
	if v.State != StateRejected || !strings.HasPrefix(v.Reason, "not reproducible (1/3)") || v.EvidenceHash != "" {
		t.Fatalf("verdict %+v", v)
	}
	if rec.states["f-1"] != "rejected" {
		t.Fatalf("finding state %q", rec.states["f-1"])
	}
}

func TestIndiscriminateOracleRejectedByNegativeControl(t *testing.T) {
	ty := newToy()
	ty.roleFlaw = true // the test really fires
	ty.noisy = true    // but every read perturbs the object, so the oracle fires on everything
	env, rec := newEnv(t, ty), newRec()
	v := run(t, env, rec, Options{}, roleTest_(t))
	if v.State != StateRejected || !strings.Contains(v.Reason, "negative control fired") || v.NegativeControl {
		t.Fatalf("verdict %+v", v)
	}
	if rec.states["f-1"] != "rejected" {
		t.Fatalf("finding state %q", rec.states["f-1"])
	}
	// control: without the noise the same flaw verifies.
	ty2 := newToy()
	ty2.roleFlaw = true
	v = run(t, newEnv(t, ty2), newRec(), Options{}, roleTest_(t))
	if v.State != StateVerified {
		t.Fatalf("clean oracle: %+v", v)
	}
}

func TestOwnerControlFailureRejects(t *testing.T) {
	ty := newToy()
	ty.roleFlaw = true
	ty.adminNoArchive = true // the legitimate actor is refused: the plumbing is broken
	env, rec := newEnv(t, ty), newRec()
	v := run(t, env, rec, Options{}, roleTest_(t))
	if v.State != StateRejected || !strings.HasPrefix(v.Reason, "owner control failed") || v.OwnerControl {
		t.Fatalf("verdict %+v", v)
	}
}

func TestInconclusiveIsUnconfirmed(t *testing.T) {
	ty := newToy()
	ty.crossStatus = 500 // the attack gets a server fault: nothing can be concluded
	env, rec := newEnv(t, ty), newRec()
	v := run(t, env, rec, Options{}, ownTest(t))
	if v.State != StateUnconfirmed || len(rec.findings) != 0 {
		t.Fatalf("verdict %+v findings %v", v, rec.findings)
	}
}

func TestCleanupFailureBlocksVerification(t *testing.T) {
	ty := newToy()
	ty.readFlaw = stable
	env, rec := newEnv(t, ty), newRec()
	env.orphan = &modelOrphan
	v := run(t, env, rec, Options{}, ownTest(t))
	if v.State != StateUnconfirmed || v.Reason != "cleanup failed" || len(v.Orphans) != 1 || v.Orphans[0].ID != "item-a1" {
		t.Fatalf("verdict %+v", v)
	}
	if rec.states["f-1"] != "unconfirmed" || v.EvidenceHash != "" {
		t.Fatalf("finding %q hash %q", rec.states["f-1"], v.EvidenceHash)
	}
	// a real compensation failure (the application refuses the delete) is the same.
	ty2 := newToy()
	ty2.readFlaw = stable
	ty2.delFails = true
	rec2 := newRec()
	v = run(t, newEnv(t, ty2), rec2, Options{}, ownTest(t))
	if v.State != StateUnconfirmed || v.Reason != "cleanup failed" || len(v.Orphans) == 0 {
		t.Fatalf("real failure: %+v", v)
	}
	for _, s := range rec2.states {
		if s == "verified" {
			t.Fatal("verified despite orphans")
		}
	}
}

func TestHaltBlocksVerification(t *testing.T) {
	// halted before anything runs
	ty := newToy()
	ty.readFlaw = stable
	env, rec := newEnv(t, ty), newRec()
	v := run(t, env, rec, Options{Halt: func() error { return errors.New("breaker open") }}, ownTest(t))
	if v.State != StateUnconfirmed || v.Reason != "halted: breaker open" || env.fresh.Load() != 0 || len(rec.findings) != 0 {
		t.Fatalf("verdict %+v fresh=%d", v, env.fresh.Load())
	}
	// halted after the finding exists: the candidate is closed as unconfirmed.
	env2, rec2 := newEnv(t, ty), newRec()
	calls := 0
	v = run(t, env2, rec2, Options{Halt: func() error {
		calls++
		if calls > 3 {
			return errors.New("breaker open")
		}
		return nil
	}}, ownTest(t))
	if v.State != StateUnconfirmed || !strings.HasPrefix(v.Reason, "halted:") || rec2.states["f-1"] != "unconfirmed" {
		t.Fatalf("mid-run halt: %+v %v", v, rec2.states)
	}
}

func TestControlsBlockedIsUnconfirmed(t *testing.T) {
	ty := newToy()
	ty.readFlaw = stable
	env, rec := newEnv(t, ty), newRec()
	x := ownTest(t)
	x.ControlsBlocked = true
	v := run(t, env, rec, Options{}, x)
	if v.State != StateUnconfirmed || v.Reason != "controls unavailable" || env.fresh.Load() != 0 || len(rec.findings) != 0 {
		t.Fatalf("verdict %+v", v)
	}
	x = ownTest(t)
	x.NegativeControl = nil
	v = run(t, env, rec, Options{}, x)
	if v.State != StateUnconfirmed || env.fresh.Load() != 0 {
		t.Fatalf("nil control: %+v", v)
	}
}

func TestCleanFirstRoundCreatesNoFinding(t *testing.T) {
	ty := newToy() // correct application
	env, rec := newEnv(t, ty), newRec()
	v := run(t, env, rec, Options{}, ownTest(t))
	if v.State != StateClean || len(rec.findings) != 0 || env.fresh.Load() != 1 {
		t.Fatalf("verdict %+v findings %v fresh=%d", v, rec.findings, env.fresh.Load())
	}
}

func TestFreshEnvironmentPerRun(t *testing.T) {
	ty := newToy()
	ty.readFlaw = stable
	env, rec := newEnv(t, ty), newRec()
	run(t, env, rec, Options{}, ownTest(t))
	if env.fresh.Load() != 9 || env.cleaned.Load() != 9 {
		t.Fatalf("Fresh called %d times, cleaned %d, want 9 and 9", env.fresh.Load(), env.cleaned.Load())
	}
}

func TestInterruptionIsUnconfirmed(t *testing.T) {
	ty := newToy()
	ty.readFlaw = stable
	env, rec := newEnv(t, ty), newRec()
	ctx, cancel := context.WithCancel(context.Background())
	calls := 0
	v, err := New(env, rec, Options{Halt: func() error {
		calls++
		if calls == 3 {
			cancel()
		}
		return nil
	}}).Verify(ctx, ownTest(t))
	if err != nil {
		t.Fatal(err)
	}
	if v.State != StateUnconfirmed || v.Reason != "interrupted" || rec.states["f-1"] != "unconfirmed" {
		t.Fatalf("verdict %+v %v", v, rec.states)
	}
}

func TestEvidenceHashDeterministicAndSensitive(t *testing.T) {
	hashOf := func() string {
		ty := newToy()
		ty.readFlaw = stable
		return run(t, newEnv(t, ty), newRec(), Options{}, ownTest(t)).EvidenceHash
	}
	a, b := hashOf(), hashOf()
	if a == "" || a != b {
		t.Fatalf("hash not deterministic: %q vs %q", a, b)
	}
	// direct sensitivity checks on the canonical form
	x := ownTest(t)
	base := []execEvidence{{Role: "test", Round: 1, Finding: "yes", Exchanges: []exchangeEvidence{{StepID: "s", Status: 200, BodySHA: "aa"}}}}
	h0, _ := evidenceHash(x, base)
	mut := func(f func(e []execEvidence)) string {
		c := []execEvidence{base[0]}
		c[0].Exchanges = append([]exchangeEvidence(nil), base[0].Exchanges...)
		f(c)
		h, _ := evidenceHash(x, c)
		return h
	}
	for name, h := range map[string]string{
		"status": mut(func(e []execEvidence) { e[0].Exchanges[0].Status = 403 }),
		"body":   mut(func(e []execEvidence) { e[0].Exchanges[0].BodySHA = "bb" }),
		"reason": mut(func(e []execEvidence) { e[0].Reason = "other" }),
	} {
		if h == h0 {
			t.Errorf("hash insensitive to %s", name)
		}
	}
	y := x
	y.Params = map[string]string{"k": "v"}
	if h, _ := evidenceHash(y, base); h == h0 {
		t.Error("hash insensitive to params")
	}
	// an environment whose redacted responses differ yields a different hash
	ty := newToy()
	ty.readFlaw = stable
	ty.noisy = true // adds a hits field to every read body
	if c := run(t, newEnv(t, ty), newRec(), Options{}, ownTest(t)); c.State == StateVerified && c.EvidenceHash == a {
		t.Error("hash did not change when response bodies changed")
	}
}

func TestVerdictReasonsCarryNoBodies(t *testing.T) {
	ty := newToy()
	ty.readFlaw = stable
	v := run(t, newEnv(t, ty), newRec(), Options{}, ownTest(t))
	if strings.Contains(v.Reason, "ALEEF-CANARY") || strings.Contains(v.Reason, "tok-") {
		t.Fatalf("reason leaks: %q", v.Reason)
	}
}

// TestMarkVerifiedOnlyCalledFromVerify: the verifier is the only caller of
// MarkVerified (the store defines it).
func TestMarkVerifiedOnlyCalledFromVerify(t *testing.T) {
	var calls []string
	scanned := 0
	for _, root := range []string{"../../../internal", "../../../cmd"} {
		if _, err := os.Stat(root); err != nil {
			t.Fatalf("expected %s to exist: %v", root, err)
		}
		err := filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() || !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
				return nil
			}
			sp := filepath.ToSlash(p)
			if strings.Contains(sp, "internal/aleef/verify/") || strings.Contains(sp, "internal/aleef/store/") {
				return nil
			}
			f, err := parser.ParseFile(token.NewFileSet(), p, nil, 0)
			if err != nil {
				return err
			}
			scanned++
			ast.Inspect(f, func(n ast.Node) bool {
				if c, ok := n.(*ast.CallExpr); ok {
					if s, ok := c.Fun.(*ast.SelectorExpr); ok && s.Sel.Name == "MarkVerified" {
						calls = append(calls, sp)
					}
				}
				return true
			})
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	if scanned < 50 {
		t.Fatalf("only %d files scanned: the walk is not covering the tree", scanned)
	}
	if len(calls) > 0 {
		t.Fatalf("MarkVerified called outside internal/aleef/verify: %v", calls)
	}
}

var _ = exec.FindingYes

func TestReproductionsHaveAFloorOfThree(t *testing.T) {
	for _, n := range []int{-1, 0, 1, 2} {
		ty := newToy()
		ty.readFlaw = stable
		env := newEnv(t, ty)
		v := run(t, env, newRec(), Options{Reproductions: n}, ownTest(t))
		if v.State != StateVerified || v.Reproductions != 3 || env.fresh.Load() != 9 {
			t.Fatalf("N=%d: %+v fresh=%d", n, v, env.fresh.Load())
		}
	}
	// reproduces only twice: not verified even when N=2 is requested
	ty := newToy()
	ty.readFlaw = func(n int) bool { return n <= 2 }
	v := run(t, newEnv(t, ty), newRec(), Options{Reproductions: 2}, ownTest(t))
	if v.State == StateVerified || !strings.HasPrefix(v.Reason, "not reproducible (2/3)") {
		t.Fatalf("two reproductions verified: %+v", v)
	}
	ty = newToy()
	ty.readFlaw = stable
	env := newEnv(t, ty)
	v = run(t, env, newRec(), Options{Reproductions: 5}, ownTest(t))
	if v.State != StateVerified || v.Reproductions != 5 || env.fresh.Load() != 15 {
		t.Fatalf("N=5: %+v fresh=%d", v, env.fresh.Load())
	}
}
