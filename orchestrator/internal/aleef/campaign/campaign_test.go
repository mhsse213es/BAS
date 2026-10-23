package campaign

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/audspect/bas/internal/aleef/exec"
	"github.com/audspect/bas/internal/aleef/export"
	"github.com/audspect/bas/internal/aleef/generate"
	"github.com/audspect/bas/internal/aleef/model"
	"github.com/audspect/bas/internal/aleef/safety"
	"github.com/audspect/bas/internal/aleef/store"
	"github.com/audspect/bas/internal/aleef/verify"
	"github.com/audspect/bas/internal/apibas/contract"
)

func mustRun(t *testing.T, cfg Config) Report {
	t.Helper()
	rep, err := Run(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	return rep
}

func TestCampaignFindsAndVerifiesToyFlaw(t *testing.T) {
	ty := newToy()
	ty.readFlaw = true
	rec := newRec()
	cfg, _ := toyConfig(t, ty, rec)
	rep := mustRun(t, cfg)
	if rep.Verified < 1 {
		t.Fatalf("no verified finding (executed %d, unconfirmed %d, rejected %d): %v", rep.Executed, rep.Unconfirmed, rep.Rejected, firstReasons(rep))
	}
	var withHash int
	for _, f := range rep.Findings {
		if f.State == verify.StateVerified && f.EvidenceHash != "" {
			withHash++
		}
	}
	if withHash < 1 || withHash != rep.Verified {
		t.Fatalf("verified=%d findings with hash=%d", rep.Verified, withHash)
	}
	if rep.RunID == "" || rep.Halted != "" || len(rep.Orphans) != 0 {
		t.Fatalf("run=%q halted=%q orphans=%v", rep.RunID, rep.Halted, rep.Orphans)
	}
	if rec.fkMisses != 0 {
		t.Fatalf("%d results/findings recorded for tests that were not saved first", rec.fkMisses)
	}
	if got := ty.leftover(); got != 0 {
		t.Fatalf("%d objects left on the toy", got)
	}

	// the corrected application: nothing to report
	clean := newToy()
	rec2 := newRec()
	cfg2, _ := toyConfig(t, clean, rec2)
	rep2 := mustRun(t, cfg2)
	if rep2.Verified != 0 || rep2.ReachedCandidate != 0 || len(rep2.Findings) != 0 || rep2.Executed == 0 {
		t.Fatalf("corrected toy: %+v", rep2)
	}
	if clean.leftover() != 0 {
		t.Fatalf("%d objects left on the corrected toy", clean.leftover())
	}
}

func TestCampaignRefusesProductionEngagementBeforeAnyRequest(t *testing.T) {
	ty := newToy()
	cfg, _ := toyConfig(t, ty, newRec())
	cfg.Engagement.Environment = "production"
	if _, err := Run(context.Background(), cfg); err == nil {
		t.Fatal("production engagement accepted")
	}
	// host outside the engagement
	cfg2, _ := toyConfig(t, ty, newRec())
	cfg2.BaseURL = "http://127.0.0.1:1"
	if _, err := Run(context.Background(), cfg2); err == nil {
		t.Fatal("BaseURL outside the engagement accepted")
	}
	// an unknown operation class is a configuration error
	cfg3, _ := toyConfig(t, ty, newRec())
	cfg3.Classes["nope"] = model.ClassRead
	if _, err := Run(context.Background(), cfg3); err == nil {
		t.Fatal("class for an unknown operation accepted")
	}
	if n := ty.total(); n != 0 {
		t.Fatalf("toy received %d requests, want 0", n)
	}
}

func TestCampaignUnclassifiedOperationsAreNeverExecuted(t *testing.T) {
	ty := newToy()
	ty.readFlaw = true
	cfg, _ := toyConfig(t, ty, newRec())
	rep := mustRun(t, cfg)
	if rep.Model.Unclassified < 2 {
		t.Fatalf("coverage %+v", rep.Model)
	}
	if n := ty.hitCount("POST /api/v2/items/{id}/archive"); n != 0 {
		t.Fatalf("archiveItem (unclassified) received %d requests", n)
	}
	if n := ty.hitCount("GET /api/v2/items"); n != 0 {
		t.Fatalf("listItems (unclassified) received %d requests", n)
	}
	if oc := rep.PerOperation["archiveItem"]; oc.Generated != 0 || oc.Executed != 0 || oc.Skipped == "" {
		t.Fatalf("archiveItem row %+v", oc)
	}
}

func TestCampaignHaltsOnBreakerAndStillCleansUp(t *testing.T) {
	ty := newToy()
	ty.readFlaw = true
	ty.tooMany = 40 // 429 after 40 non-delete requests
	cfg, _ := toyConfig(t, ty, newRec())
	rep := mustRun(t, cfg)
	if rep.Halted == "" || !strings.Contains(rep.Halted, "429") {
		t.Fatalf("Halted=%q", rep.Halted)
	}
	if rep.NotExecuted < 1 {
		t.Fatalf("no test counted as not executed: executed=%d total=%d", rep.Executed, rep.Total)
	}
	if rep.Executed+rep.NotExecuted != rep.Total {
		t.Fatalf("executed %d + not executed %d != total %d", rep.Executed, rep.NotExecuted, rep.Total)
	}
	if rep.CleanupRequests == 0 || ty.deletes == 0 {
		t.Fatalf("no cleanup after the halt: cleanup requests %d deletes %d", rep.CleanupRequests, ty.deletes)
	}
	if got := ty.leftover(); got != 0 {
		t.Fatalf("%d objects left on the toy after a halted campaign", got)
	}
	if len(rep.Orphans) != 0 {
		t.Fatalf("orphans %v", rep.Orphans)
	}
	for _, o := range rep.Tests {
		if o.State == verify.StateVerified {
			t.Fatalf("verified despite the halt: %+v", o)
		}
	}
}

func TestCampaignBudgetExhaustion(t *testing.T) {
	ty := newToy()
	ty.readFlaw = true
	cfg, _ := toyConfig(t, ty, newRec())
	cfg.Engagement.MaxRequests = 60
	rep := mustRun(t, cfg)
	if rep.Halted == "" || !strings.Contains(rep.Halted, "budget") {
		t.Fatalf("Halted=%q requests=%d", rep.Halted, rep.Requests)
	}
	if rep.Requests > 60 {
		t.Fatalf("%d requests exceed the budget of 60", rep.Requests)
	}
	if rep.NotExecuted < 1 || rep.Executed+rep.NotExecuted != rep.Total {
		t.Fatalf("executed=%d not=%d total=%d", rep.Executed, rep.NotExecuted, rep.Total)
	}
	if got := ty.leftover(); got != 0 {
		t.Fatalf("%d objects left behind after budget exhaustion", got)
	}
}

func TestCampaignContextCancel(t *testing.T) {
	ty := newToy()
	ty.readFlaw = true
	cfg, _ := toyConfig(t, ty, newRec())
	ctx, cancel := context.WithCancel(context.Background())
	rec := cfg.Recorder.(*fakeRec)
	// cancel as soon as the first result has been recorded
	cfg.Recorder = cancelAfterResult{fakeRec: rec, cancel: cancel}
	rep, err := Run(ctx, cfg)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if rep.Halted != "cancelled" {
		t.Fatalf("Halted=%q", rep.Halted)
	}
	if rep.NotExecuted < 1 || rep.Executed+rep.NotExecuted != rep.Total {
		t.Fatalf("executed=%d not=%d total=%d", rep.Executed, rep.NotExecuted, rep.Total)
	}
	if got := ty.leftover(); got != 0 {
		t.Fatalf("%d objects left behind after cancel", got)
	}
}

func TestCampaignReportHasNoSecrets(t *testing.T) {
	ty := newToy()
	ty.readFlaw = true
	cfg, _ := toyConfig(t, ty, newRec())
	rep := mustRun(t, cfg)
	raw, err := json.Marshal(rep)
	if err != nil {
		t.Fatal(err)
	}
	s := string(raw)
	for _, bad := range []string{"tok-alice", "tok-bob", "tok-dave", "Bearer", "ALEEF-CANARY", "Authorization", "\"Exchanges\"", "\"Body\""} {
		if strings.Contains(s, bad) {
			t.Fatalf("report contains %q", bad)
		}
	}
}

func TestCampaignPerOperationCoverageAddsUp(t *testing.T) {
	ty := newToy()
	ty.readFlaw = true
	cfg, _ := toyConfig(t, ty, newRec())
	cfg.Options.Variations = nil
	rep := mustRun(t, cfg)
	g := rep.Generated
	if rep.Total != g.BaseTests+g.Variants-g.Truncated {
		t.Fatalf("total %d != base %d + variants %d - truncated %d", rep.Total, g.BaseTests, g.Variants, g.Truncated)
	}
	if rep.Total != rep.Executed+rep.NotExecuted || len(rep.Tests) != rep.Total {
		t.Fatalf("total %d executed %d not %d tests %d", rep.Total, rep.Executed, rep.NotExecuted, len(rep.Tests))
	}
	var gen, exe, not, fnd, ver int
	for id, oc := range rep.PerOperation {
		if oc.Generated != oc.Executed+oc.NotExecuted {
			t.Fatalf("%s: generated %d != executed %d + not executed %d", id, oc.Generated, oc.Executed, oc.NotExecuted)
		}
		if oc.Verified > oc.Findings || oc.Findings > oc.Executed {
			t.Fatalf("%s row inconsistent: %+v", id, oc)
		}
		gen, exe, not, fnd, ver = gen+oc.Generated, exe+oc.Executed, not+oc.NotExecuted, fnd+oc.Findings, ver+oc.Verified
	}
	if gen != rep.Total || exe != rep.Executed || not != rep.NotExecuted || ver != rep.Verified || fnd != len(rep.Findings) {
		t.Fatalf("rows (%d,%d,%d,%d,%d) vs totals (%d,%d,%d,%d,%d)", gen, exe, not, fnd, ver, rep.Total, rep.Executed, rep.NotExecuted, len(rep.Findings), rep.Verified)
	}
	if rep.Clean+rep.Verified+rep.Rejected+rep.Unconfirmed+rep.Inconclusive != rep.Executed {
		t.Fatalf("outcome counts do not add up: %+v", rep)
	}
	for _, op := range []string{"getItem"} {
		if rep.PerOperation[op].Generated == 0 {
			t.Fatalf("no tests targeted %s", op)
		}
	}
	if rep.Model.Operations != 5 || rep.Model.Runnable != 3 {
		t.Fatalf("model coverage %+v", rep.Model)
	}
}

func TestCampaignDeterministic(t *testing.T) {
	type row struct{ ID, State, Hash string }
	collect := func() []row {
		ty := newToy()
		ty.readFlaw = true
		cfg, _ := toyConfig(t, ty, newRec())
		cfg.Options.Variations = []string{"id-stale"}
		rep := mustRun(t, cfg)
		var out []row
		for _, o := range rep.Tests {
			out = append(out, row{o.TestID, o.State, o.EvidenceHash})
		}
		return out
	}
	a, b := collect(), collect()
	if len(a) == 0 {
		t.Fatal("no tests")
	}
	ja, _ := json.Marshal(a)
	jb, _ := json.Marshal(b)
	if string(ja) != string(jb) {
		t.Fatalf("two campaigns with the same seed differ:\n%s\n%s", ja, jb)
	}
}

func TestCampaignFreshIdsAreAliased(t *testing.T) {
	// Every fixture gets new server-assigned ids; verification must still
	// reach the objects the tests were generated for.
	ty := newToy()
	ty.readFlaw = true
	cfg, _ := toyConfig(t, ty, newRec())
	rep := mustRun(t, cfg)
	if ty.seq < 20 {
		t.Fatalf("toy only assigned %d ids: fixtures were not rebuilt", ty.seq)
	}
	if rep.Verified < 1 {
		t.Fatalf("flaw not verified across fresh ids: %v", firstReasons(rep))
	}
}

func TestCampaignCleanupFailureIsReported(t *testing.T) {
	ty := newToy()
	ty.readFlaw = true
	cfg, _ := toyConfig(t, ty, newRec())
	// compensation is refused: every created object stays behind
	ty.noDelete = true
	rep, err := Run(context.Background(), cfg)
	if err != nil {
		t.Logf("Run returned %v", err) // generation may fail first; the report is still returned
	}
	if len(rep.Orphans) == 0 || !strings.Contains(rep.Halted, "cleanup failed") {
		t.Fatalf("orphans=%v halted=%q", rep.Orphans, rep.Halted)
	}
}

func TestCampaignClockIsInjectable(t *testing.T) {
	ty := newToy()
	cfg, _ := toyConfig(t, ty, newRec())
	cfg.Now = func() time.Time { return time.Now().Add(48 * time.Hour) } // outside the window
	if _, err := Run(context.Background(), cfg); err == nil {
		t.Fatal("run accepted outside the engagement window")
	}
	if n := ty.total(); n != 0 {
		t.Fatalf("%d requests sent outside the window", n)
	}
}

// cancelAfterResult cancels the campaign's context as soon as the first
// execution has been recorded.
type cancelAfterResult struct {
	*fakeRec
	cancel context.CancelFunc
}

func (c cancelAfterResult) SaveResult(ctx context.Context, runID string, t generate.Test, execNo int, res exec.Result) error {
	err := c.fakeRec.SaveResult(ctx, runID, t, execNo, res)
	c.cancel()
	return err
}

func firstReasons(rep Report) []string {
	var out []string
	for i, o := range rep.Tests {
		if i >= 3 {
			break
		}
		out = append(out, o.TestID+": "+o.State+" "+o.Reason)
	}
	return out
}

// ---- alias safety, end to end ----

// verifyMutated builds the campaign environment by hand, generates the
// cross-identity read test, lets mutate change its last step, and verifies it.
func verifyMutated(t *testing.T, ty *toy, mutate func(genID string, st *contract.Step)) verify.Verdict {
	t.Helper()
	rec := newRec()
	cfg, _ := toyConfig(t, ty, rec)
	m, err := prepare(cfg)
	if err != nil {
		t.Fatal(err)
	}
	g, err := safety.NewGuard(cfg.Engagement, nil, m, safety.GuardOptions{})
	if err != nil {
		t.Fatal(err)
	}
	e, err := newEnv(cfg, m, g, "tag")
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	cleanup, err := e.generationFixture(ctx)
	if err != nil {
		t.Fatal(err)
	}
	tests, err := generate.Generate(m, e.genFx, cfg.Accounts, generate.Options{Seed: 1, Catalogue: []contract.Scenario{}})
	if err != nil {
		t.Fatal(err)
	}
	_, _ = cleanup(ctx)
	for _, x := range tests {
		if x.Property != "P-OWN-1" || x.Params["operation"] != "getItem" || x.OwnerControl == nil {
			continue
		}
		last := &x.Scenario.Steps[len(x.Scenario.Steps)-1]
		mutate(e.genIDs[0], last)
		for _, tt := range []generate.Test{x, *x.OwnerControl, *x.NegativeControl} {
			_ = rec.SaveTest(ctx, "r", tt)
		}
		v, err := verify.New(e, rec, verify.Options{RunID: "r"}).Verify(ctx, x)
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	t.Fatal("no P-OWN-1 test on getItem")
	return verify.Verdict{}
}

func TestAliasUntranslatedHeaderIsNeverSentNorClean(t *testing.T) {
	ty := newToy()
	ty.readFlaw = true
	v := verifyMutated(t, ty, func(id string, st *contract.Step) {
		if st.Headers == nil {
			st.Headers = map[string]string{}
		}
		st.Headers["X-Probe"] = "prefix-" + id
	})
	if v.State != verify.StateUnconfirmed {
		t.Fatalf("State=%q reason=%q, want unconfirmed", v.State, v.Reason)
	}
	if ty.probe {
		t.Fatal("the request carrying a dead generation id reached the server")
	}
	if ty.leftover() != 0 {
		t.Fatalf("%d objects left", ty.leftover())
	}
}

func TestAliasUntranslatedEncodedQueryIsNeverSentNorClean(t *testing.T) {
	ty := newToy()
	ty.readFlaw = true
	v := verifyMutated(t, ty, func(id string, st *contract.Step) { st.Path += "?ref=a%2C" + id })
	if v.State != verify.StateUnconfirmed {
		t.Fatalf("State=%q reason=%q, want unconfirmed", v.State, v.Reason)
	}
	if ty.sawRef {
		t.Fatal("the request carrying a dead generation id reached the server")
	}
}

func TestAliasFreshIdEqualToLiteralRouteFailsFresh(t *testing.T) {
	ty := newToy()
	ty.readFlaw = true
	// the generation fixture (ids 1-3) is normal; every later fixture's first
	// object gets an id that is a literal segment of a sibling route
	ty.idFn = func(seq int) string {
		if seq > 3 && seq%3 == 1 {
			return "archive"
		}
		return fmt.Sprintf("item-%d", seq)
	}
	cfg, _ := toyConfig(t, ty, newRec())
	rep := mustRun(t, cfg)
	if rep.Verified != 0 || rep.Executed != 0 {
		t.Fatalf("verified=%d executed=%d, want none", rep.Verified, rep.Executed)
	}
	for _, p := range ty.paths {
		if strings.HasPrefix(p, "GET ") && strings.HasSuffix(p, "/items/archive") {
			t.Fatalf("a test request reached the literal route: %s", p)
		}
	}
	if ty.leftover() != 0 {
		t.Fatalf("%d objects left", ty.leftover())
	}
}

// ---- regressions ----

// checkEnvFor returns an environment on a fresh toy whose generation fixture
// has the same ids as a campaign's (a new toy numbers its first fixture from 1).
func checkEnvFor(t *testing.T, ty *toy) *env {
	t.Helper()
	cfg, _ := toyConfig(t, ty, newRec())
	m, err := prepare(cfg)
	if err != nil {
		t.Fatal(err)
	}
	g, err := safety.NewGuard(cfg.Engagement, nil, m, safety.GuardOptions{})
	if err != nil {
		t.Fatal(err)
	}
	e, err := newEnv(cfg, m, g, runTag(cfg.Engagement, cfg.Options.Seed))
	if err != nil {
		t.Fatal(err)
	}
	cleanup, err := e.generationFixture(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if orphans, err := cleanup(context.Background()); err != nil || len(orphans) > 0 {
		t.Fatalf("generation cleanup: %v %v", orphans, err)
	}
	return e
}

// assertRegressionExecutable replays a stored bundle against the corrected and
// the flawed toy.
func assertRegressionExecutable(t *testing.T, bundleJSON []byte) {
	t.Helper()
	b, err := export.UnmarshalBundle(bundleJSON)
	if err != nil {
		t.Fatalf("bundle does not round-trip: %v", err)
	}
	ctx := context.Background()
	if out, err := export.Check(ctx, checkEnvFor(t, newToy()), b); err != nil || out != export.FixedConfirmed {
		t.Fatalf("corrected toy: %v %v", out, err)
	}
	flawed := newToy()
	flawed.readFlaw = true
	if out, err := export.Check(ctx, checkEnvFor(t, flawed), b); err != nil || out != export.StillVulnerable {
		t.Fatalf("flawed toy: %v %v", out, err)
	}
}

func TestCampaignSavesExecutableRegressionForEveryVerifiedFinding(t *testing.T) {
	ty := newToy()
	ty.readFlaw = true
	rec := newRec()
	cfg, _ := toyConfig(t, ty, rec)
	rep := mustRun(t, cfg)
	if rep.Verified < 1 || rep.RegressionFailed != 0 {
		t.Fatalf("verified=%d regression failures=%d", rep.Verified, rep.RegressionFailed)
	}
	if len(rec.regs) != rep.Verified {
		t.Fatalf("%d regressions saved for %d verified findings", len(rec.regs), rep.Verified)
	}
	checked := 0
	for _, f := range rep.Findings {
		if f.State != verify.StateVerified {
			continue
		}
		reg, ok := rec.regs[f.FindingID]
		if !ok || reg.RegressionID == "" || reg.RegressionID != f.RegressionID {
			t.Fatalf("finding %s: saved %+v report %q", f.FindingID, reg, f.RegressionID)
		}
		if checked < 2 {
			assertRegressionExecutable(t, reg.BundleJSON)
			checked++
		}
	}
	// ids only in the report: no bundle, scenario or secret
	raw, _ := json.Marshal(rep)
	for _, bad := range []string{"\"version\"", "Scenario", "scenario", "bundle", "tok-", "ALEEF-CANARY"} {
		if strings.Contains(string(raw), bad) {
			t.Fatalf("report contains %q", bad)
		}
	}
	if !strings.Contains(string(raw), "ALEEF-REG-") {
		t.Fatal("report does not name the regression ids")
	}
}

func TestCampaignDemotesFindingWhenRegressionCannotBeSaved(t *testing.T) {
	for name, set := range map[string]func(*fakeRec){
		"save fails":     func(r *fakeRec) { r.failSave = true },
		"sequence fails": func(r *fakeRec) { r.failSeq = true },
	} {
		t.Run(name, func(t *testing.T) {
			ty := newToy()
			ty.readFlaw = true
			rec := newRec()
			set(rec)
			cfg, _ := toyConfig(t, ty, rec)
			rep := mustRun(t, cfg)
			if rep.Verified != 0 || rep.RegressionFailed < 1 {
				t.Fatalf("verified=%d regression failures=%d", rep.Verified, rep.RegressionFailed)
			}
			demoted := 0
			for _, o := range rep.Tests {
				if o.Reason == "regression could not be saved" {
					if o.State != verify.StateUnconfirmed || o.EvidenceHash != "" || o.RegressionID != "" {
						t.Fatalf("outcome %+v", o)
					}
					demoted++
				}
			}
			if demoted != rep.RegressionFailed {
				t.Fatalf("demoted %d, counted %d", demoted, rep.RegressionFailed)
			}
			for id, st := range rec.states {
				if st == "verified" {
					t.Fatalf("finding %s is still verified without a regression", id)
				}
			}
			if len(rec.regs) != 0 {
				t.Fatalf("%d regressions saved", len(rec.regs))
			}
			for _, f := range rep.Findings {
				if f.State == verify.StateVerified || f.RegressionID != "" {
					t.Fatalf("finding row %+v", f)
				}
			}
		})
	}
}

func TestCampaignRepairsVerifiedFindingsWithoutRegression(t *testing.T) {
	ty := newToy()
	rec := newRec()
	// an earlier campaign died between verification and saving the regression
	rec.states["old-1"], rec.hash["old-1"] = "verified", "h1"
	rec.meta["old-1"] = store.Finding{ID: "old-1", TestID: "x"}
	// and one that completed properly
	rec.states["old-2"], rec.hash["old-2"] = "verified", "h2"
	rec.meta["old-2"] = store.Finding{ID: "old-2", TestID: "y"}
	rec.regs["old-2"] = store.Regression{FindingID: "old-2", RegressionID: "ALEEF-REG-0001"}
	cfg, _ := toyConfig(t, ty, rec)
	rep := mustRun(t, cfg)
	if rep.RepairedUnregressed != 1 {
		t.Fatalf("repaired %d", rep.RepairedUnregressed)
	}
	if rec.states["old-1"] != "unconfirmed" || rec.states["old-2"] != "verified" {
		t.Fatalf("states %v", rec.states)
	}
	if left, _ := rec.ListVerifiedWithoutRegression(context.Background(), ""); len(left) != 0 {
		t.Fatalf("still unregressed: %v", left)
	}
}
