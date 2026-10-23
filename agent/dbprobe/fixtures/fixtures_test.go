package fixtures

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"audspect/agent/dbprobe"
)

// fakeAd is a recording dbprobe.Adapter that also implements ModeReporter and
// FixtureInspector. state models the objects that currently exist for the
// fixture schema.
type fakeAd struct {
	mu         sync.Mutex
	mode       dbprobe.ExecMode
	calls      []string
	state      []string
	seedErr    error
	cleanupErr error
	leftover   []string // objects that survive Cleanup
	inspectErr error
	seeded     dbprobe.Fixture
	cleanupCtx context.Context
	seedCtx    context.Context

	cleanupCtxErr      error
	cleanupDeadline    time.Time
	cleanupHasDeadline bool
	errClears          bool // a failing Cleanup still removed everything
}

func (f *fakeAd) rec(s string) { f.mu.Lock(); f.calls = append(f.calls, s); f.mu.Unlock() }

func (f *fakeAd) Mode() dbprobe.ExecMode { return f.mode }

func (f *fakeAd) Connect(context.Context, dbprobe.ConnectionConfig) error { return nil }
func (f *fakeAd) Identity(context.Context) (string, error)                { return "id", nil }
func (f *fakeAd) EnumerateRoles(context.Context) ([]dbprobe.Role, error)  { return nil, nil }
func (f *fakeAd) ReadGrants(context.Context) ([]dbprobe.Grant, error)     { return nil, nil }
func (f *fakeAd) RunProbe(context.Context, dbprobe.ProbeDef, dbprobe.DBProbeSpec) (dbprobe.ProbeResult, error) {
	return dbprobe.ProbeResult{}, nil
}
func (f *fakeAd) CollectAudit(context.Context, dbprobe.AuditQuery) ([]dbprobe.AuditEvent, error) {
	return nil, nil
}
func (f *fakeAd) Capabilities() dbprobe.Capabilities { return dbprobe.Capabilities{} }
func (f *fakeAd) Close() error                       { return nil }

func (f *fakeAd) InspectFixture(_ context.Context, _ dbprobe.Fixture) ([]string, error) {
	f.rec("inspect")
	if f.inspectErr != nil {
		return nil, f.inspectErr
	}
	return append([]string(nil), f.state...), nil
}

func (f *fakeAd) Seed(ctx context.Context, fx dbprobe.Fixture) error {
	f.rec("seed")
	f.seedCtx = ctx
	f.seeded = fx
	if f.seedErr != nil {
		return f.seedErr
	}
	f.state = append([]string{"schema:dbsim_" + fx.ID}, fx.Objects...)
	return nil
}

func (f *fakeAd) Cleanup(ctx context.Context, fx dbprobe.Fixture) (dbprobe.CleanupResult, error) {
	f.rec("cleanup")
	f.cleanupCtx = ctx
	f.cleanupCtxErr = ctx.Err()
	f.cleanupDeadline, f.cleanupHasDeadline = ctx.Deadline()
	if f.cleanupErr != nil {
		if f.errClears {
			f.state = nil
		}
		return dbprobe.CleanupResult{Error: f.cleanupErr.Error()}, f.cleanupErr
	}
	f.state = append([]string(nil), f.leftover...)
	return dbprobe.CleanupResult{Removed: []string{"schema:dbsim_" + fx.ID}}, nil
}

func labAd() *fakeAd { return &fakeAd{mode: dbprobe.ModeLab} }

func mustSpec(t *testing.T, name string) dbprobe.FixtureSpec {
	t.Helper()
	s, ok := Lookup(name)
	if !ok {
		t.Fatalf("catalog fixture %q missing", name)
	}
	return s
}

func TestSeedCreatesIsolatedSchemaOnly(t *testing.T) {
	ad := labAd()
	spec := mustSpec(t, "accounts")
	fx, err := Seed(context.Background(), ad, spec)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(ad.calls, ","); got != "inspect,seed" {
		t.Fatalf("calls = %s, want inspect before seed", got)
	}
	if !regexp.MustCompile(`^[a-f0-9]{12}$`).MatchString(fx.ID) {
		t.Fatalf("fixture id %q not in the expected format", fx.ID)
	}
	if len(fx.PreState) != 0 {
		t.Fatalf("pre-state must be recorded empty, got %v", fx.PreState)
	}
	schema := "dbsim_" + fx.ID
	if len(fx.Objects) == 0 {
		t.Fatal("fixture must list the objects it will create")
	}
	for _, o := range fx.Objects {
		if o != "schema:"+schema && !strings.HasPrefix(o, "table:"+schema+".") {
			t.Errorf("object %q outside the dedicated schema %s", o, schema)
		}
	}
	if !reflect.DeepEqual(fx.Tables, spec.Tables) {
		t.Error("fixture must carry the spec's tables to the adapter")
	}
	if fx.Kind != "accounts" {
		t.Errorf("kind = %q", fx.Kind)
	}
}

func TestSeedRefusesNonLabBeforeAnySQL(t *testing.T) {
	for _, m := range []dbprobe.ExecMode{dbprobe.ModeClient, ""} {
		ad := &fakeAd{mode: m}
		if _, err := Seed(context.Background(), ad, mustSpec(t, "accounts")); err == nil {
			t.Fatalf("mode %q: expected refusal", m)
		}
		if len(ad.calls) != 0 {
			t.Fatalf("mode %q: SQL-bearing calls before refusal: %v", m, ad.calls)
		}
	}
	// An adapter that cannot state its mode is refused (fail closed).
	n := &noModeAd{fakeAd: labAd()}
	if _, err := Seed(context.Background(), n, mustSpec(t, "accounts")); err == nil {
		t.Fatal("adapter without ModeReporter must be refused")
	}
	if len(n.calls) != 0 {
		t.Fatalf("calls: %v", n.calls)
	}
}

// noModeAd hides the ModeReporter method of fakeAd.
type noModeAd struct{ *fakeAd }

func (noModeAd) Mode() {}

func TestSeedRefusesPreexistingState(t *testing.T) {
	ad := labAd()
	ad.state = []string{"schema:dbsim_whatever"}
	if _, err := Seed(context.Background(), ad, mustSpec(t, "accounts")); err == nil {
		t.Fatal("non-empty pre-state must refuse")
	}
	for _, c := range ad.calls {
		if c == "seed" {
			t.Fatal("seed must not run over pre-existing state")
		}
	}
}

func TestSeedRefusesOverCapSpecBeforeAnySQL(t *testing.T) {
	spec := dbprobe.FixtureSpec{Kind: "big", Tables: []dbprobe.FixtureTable{{
		Name: "t", Columns: []dbprobe.FixtureColumn{{Name: "id", Type: "int", PK: true}},
	}}}
	for i := 0; i <= dbprobe.MaxFixtureRows; i++ {
		spec.Tables[0].Rows = append(spec.Tables[0].Rows, []any{i})
	}
	ad := labAd()
	if _, err := Seed(context.Background(), ad, spec); err == nil {
		t.Fatal("over-cap row count must be refused")
	}
	if len(ad.calls) != 0 {
		t.Fatalf("calls before refusal: %v", ad.calls)
	}
}

func TestSeedIDsUnique(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 200; i++ {
		ad := labAd()
		fx, err := Seed(context.Background(), ad, mustSpec(t, "empty"))
		if err != nil {
			t.Fatal(err)
		}
		if seen[fx.ID] {
			t.Fatalf("duplicate id %s", fx.ID)
		}
		seen[fx.ID] = true
	}
}

func TestSeedDeterministicData(t *testing.T) {
	a1, a2 := labAd(), labAd()
	f1, err := Seed(context.Background(), a1, mustSpec(t, "classified-pii"))
	if err != nil {
		t.Fatal(err)
	}
	f2, err := Seed(context.Background(), a2, mustSpec(t, "classified-pii"))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(f1.Tables, f2.Tables) {
		t.Fatal("two seeds of the same fixture must carry identical rows")
	}
	if f1.ID == f2.ID {
		t.Fatal("ids must still differ")
	}
}

func TestSeedInjectedIDGenerator(t *testing.T) {
	old := newID
	newID = func() (string, error) { return "aabbccddeeff", nil }
	defer func() { newID = old }()
	fx, err := Seed(context.Background(), labAd(), mustSpec(t, "empty"))
	if err != nil || fx.ID != "aabbccddeeff" {
		t.Fatalf("fx=%+v err=%v", fx, err)
	}
	newID = func() (string, error) { return "bad id; drop", nil }
	if _, err := Seed(context.Background(), labAd(), mustSpec(t, "empty")); err == nil {
		t.Fatal("an invalid generated id must be refused")
	}
}

func TestVerifyCleanDetectsLeftoverObject(t *testing.T) {
	ad := labAd()
	fx := dbprobe.Fixture{ID: "aabbccddeeff"}
	ad.state = []string{"table:dbsim_aabbccddeeff.accounts"}
	res, err := VerifyClean(context.Background(), ad, fx)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Residual) != 1 || res.Residual[0] != "table:dbsim_aabbccddeeff.accounts" {
		t.Fatalf("residual = %v", res.Residual)
	}
	// Clean state: no residual.
	ad.state = nil
	res, err = VerifyClean(context.Background(), ad, fx)
	if err != nil || len(res.Residual) != 0 {
		t.Fatalf("clean state flagged: %v %v", res, err)
	}
	// Objects that pre-existed (recorded pre-state) are not our residual.
	fx.PreState = []string{"schema:dbsim_aabbccddeeff"}
	ad.state = []string{"schema:dbsim_aabbccddeeff"}
	res, _ = VerifyClean(context.Background(), ad, fx)
	if len(res.Residual) != 0 {
		t.Fatalf("pre-existing object counted as residual: %v", res.Residual)
	}
}

func TestVerifyCleanCannotVerifyIsError(t *testing.T) {
	ad := labAd()
	ad.inspectErr = errors.New("boom")
	if _, err := VerifyClean(context.Background(), ad, dbprobe.Fixture{ID: "aabbccddeeff"}); err == nil {
		t.Fatal("an inspection failure must not read as clean")
	}
	n := &noInspectAd{labAd()}
	if _, err := VerifyClean(context.Background(), n, dbprobe.Fixture{ID: "aabbccddeeff"}); err == nil {
		t.Fatal("an adapter that cannot inspect must not read as clean")
	}
}

// noInspectAd is an Adapter without FixtureInspector.
type noInspectAd struct{ *fakeAd }

func (noInspectAd) InspectFixture() {}

func TestCleanupFailureIsSafetyIncident(t *testing.T) {
	ranAfter := false
	// 1. Cleanup errors.
	ad := labAd()
	ad.cleanupErr = errors.New("drop denied")
	ad.leftover = []string{"schema:dbsim_x"}
	res, err := WithFixture(context.Background(), ad, mustSpec(t, "accounts"), func(dbprobe.Fixture) error { return nil })
	var inc *ErrSafetyIncident
	if !errors.As(err, &inc) {
		t.Fatalf("a run whose cleanup fails must return ErrSafetyIncident, got %v", err)
	}
	if inc.Status != StatusResidual && inc.Status != StatusFailed {
		t.Fatalf("status = %q", inc.Status)
	}
	if len(res.Residual) == 0 {
		t.Fatalf("result must carry the residual: %+v", res)
	}
	if err == nil {
		ranAfter = true
	}
	if ranAfter {
		t.Fatal("normal completion must be impossible after a failed cleanup")
	}

	// 2. Cleanup "succeeds" but verification finds a leftover: residual.
	ad2 := labAd()
	ad2.leftover = []string{"table:dbsim_x.accounts"}
	res, err = WithFixture(context.Background(), ad2, mustSpec(t, "accounts"), func(dbprobe.Fixture) error { return nil })
	if !errors.As(err, &inc) || inc.Status != StatusResidual || len(res.Residual) != 1 {
		t.Fatalf("residual case: err=%v res=%+v", err, res)
	}

	// 3. Cleanup fails without a visible leftover: failed, still an incident.
	ad3 := labAd()
	ad3.cleanupErr = errors.New("timeout")
	ad3.errClears = true
	_, err = WithFixture(context.Background(), ad3, mustSpec(t, "accounts"), func(dbprobe.Fixture) error { return nil })
	if !errors.As(err, &inc) || inc.Status != StatusFailed {
		t.Fatalf("failed case: %v", err)
	}
	if strings.Contains(inc.Error(), "password") {
		t.Fatal("no secrets in the incident text")
	}
}

func TestWithFixtureCleanOK(t *testing.T) {
	ad := labAd()
	called := 0
	res, err := WithFixture(context.Background(), ad, mustSpec(t, "accounts"), func(fx dbprobe.Fixture) error {
		called++
		if fx.ID == "" {
			t.Error("fn must receive the seeded fixture")
		}
		return nil
	})
	if err != nil || called != 1 || len(res.Residual) != 0 {
		t.Fatalf("err=%v called=%d res=%+v", err, called, res)
	}
	want := "inspect,seed,cleanup,inspect"
	if got := strings.Join(ad.calls, ","); got != want {
		t.Fatalf("calls = %s, want %s", got, want)
	}
}

func TestWithFixtureCleansUpOnFnError(t *testing.T) {
	ad := labAd()
	boom := errors.New("probe failed")
	_, err := WithFixture(context.Background(), ad, mustSpec(t, "accounts"), func(dbprobe.Fixture) error { return boom })
	if !errors.Is(err, boom) {
		t.Fatalf("fn error must be returned: %v", err)
	}
	var inc *ErrSafetyIncident
	if errors.As(err, &inc) {
		t.Fatal("a clean cleanup after an fn error is not a safety incident")
	}
	if !strings.Contains(strings.Join(ad.calls, ","), "cleanup") {
		t.Fatal("cleanup must run")
	}
}

func TestWithFixtureCleansUpOnPanicAndRepanics(t *testing.T) {
	ad := labAd()
	func() {
		defer func() {
			r := recover()
			if r != "boom" {
				t.Fatalf("expected original panic value re-raised, got %v", r)
			}
		}()
		_, _ = WithFixture(context.Background(), ad, mustSpec(t, "accounts"), func(dbprobe.Fixture) error { panic("boom") })
	}()
	if !strings.Contains(strings.Join(ad.calls, ","), "cleanup") {
		t.Fatal("cleanup must run before the panic propagates")
	}
}

func TestWithFixturePanicWithFailedCleanupSurfacesIncident(t *testing.T) {
	ad := labAd()
	ad.leftover = []string{"schema:dbsim_x"}
	defer func() {
		r := recover()
		inc, ok := r.(*ErrSafetyIncident)
		if !ok {
			t.Fatalf("panic with failed cleanup must carry the incident, got %T %v", r, r)
		}
		if !strings.Contains(inc.Error(), "boom") {
			t.Errorf("incident should mention the original panic: %v", inc)
		}
	}()
	_, _ = WithFixture(context.Background(), ad, mustSpec(t, "accounts"), func(dbprobe.Fixture) error { panic("boom") })
}

func TestWithFixtureCleansUpOnCancelledContextWithFreshBoundedCtx(t *testing.T) {
	ad := labAd()
	ctx, cancel := context.WithCancel(context.Background())
	_, err := WithFixture(ctx, ad, mustSpec(t, "accounts"), func(dbprobe.Fixture) error {
		cancel()
		return ctx.Err()
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v", err)
	}
	if ad.cleanupCtx == nil {
		t.Fatal("cleanup must run")
	}
	if ad.cleanupCtxErr != nil {
		t.Fatal("cleanup ctx must not inherit the cancellation")
	}
	if !ad.cleanupHasDeadline || time.Until(ad.cleanupDeadline) > CleanupTimeout+time.Second {
		t.Fatalf("cleanup ctx must be bounded by CleanupTimeout (has=%v)", ad.cleanupHasDeadline)
	}
}

func TestWithFixtureSeedFailureStillCleansUp(t *testing.T) {
	ad := labAd()
	ad.seedErr = errors.New("create failed")
	called := false
	_, err := WithFixture(context.Background(), ad, mustSpec(t, "accounts"), func(dbprobe.Fixture) error { called = true; return nil })
	if err == nil || called {
		t.Fatalf("seed failure must fail the run without calling fn (err=%v called=%v)", err, called)
	}
	if !strings.Contains(strings.Join(ad.calls, ","), "cleanup") {
		t.Fatal("a partially seeded fixture must still be cleaned")
	}
}

func TestWithFixtureRefusedSeedRunsNoCleanup(t *testing.T) {
	ad := &fakeAd{mode: dbprobe.ModeClient}
	_, err := WithFixture(context.Background(), ad, mustSpec(t, "accounts"), func(dbprobe.Fixture) error { return nil })
	if err == nil {
		t.Fatal("expected refusal")
	}
	if len(ad.calls) != 0 {
		t.Fatalf("a refused seed must issue no calls: %v", ad.calls)
	}
	var inc *ErrSafetyIncident
	if errors.As(err, &inc) {
		t.Fatal("a refusal is not a safety incident")
	}
}

// ---- catalog ----

func TestCatalogNames(t *testing.T) {
	for _, n := range []string{"accounts", "classified-pii", "empty", "edge"} {
		if _, ok := Lookup(n); !ok {
			t.Errorf("missing catalog fixture %q", n)
		}
	}
	if _, ok := Lookup("nope"); ok {
		t.Error("unknown name must not resolve")
	}
	names := Names()
	if len(names) < 4 {
		t.Fatalf("names = %v", names)
	}
	for i := 1; i < len(names); i++ {
		if names[i-1] >= names[i] {
			t.Fatalf("Names must be sorted: %v", names)
		}
	}
}

func TestCatalogDeterministicAndIndependent(t *testing.T) {
	a, _ := Lookup("accounts")
	b, _ := Lookup("accounts")
	if !reflect.DeepEqual(a, b) {
		t.Fatal("catalog data must be identical on every call")
	}
	a.Tables[0].Rows[0][1] = "mutated"
	c, _ := Lookup("accounts")
	if c.Tables[0].Rows[0][1] == "mutated" {
		t.Fatal("Lookup must return a copy; callers cannot mutate the catalog")
	}
}

var (
	reDigitRun = regexp.MustCompile(`[0-9]{13,}`)
	// Luhn-valid published test numbers only (Visa, Mastercard, Amex test cards).
	pansAllowed = map[string]bool{"4111111111111111": true, "5555555555554444": true, "378282246310005": true}
)

func cellStrings(c any) string {
	switch v := c.(type) {
	case nil:
		return ""
	case string:
		return v
	default:
		return fmt.Sprint(v)
	}
}

func TestNoRealPANPatterns(t *testing.T) {
	for _, name := range Names() {
		spec, _ := Lookup(name)
		for _, tb := range spec.Tables {
			syn := -1
			for i, c := range tb.Columns {
				if c.Name == "synthetic" {
					syn = i
				}
			}
			if syn < 0 {
				t.Fatalf("%s.%s: every table needs a synthetic marker column", name, tb.Name)
			}
			for ri, row := range tb.Rows {
				m, _ := row[syn].(string)
				if !strings.HasPrefix(m, "BAS-SIM-") {
					t.Errorf("%s.%s row %d lacks the BAS-SIM- marker (%q)", name, tb.Name, ri, m)
				}
				for _, cell := range row {
					for _, run := range reDigitRun.FindAllString(cellStrings(cell), -1) {
						if !pansAllowed[run] {
							t.Errorf("%s.%s row %d: digit run %q is not an allow-listed published test number", name, tb.Name, ri, run)
						}
					}
				}
			}
		}
	}
	// Allow-list entries are Luhn-valid published numbers (so classifiers fire)
	// and the only PAN-like values the catalog may carry.
	for pan := range pansAllowed {
		if !luhnValid(pan) {
			t.Errorf("allow-list entry %s is not Luhn valid", pan)
		}
	}
	found := map[string]bool{}
	for _, name := range Names() {
		spec, _ := Lookup(name)
		for _, tb := range spec.Tables {
			for _, row := range tb.Rows {
				for _, cell := range row {
					for _, run := range reDigitRun.FindAllString(cellStrings(cell), -1) {
						found[run] = true
					}
				}
			}
		}
	}
	if len(found) == 0 {
		t.Error("classified-pii should carry at least one published test PAN so DAM classifiers can fire")
	}
}

func luhnValid(s string) bool {
	sum, alt := 0, false
	for i := len(s) - 1; i >= 0; i-- {
		d := int(s[i] - '0')
		if alt {
			d *= 2
			if d > 9 {
				d -= 9
			}
		}
		sum += d
		alt = !alt
	}
	return sum%10 == 0
}

func TestNoRealIdentifiersInCatalog(t *testing.T) {
	reEmail := regexp.MustCompile(`[A-Za-z0-9._+-]+@([A-Za-z0-9.-]+)`)
	for _, name := range Names() {
		spec, _ := Lookup(name)
		for _, tb := range spec.Tables {
			for _, row := range tb.Rows {
				for _, cell := range row {
					for _, m := range reEmail.FindAllStringSubmatch(cellStrings(cell), -1) {
						if !strings.HasSuffix(m[1], ".invalid") && m[1] != "example.com" && !strings.HasSuffix(m[1], ".example.com") {
							t.Errorf("%s.%s: email domain %q is not reserved", name, tb.Name, m[1])
						}
					}
				}
			}
		}
	}
}

func TestEmptyAndNullAndHugeValuesRespectMaxRows(t *testing.T) {
	empty := mustSpec(t, "empty")
	if len(empty.Tables) == 0 {
		t.Fatal("empty fixture needs a table")
	}
	for _, tb := range empty.Tables {
		if len(tb.Rows) != 0 {
			t.Errorf("empty.%s has %d rows", tb.Name, len(tb.Rows))
		}
	}
	edge := mustSpec(t, "edge")
	var nulls, huge, uni int
	for _, tb := range edge.Tables {
		if len(tb.Rows) > dbprobe.MaxFixtureRows {
			t.Errorf("edge.%s exceeds the row cap", tb.Name)
		}
		for _, row := range tb.Rows {
			for _, c := range row {
				switch v := c.(type) {
				case nil:
					nulls++
				case string:
					if len(v) > 1024 {
						huge++
					}
					if len(v) > dbprobe.MaxFixtureCellBytes {
						t.Errorf("edge cell of %d bytes exceeds the %d cap", len(v), dbprobe.MaxFixtureCellBytes)
					}
					for _, r := range v {
						if r > 0x7f {
							uni++
							break
						}
					}
				}
			}
		}
	}
	if nulls == 0 || huge == 0 || uni == 0 {
		t.Fatalf("edge must exercise NULLs (%d), long text (%d) and unicode (%d)", nulls, huge, uni)
	}
	for _, name := range Names() {
		spec, _ := Lookup(name)
		if err := dbprobe.ValidateFixtureTables(spec.Tables); err != nil {
			t.Errorf("catalog fixture %s violates the caps: %v", name, err)
		}
	}

	// The caps are enforced, not just respected by the catalog.
	over := dbprobe.FixtureTable{Name: "t", Columns: []dbprobe.FixtureColumn{{Name: "v", Type: "text"}}}
	for i := 0; i <= dbprobe.MaxFixtureRows; i++ {
		over.Rows = append(over.Rows, []any{"BAS-SIM-x"})
	}
	if dbprobe.ValidateFixtureTables([]dbprobe.FixtureTable{over}) == nil {
		t.Error("rows over the cap must be rejected")
	}
	big := dbprobe.FixtureTable{Name: "t", Columns: []dbprobe.FixtureColumn{{Name: "v", Type: "text"}},
		Rows: [][]any{{strings.Repeat("x", dbprobe.MaxFixtureCellBytes+1)}}}
	if dbprobe.ValidateFixtureTables([]dbprobe.FixtureTable{big}) == nil {
		t.Error("an oversized cell must be rejected")
	}
	bad := dbprobe.FixtureTable{Name: "t", Columns: []dbprobe.FixtureColumn{{Name: "v", Type: "text"}},
		Rows: [][]any{{"a\x00b"}}}
	if dbprobe.ValidateFixtureTables([]dbprobe.FixtureTable{bad}) == nil {
		t.Error("NUL in a cell must be rejected")
	}
	badUTF := dbprobe.FixtureTable{Name: "t", Columns: []dbprobe.FixtureColumn{{Name: "v", Type: "text"}},
		Rows: [][]any{{"a\xffb"}}}
	if dbprobe.ValidateFixtureTables([]dbprobe.FixtureTable{badUTF}) == nil {
		t.Error("invalid UTF-8 must be rejected")
	}
	badIdent := dbprobe.FixtureTable{Name: "t; drop", Columns: []dbprobe.FixtureColumn{{Name: "v", Type: "text"}}}
	if dbprobe.ValidateFixtureTables([]dbprobe.FixtureTable{badIdent}) == nil {
		t.Error("invalid identifier must be rejected")
	}
}
