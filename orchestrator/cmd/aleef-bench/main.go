// Command aleef-bench runs the Aleef Milestone 1 held-out evaluation against
// the synthetic bank, on loopback only, under a lab engagement.
//
//	go run ./cmd/aleef-bench -fixed-only                     rehearsal: fixed build, no labels, no sealed file
//	go run -tags aleefsealed ./cmd/aleef-bench -labels PATH  full evaluation (owner supplies the sealed file and labels)
//
// This command is the only place the bank is wired in. The campaign receives
// the OpenAPI document served by the bank, the accounts, the operator's class
// table and the setup declaration, and nothing else: it never sees a policy,
// a label or a defect.
package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/aleef/bank"
	"github.com/audspect/bas/internal/aleef/bank/sealed"
	"github.com/audspect/bas/internal/aleef/bench"
	"github.com/audspect/bas/internal/aleef/campaign"
	"github.com/audspect/bas/internal/aleef/model"
	"github.com/audspect/bas/internal/aleef/property"
	"github.com/audspect/bas/internal/aleef/safety"
	"github.com/audspect/bas/internal/aleef/store"
	"github.com/audspect/bas/internal/testutil"
)

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "aleef-bench:", err)
		os.Exit(1)
	}
}

func run(args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("aleef-bench", flag.ContinueOnError)
	labelsPath := fs.String("labels", "", "path to the owner's labels file (outside the repository; required unless -fixed-only)")
	fixedOnly := fs.Bool("fixed-only", false, "rehearsal: run only the fixed build; needs no labels and no sealed file")
	out := fs.String("out", "", "write the markdown report to this path")
	seed := fs.Int64("seed", 1, "generation seed")
	maxTests := fs.Int("max-tests", 0, "cap on generated tests per build (0 = no cap)")
	dbURL := fs.String("database-url", "", "Postgres URL; empty starts a throwaway Postgres container (Docker)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var labels []bench.Label
	var vulnPolicy *bank.Policy
	if !*fixedOnly {
		if *labelsPath == "" {
			return errors.New("-labels is required (or use -fixed-only for the rehearsal)")
		}
		var err error
		if labels, err = bench.LoadLabels(*labelsPath); err != nil {
			return err
		}
		// Refuse before anything runs when the sealed defects are not compiled in.
		p, err := vulnerablePolicy(labels)
		if err != nil {
			return err
		}
		vulnPolicy = &p
	}

	st, closeDB, err := openStore(ctx, *dbURL)
	if err != nil {
		return err
	}
	defer closeDB()

	runBuild := func(build string) (bench.RunOutcome, error) {
		pol := bank.FixedPolicy()
		if build == bench.BuildVulnerable {
			pol = *vulnPolicy
		}
		return runOne(ctx, st, build, pol, *seed, *maxTests)
	}

	started := time.Now()
	var md string
	if *fixedOnly {
		o, err := runBuild(bench.BuildFixed)
		if err != nil {
			return err
		}
		md = bench.FixedOnlyMarkdown(o) + fmt.Sprintf("\nElapsed: %s\n", time.Since(started).Round(time.Millisecond))
		if len(o.Findings) > 0 {
			defer func() {
				fmt.Fprintln(os.Stderr, "aleef-bench: verified findings on the fixed build: milestone would fail")
			}()
		}
	} else {
		rep, err := bench.Evaluate(ctx, labels, runBuild)
		if err != nil {
			return err
		}
		md = rep.Markdown() + fmt.Sprintf("\nElapsed: %s\n", time.Since(started).Round(time.Millisecond))
	}
	fmt.Fprint(stdout, md)
	if *out != "" {
		if err := os.WriteFile(*out, []byte(md), 0o644); err != nil {
			return fmt.Errorf("write report: %w", err)
		}
	}
	return nil
}

func openStore(ctx context.Context, dsn string) (*store.Store, func(), error) {
	if dsn == "" {
		tdb := testutil.MustSharedTestDB()
		if err := store.EnsureSchema(ctx, tdb.Pool); err != nil {
			tdb.Cleanup()
			return nil, nil, err
		}
		return store.New(tdb.Pool), tdb.Cleanup, nil
	}
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return nil, nil, fmt.Errorf("connect database: %w", err)
	}
	if err := store.EnsureSchema(ctx, pool); err != nil {
		pool.Close()
		return nil, nil, err
	}
	return store.New(pool), pool.Close, nil
}

// vulnerablePolicy composes the sealed policy generically: for every label id
// it asks the sealed package for that id's policy and takes each hook that
// differs from the fixed policy. It knows nothing about which hooks or ids are
// defective. The stub (built without the aleefsealed tag) answers false for
// every id, which is refused.
func vulnerablePolicy(labels []bench.Label) (bank.Policy, error) {
	return composePolicy(labels, sealed.Policy)
}

func composePolicy(labels []bench.Label, lookup func(string) (bank.Policy, bool)) (bank.Policy, error) {
	fixed := bank.FixedPolicy()
	merged := fixed
	fv, mv := reflect.ValueOf(fixed), reflect.ValueOf(&merged).Elem()
	changedBy := map[int]string{}
	for _, l := range labels {
		p, ok := lookup(l.ID)
		if !ok {
			return bank.Policy{}, fmt.Errorf("the sealed policy for %q is not available: build with -tags aleefsealed and the owner's sealed file (the default build has no sealed defects; the vulnerable evaluation is refused)", l.ID)
		}
		pv := reflect.ValueOf(p)
		changed := 0
		for i := 0; i < pv.NumField(); i++ {
			if pv.Field(i).IsNil() {
				return bank.Policy{}, fmt.Errorf("sealed policy %q leaves a hook unset", l.ID)
			}
			if pv.Field(i).Pointer() == fv.Field(i).Pointer() {
				continue
			}
			if prev, dup := changedBy[i]; dup {
				return bank.Policy{}, fmt.Errorf("sealed policies %q and %q both replace the same hook; supply policies that replace disjoint hooks", prev, l.ID)
			}
			changedBy[i] = l.ID
			mv.Field(i).Set(pv.Field(i))
			changed++
		}
		if changed == 0 {
			return bank.Policy{}, fmt.Errorf("sealed policy %q is identical to the fixed policy", l.ID)
		}
	}
	return merged, nil
}

// ---- the lab setup ----

// opClass is the operator's declarative class table for the bank's documented
// resources (reads, beneficiary and payment lifecycle, transactions). It is
// keyed by "METHOD path" exactly as the OpenAPI document lists them and holds
// no knowledge of which operations are flawed.
var opClass = map[string]model.OpClass{
	"POST /v2/beneficiaries":         model.ClassSetupSafe,
	"PATCH /v2/beneficiaries/{id}":   model.ClassReversible,
	"DELETE /v2/beneficiaries/{id}":  model.ClassReversible,
	"DELETE /v2/transactions/{id}":   model.ClassReversible,
	"DELETE /v2/payments/{id}":       model.ClassReversible,
	"POST /v2/transactions":          model.ClassSetupSafe,
	"POST /v2/payments":              model.ClassSetupSafe,
	"PATCH /v2/payments/{id}":        model.ClassReversible,
	"POST /v2/payments/{id}/approve": model.ClassReversible,
	"POST /v2/payments/{id}/settle":  model.ClassMoney,
}

// classify maps operation ids to classes: every GET is a read, everything
// else comes from opClass; anything unlisted stays unclassified (never run).
func classify(m model.Model) (classes map[string]model.OpClass, ids map[string]string) {
	classes, ids = map[string]model.OpClass{}, map[string]string{}
	for _, op := range m.Operations {
		key := strings.ToUpper(op.Method) + " " + op.Path
		ids[op.ID] = key
		if strings.EqualFold(op.Method, "GET") {
			classes[op.ID] = model.ClassRead
		} else if c, ok := opClass[key]; ok {
			classes[op.ID] = c
		}
	}
	return classes, ids
}

type secrets map[string]string

func (s secrets) Resolve(ref string) (string, error) {
	if v, ok := s[ref]; ok {
		return v, nil
	}
	return "", errors.New("no secret")
}

func token() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// recorder wraps the campaign's base transport and records every request's
// origin and method/path so the harness can state facts about what was sent.
type recorder struct {
	base http.RoundTripper
	mu   sync.Mutex
	reqs []reqRecord
}

type reqRecord struct {
	at           time.Time
	origin       string
	method, path string
}

func (r *recorder) RoundTrip(req *http.Request) (*http.Response, error) {
	r.mu.Lock()
	r.reqs = append(r.reqs, reqRecord{at: time.Now(), origin: req.URL.Scheme + "://" + req.URL.Host, method: req.Method, path: req.URL.Path})
	r.mu.Unlock()
	return r.base.RoundTrip(req)
}

func pathRegexp(tmpl string) *regexp.Regexp {
	re := regexp.MustCompile(`\\\{[^}]*\\\}`).ReplaceAllString(regexp.QuoteMeta(tmpl), `[^/]+`)
	return regexp.MustCompile("^" + re + "$")
}

func runOne(ctx context.Context, st *store.Store, build string, pol bank.Policy, seed int64, maxTests int) (bench.RunOutcome, error) {
	var o bench.RunOutcome
	// ---- the bank, on loopback only
	tAlice, tBob, tCarol := token(), token(), token()
	srv, err := bank.New(bank.Config{Policy: pol, Tokens: map[string]bank.Principal{
		tAlice: {ID: "cust-a", Role: bank.RoleCustomer},
		tBob:   {ID: "cust-b", Role: bank.RoleCustomer},
		tCarol: {ID: "appr-c", Role: bank.RoleApprover},
	}})
	if err != nil {
		return o, err
	}
	// The bank's documented seed: one account per principal and one
	// document per customer. These are the objects the API cannot create; the
	// bench declares them as the accounts' Existing objects below.
	accA, accB, accC := srv.AddAccount("cust-a", 100000), srv.AddAccount("cust-b", 100000), srv.AddAccount("appr-c", 100000)
	docA, docB := srv.AddDocument("cust-a", "doc-a"), srv.AddDocument("cust-b", "doc-b")
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return o, err
	}
	ts := httptest.NewUnstartedServer(srv.Handler())
	ts.Listener = ln
	ts.Start()
	defer ts.Close()
	base := ts.URL

	// ---- the only campaign inputs: the served OpenAPI document and declarations
	resp, err := http.Get(base + "/openapi.json")
	if err != nil {
		return o, err
	}
	spec, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	resp.Body.Close()
	if err != nil {
		return o, err
	}
	m, err := model.Import(spec)
	if err != nil {
		return o, err
	}
	classes, keyOf := classify(m)
	idOf := map[string]string{}
	for id, k := range keyOf {
		idOf[k] = id
	}
	var setup []model.SetupOp
	for _, s := range setupDecl {
		id, ok := idOf[s.key]
		if !ok {
			return o, fmt.Errorf("setup operation %q not found in the served OpenAPI document", s.key)
		}
		comp, ok := idOf[s.compensate]
		if !ok {
			return o, fmt.Errorf("compensating operation %q not found in the served OpenAPI document", s.compensate)
		}
		setup = append(setup, model.SetupOp{OperationID: id, Body: s.body, Compensate: comp})
	}
	var listed []string
	for id := range classes {
		listed = append(listed, id)
	}
	sort.Strings(listed)

	now := time.Now()
	eng := safety.Engagement{
		ID: "aleef-bench-" + build, Customer: "synthetic-bank-lab", Environment: "lab", Hosts: []string{base},
		Approver: "bench-operator", NotBefore: now.Add(-time.Minute), NotAfter: now.Add(2 * time.Hour),
		MaxRequests: 200000, MaxConcurrent: 8, RPS: 2000,
		// Money operations run only here: lab engagement, loopback origin,
		// synthetic bank, simulated rail, explicit operation list. The safety
		// rules for UAT and production are unchanged.
		SimulatedRail: true, SimulatorBeneficiaries: []string{"bench payee"}, Operations: listed,
	}
	rec := &recorder{base: http.DefaultTransport}
	cfg := campaign.Config{
		OpenAPI: spec, BaseURL: base, Engagement: eng,
		Accounts: []model.Account{
			{Name: "alice", CustomerID: "cust-a", TokenRef: "ref-alice", Role: bank.RoleCustomer,
				Existing: map[string]string{"account": accA.ID, "document": docA.ID, "customer": "cust-a"}},
			{Name: "bob", CustomerID: "cust-b", TokenRef: "ref-bob", Role: bank.RoleCustomer,
				Existing: map[string]string{"account": accB.ID, "document": docB.ID, "customer": "cust-b"}},
			{Name: "carol", CustomerID: "appr-c", TokenRef: "ref-carol", Role: bank.RoleApprover,
				Existing: map[string]string{"account": accC.ID, "customer": "appr-c"}},
		},
		Setup:    setup,
		Classes:  classes,
		Roles:    []string{bank.RoleCustomer, bank.RoleApprover},
		Workflow: workflow(idOf),
		Secrets:  secrets{"ref-alice": tAlice, "ref-bob": tBob, "ref-carol": tCarol},
		Recorder: st,
		Options:  campaign.Options{Seed: seed, MaxTests: maxTests},
		HTTP:     &http.Client{Transport: rec, Timeout: 30 * time.Second},
	}
	rep, err := campaign.Run(ctx, cfg)
	if err != nil {
		return o, fmt.Errorf("%s build: campaign: %w", build, err)
	}
	out := toOutcome(ctx, st, rep, rec, base, eng, keyOf, classes)
	// Cleanup is assessable now that the bank has delete operations: the
	// campaign reports no orphans and the bank itself holds no test objects.
	tx, bn, py := srv.ObjectCounts()
	out.SafetyChecks["cleanup_left_no_objects"] = len(rep.Orphans) == 0 && tx+bn+py == 0
	return out, nil
}

// setupDecl creates, per account and in order, the objects the API can create.
// Later bodies reference earlier objects of the same account through the
// {{self.<type>.id}} placeholder; the account's own seeded account is an
// Existing object.
var setupDecl = []struct {
	key, compensate string
	body            map[string]any
}{
	{"POST /v2/beneficiaries", "DELETE /v2/beneficiaries/{id}", map[string]any{"name": "bench payee", "account_number": "000111222"}},
	{"POST /v2/transactions", "DELETE /v2/transactions/{id}", map[string]any{"account_id": "{{self.account.id}}", "amount": 100, "description": "bench entry"}},
	{"POST /v2/payments", "DELETE /v2/payments/{id}", map[string]any{"account_id": "{{self.account.id}}", "beneficiary_id": "{{self.beneficiary.id}}", "amount": 100}},
}

// workflow is the operator's declaration of the payment lifecycle from the
// bank's documented resources (initiate, approve, modify, settle, read).
func workflow(idOf map[string]string) *property.Workflow {
	return &property.Workflow{
		Name: "payment",
		Steps: []property.WorkflowStep{
			{Op: idOf["POST /v2/payments"], Kind: property.StepCreate},
			{Op: idOf["POST /v2/payments/{id}/approve"], Kind: property.StepAuthorize, Role: bank.RoleApprover},
			{Op: idOf["PATCH /v2/payments/{id}"], Kind: property.StepModify},
			{Op: idOf["POST /v2/payments/{id}/settle"], Kind: property.StepExecute},
			{Op: idOf["GET /v2/payments/{id}"], Kind: property.StepRead},
		},
		SuccessValues: []string{"settled"},
	}
}

func toOutcome(ctx context.Context, st *store.Store, rep campaign.Report, rec *recorder, base string, eng safety.Engagement,
	keyOf map[string]string, classes map[string]model.OpClass) bench.RunOutcome {
	o := bench.RunOutcome{
		TestsGenerated: rep.Total, TestsRun: rep.Executed,
		CoveragePerOperation: map[string]int{},
		OperationAliases:     keyOf,
		ControlsOK:           map[string]bool{}, RegressionSaved: map[string]bool{}, Reproductions: map[string]int{},
		SafetyChecks: map[string]bool{},
		Halted:       rep.Halted,
	}
	o.SkipReasons, o.NoFixtureDropped = map[string]string{}, map[string]int{}
	for id, c := range rep.PerOperation {
		o.CoveragePerOperation[id] = c.Generated
		if c.Skipped != "" {
			o.SkipReasons[id] = c.Skipped
		}
	}
	for t, n := range rep.Generated.NoFixture {
		o.NoFixtureDropped[t] = n
	}
	o.StateCounts = map[string]int{}
	for _, t := range rep.Tests {
		if t.Executed && t.State != "clean" {
			o.NotClean = append(o.NotClean, bench.TestNote{TestID: t.TestID, Property: t.Property, Operation: t.Operation, State: t.State, Reason: t.Reason})
		}
		if t.Executed {
			k := t.State
			if t.Reason != "" {
				k += ": " + t.Reason
			}
			o.StateCounts[k]++
		}
	}
	repro := map[string]int{}
	for _, t := range rep.Tests {
		repro[t.TestID] = t.Reproductions
	}
	for _, f := range rep.Findings {
		bf := bench.Finding{Finding: store.Finding{ID: f.FindingID, TestID: f.TestID, Property: f.Property, State: f.State}, Operation: f.Operation}
		if f.State == "verified" {
			o.Findings = append(o.Findings, bf)
			// A verified verdict requires the owner and negative controls to
			// pass in every round (verify package contract).
			o.ControlsOK[f.FindingID] = true
			o.Reproductions[f.FindingID] = repro[f.TestID]
			if r, err := st.GetRegression(ctx, f.FindingID); err == nil && r.RegressionID != "" && len(r.BundleJSON) > 0 {
				o.RegressionSaved[f.FindingID] = true
			}
		} else {
			o.Candidates = append(o.Candidates, bf)
		}
	}

	// ---- safety facts the harness can know without defect knowledge
	rec.mu.Lock()
	reqs := append([]reqRecord(nil), rec.reqs...)
	rec.mu.Unlock()
	onlyOrigin, inWindow := true, true
	var moneyRe []struct {
		method string
		re     *regexp.Regexp
	}
	for id, c := range classes {
		if c == model.ClassMoney {
			parts := strings.SplitN(keyOf[id], " ", 2)
			moneyRe = append(moneyRe, struct {
				method string
				re     *regexp.Regexp
			}{parts[0], pathRegexp(parts[1])})
		}
	}
	moneySent := 0
	for _, r := range reqs {
		if r.origin != base {
			onlyOrigin = false
		}
		if r.at.Before(eng.NotBefore) || !r.at.Before(eng.NotAfter) {
			inWindow = false
		}
		for _, m := range moneyRe {
			if r.method == m.method && m.re.MatchString(r.path) {
				moneySent++
			}
		}
	}
	u, _ := url.Parse(base)
	ip := net.ParseIP(u.Hostname())
	o.SafetyChecks["no_prod_target"] = eng.Environment == "lab" && ip != nil && ip.IsLoopback()
	o.SafetyChecks["requests_only_to_engaged_origin"] = onlyOrigin && len(reqs) > 0
	o.SafetyChecks["requests_inside_engagement_window"] = inWindow
	o.SafetyChecks["engagement_enforced"] = rep.Requests > 0 && rep.Requests <= eng.MaxRequests
	// Money requests are allowed only on the lab loopback bank under the
	// declared simulated rail; the guard enforces the operation list.
	o.SafetyChecks["money_requests_only_under_lab_simulated_rail"] = moneySent == 0 ||
		(eng.Environment == "lab" && eng.SimulatedRail && len(eng.SimulatorBeneficiaries) > 0 && onlyOrigin && ip != nil && ip.IsLoopback())
	o.SafetyNotAssessed = []string{
		"no_unauthorized_money_movement (a settlement reached without authorization cannot be judged without defect knowledge; the owner assesses it from the bank's own logs)",
	}
	sort.Strings(o.SafetyNotAssessed)
	return o
}
