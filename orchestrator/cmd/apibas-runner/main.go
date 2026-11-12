// Command apibas-runner executes one API BAS scenario against an approved
// target and prints the graded report as JSON.
//
// It is the dedicated test runner from blueprint D2. The orchestrator will
// schedule it later. Credentials come from the environment, are held only for
// this run, and never appear in the output:
//
//	APIBAS_CUSTOMER_A_TOKEN, APIBAS_CUSTOMER_B_TOKEN, APIBAS_LAB_ADMIN_TOKEN
//
// Targets are allowlisted. Only loopback and the lab hosts named by -allow are
// reachable.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/audspect/bas/internal/apibas/calibration"
	"github.com/audspect/bas/internal/apibas/catalog"
	"github.com/audspect/bas/internal/apibas/contract"
	"github.com/audspect/bas/internal/apibas/fixture"
	"github.com/audspect/bas/internal/apibas/runner"
	"github.com/audspect/bas/internal/apibas/runnerproto"
)

func main() {
	target := flag.String("target", "http://127.0.0.1:8099", "lab base URL")
	scenarioID := flag.String("scenario", "API-BAS-AUTHZ-001", "scenario ID from the catalog")
	fixtureName := flag.String("fixture", "orders-two-tenant", "fixture the target was seeded with")
	allow := flag.String("allow", "", "comma-separated extra hosts the runner may reach (lab only)")
	calibrate := flag.Bool("calibrate", false, "measure the baseline and write a new calibration record; runs no scenario")
	machine := flag.String("machine", "", "display label for the record; identity comes from the environment fingerprint, not this label")
	fixedTarget := flag.String("fixed-target", "", "lab base URL of the fixed build; required with -calibrate")
	calDir := flag.String("calibration-dir", "internal/apibas/calibration/records", "directory the calibration record is written to")
	jobRequest := flag.String("job-request", "", "orchestrator mode: run the JobRequest in this file and write a JobResult to stdout")
	flag.Parse()

	if *jobRequest != "" {
		os.Exit(runJob(*jobRequest))
	}

	if err := checkTarget(*target, *allow); err != nil {
		log.Fatal(err)
	}
	fx, ok := map[string]fixture.Fixture{
		"orders-two-tenant":   fixture.OrdersTwoTenant(),
		"orders-no-protected": fixture.OrdersNoProtected(),
		"orders-paged":        fixture.OrdersPaged(),
	}[*fixtureName]
	if !ok {
		log.Fatalf("unknown fixture %q", *fixtureName)
	}
	scen, err := findScenario(*scenarioID)
	if err != nil {
		log.Fatal(err)
	}

	secrets, adminTok, err := secretsFromEnv()
	// One lab-admin client serves both the state adapter and the reset adapter.
	admin := runner.NewLabAdmin(*target, adminTok)
	if err != nil {
		log.Fatal(err)
	}
	r, err := runner.New(runner.Config{
		BaseURL:   *target,
		Fixture:   fx,
		Secrets:   secrets,
		State:     admin,
		Reporting: admin,
		Reset:     admin,
		Events:    admin,
		HTTP:      &http.Client{Timeout: 10 * time.Second},
		Machine:   *machine,
	})
	if err != nil {
		log.Fatal(err)
	}
	if *calibrate {
		if err := checkTarget(*fixedTarget, *allow); err != nil {
			log.Fatal(err)
		}
		fixed, err := runner.New(runner.Config{BaseURL: *fixedTarget, Fixture: fx, Secrets: secrets, State: admin, Reporting: admin, Reset: admin, Events: admin, HTTP: &http.Client{Timeout: 10 * time.Second}})
		if err != nil {
			log.Fatal(err)
		}
		runCalibration(r, fixed, scen, *machine, *calDir)
		return
	}
	rep, err := r.Run(context.Background(), scen)
	if err != nil {
		log.Fatal(err)
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(rep); err != nil {
		log.Fatal(err)
	}
}

// runCalibration is the explicit recalibration operation. It writes the next record
// and prints the catalog values to update. It does not change the catalog itself.
func runCalibration(r, fixed *runner.Runner, scen contract.Scenario, machine, dir string) {
	if machine == "" {
		log.Fatal("calibrate needs -machine, a label for the hardware this run measures")
	}
	rec, err := r.Calibrate(context.Background(), scen, fixed, machine, dir)
	if err != nil {
		log.Fatal(err)
	}
	path, err := calibration.Write(dir, rec)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Fprintf(os.Stderr, "wrote %s\n", path)
	fmt.Fprintf(os.Stderr, "qualified: %v %v\n", rec.Qualified, rec.QualificationReasons)
	fmt.Fprintf(os.Stderr, "separation: p=%g ratio=%g vulnerable_median_ms=%g fixed_median_ms=%g\n",
		rec.Separation.P, rec.Separation.Ratio, rec.Separation.VulnMedianMs, rec.Separation.FixedMedianMs)
	fmt.Fprintf(os.Stderr, "set in %s:\n  calibration.version: %d\n  calibration.baseline_ms: %v\n",
		scen.ID, rec.Version, rec.Thresholds.DeclaredBaselineMs)
}

// checkTarget refuses any host that is not loopback or explicitly allowed.
// This keeps a lab-only runner from being pointed at an arbitrary address.
func checkTarget(raw, allow string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return fmt.Errorf("invalid target %q", raw)
	}
	host := u.Hostname()
	if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
		return nil
	}
	if host == "localhost" {
		return nil
	}
	if slices.Contains(splitComma(allow), host) {
		return nil
	}
	return fmt.Errorf("target host %q is not loopback and not in -allow; refusing to run", host)
}

func splitComma(s string) []string {
	var out []string
	for part := range strings.SplitSeq(s, ",") {
		if p := strings.TrimSpace(part); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func findScenario(id string) (contract.Scenario, error) {
	all, err := catalog.All()
	if err != nil {
		return contract.Scenario{}, err
	}
	for _, s := range all {
		if s.ID == id {
			return s, nil
		}
	}
	return contract.Scenario{}, fmt.Errorf("scenario %s not in catalog", id)
}

// secretsFromEnv maps the blueprint's secret references to environment
// variables. Production will use a secret store behind runner.SecretResolver.
func secretsFromEnv() (runner.SecretResolver, string, error) {
	m := runner.MapSecrets{}
	refs := map[string]string{
		"apibas/lab/customer-a": "APIBAS_CUSTOMER_A_TOKEN",
		"apibas/lab/customer-b": "APIBAS_CUSTOMER_B_TOKEN",
	}
	for ref, env := range refs {
		v := os.Getenv(env)
		if v == "" {
			return nil, "", fmt.Errorf("set %s", env)
		}
		m[ref] = v
	}
	// Optional: without it, scenarios that need the revoked credential are
	// precondition skips rather than runs.
	if rev := os.Getenv("APIBAS_CUSTOMER_A_REVOKED_TOKEN"); rev != "" {
		m["apibas/lab/customer-a-revoked"] = rev
	}
	admin := os.Getenv("APIBAS_LAB_ADMIN_TOKEN")
	if admin == "" {
		return nil, "", fmt.Errorf("set APIBAS_LAB_ADMIN_TOKEN")
	}
	return m, admin, nil
}

// runJob executes one orchestrator job. It reads a validated JobRequest, loads the job's credentials from the file the
// request names, runs each scenario, and writes one JobResult to stdout. It returns the process exit status. A failure at
// any point writes a failed result with a reason and no reports, so a crash or error can never look like success.
func runJob(path string) int {
	f, err := os.Open(path)
	if err != nil {
		return emitFailure(runnerproto.JobResult{}, "job request unreadable")
	}
	req, err := runnerproto.DecodeJobRequest(f)
	f.Close()
	if err != nil {
		return emitFailure(runnerproto.JobResult{}, err.Error())
	}
	base := runnerproto.JobResult{
		SchemaVersion: runnerproto.SchemaVersion, JobID: req.JobID,
		TargetBaseURL: req.TargetBaseURL, ScenarioIDs: req.ScenarioIDs,
	}
	if err := checkTarget(req.TargetBaseURL, strings.Join(req.AllowedHosts, ",")); err != nil {
		return emitFailure(base, err.Error())
	}
	// A customer-bound job carries its own scenarios (rebuilt here from the plan) and runs against the customer's API with no
	// independent state reader, so the runner grades read-only scenarios on the response alone and refuses anything else.
	plan, err := req.CheckBound()
	if err != nil {
		return emitFailure(base, err.Error())
	}
	creds, err := runnerproto.LoadCredentials(req.CredentialsFile)
	if err != nil {
		return emitFailure(base, err.Error())
	}
	var cfg runner.Config
	var boundScenarios map[string]contract.Scenario
	if plan != nil {
		boundScenarios = make(map[string]contract.Scenario, len(plan.Scenarios))
		for _, sc := range plan.Scenarios {
			boundScenarios[sc.ID] = sc
		}
		cfg = runner.Config{
			BaseURL: req.TargetBaseURL, Fixture: plan.Fixture, Secrets: creds, State: runner.NoState{},
			HTTP: &http.Client{Timeout: 10 * time.Second}, AllowedPaths: req.AllowedPaths,
		}
		if plan.Writes {
			// Write scenarios are judged by reading each object back as its owner, and are cleaned up by the owner's restore
			// request. Both stay inside the job's allowed paths.
			tokenRef := func(identity string) string {
				id, _ := plan.Fixture.Identity(identity)
				return id.TokenRef
			}
			probes := make([]runner.Probe, 0, len(plan.Probes))
			for _, p := range plan.Probes {
				probes = append(probes, runner.Probe{Key: p.Key, TokenRef: tokenRef(p.Identity), Path: p.Path, Ignore: p.Ignore, Watch: p.Watch})
			}
			restores := make([]runner.Restore, 0, len(plan.Restores))
			for _, rs := range plan.Restores {
				restores = append(restores, runner.Restore{Key: rs.Key, TokenRef: tokenRef(rs.Identity), Method: rs.Method, Path: rs.Path, Body: rs.Body})
			}
			st, serr := runner.NewHTTPState(req.TargetBaseURL, probes, creds, cfg.HTTP, req.AllowedPaths)
			if serr != nil {
				return emitFailure(base, serr.Error())
			}
			rr, rerr := runner.NewHTTPRestore(req.TargetBaseURL, restores, creds, cfg.HTTP, req.AllowedPaths)
			if rerr != nil {
				return emitFailure(base, rerr.Error())
			}
			cfg.State, cfg.Reset = st, rr
		}
	} else {
		fx, ok := map[string]fixture.Fixture{
			"orders-two-tenant":   fixture.OrdersTwoTenant(),
			"orders-no-protected": fixture.OrdersNoProtected(),
			"orders-paged":        fixture.OrdersPaged(),
		}[req.Fixture]
		if !ok {
			return emitFailure(base, "unknown fixture")
		}
		admin := runner.NewLabAdmin(req.TargetBaseURL, creds["apibas/lab/admin"])
		cfg = runner.Config{
			BaseURL: req.TargetBaseURL, Fixture: fx, Secrets: creds,
			State: admin, Reporting: admin, Reset: admin, Events: admin,
			HTTP: &http.Client{Timeout: 10 * time.Second}, AllowedPaths: req.AllowedPaths,
		}
	}
	r, err := runner.New(cfg)
	if err != nil {
		return emitFailure(base, "runner setup failed")
	}
	reports := make([]runner.Report, 0, len(req.ScenarioIDs))
	for _, id := range req.ScenarioIDs {
		var scen contract.Scenario
		if boundScenarios != nil {
			bs, found := boundScenarios[id]
			if !found {
				return emitFailure(base, "scenario not in the bound plan")
			}
			scen = bs
		} else {
			var ferr error
			if scen, ferr = findScenario(id); ferr != nil {
				return emitFailure(base, "scenario not in the catalog")
			}
		}
		if err := runner.CheckScope(req.AllowedPaths, scen); err != nil {
			return emitFailure(base, err.Error())
		}
		rep, err := r.Run(context.Background(), scen)
		if err != nil {
			return emitFailure(base, "scenario did not complete")
		}
		reports = append(reports, rep)
	}
	base.Status = runnerproto.StatusCompleted
	base.Reports = reports
	if err := runnerproto.EncodeResult(os.Stdout, base); err != nil {
		return 1
	}
	return 0
}

// emitFailure writes a failed JobResult. The reason is kept short and never carries a credential value.
func emitFailure(base runnerproto.JobResult, reason string) int {
	base.SchemaVersion = runnerproto.SchemaVersion
	base.Status = runnerproto.StatusFailed
	base.Error = reason
	base.Reports = nil
	_ = runnerproto.EncodeResult(os.Stdout, base)
	return 1
}
