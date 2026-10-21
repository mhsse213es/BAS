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
	"github.com/audspect/bas/internal/db"
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
	buildLabel := flag.String("build", "", "which build the target is: vulnerable or fixed; required when APIBAS_DB_DSN is set")
	flag.Parse()

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
		BaseURL: *target,
		Fixture: fx,
		Secrets: secrets,
		State:     admin,
		Reporting: admin,
		Reset:   admin,
		Events:  admin,
		HTTP:    &http.Client{Timeout: 10 * time.Second},
		Machine: *machine,
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
	dsn := os.Getenv("APIBAS_DB_DSN")
	if dsn != "" && *buildLabel != "vulnerable" && *buildLabel != "fixed" {
		log.Fatal("-build must be vulnerable or fixed when APIBAS_DB_DSN is set")
	}
	rep, err := r.Run(context.Background(), scen)
	if err != nil {
		log.Fatal(err)
	}
	if dsn != "" {
		persistRun(dsn, rep, *buildLabel)
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

// persistRun stores one run in apibas_runs. The report is the same JSON printed to stdout. The database is
// reached only through APIBAS_DB_DSN, so the credential never appears on the command line.
func persistRun(dsn string, rep runner.Report, build string) {
	ctx := context.Background()
	pool, err := db.Connect(ctx, dsn)
	if err != nil {
		log.Fatalf("persist: %v", err)
	}
	defer pool.Close()
	if err := db.EnsureAPIBASRunSchema(ctx, pool); err != nil {
		log.Fatalf("persist schema: %v", err)
	}
	raw, err := json.Marshal(rep)
	if err != nil {
		log.Fatalf("persist encode: %v", err)
	}
	id, err := db.SaveAPIBASRun(ctx, pool, db.APIBASRun{
		RunTag: rep.RunTag, ScenarioID: rep.ScenarioID, Build: build,
		Result: string(rep.Outcome.Result), Exploitability: string(rep.Outcome.Exploitability),
		Control: string(rep.Outcome.Control), Detection: rep.Outcome.Detection,
		Reason: string(rep.Outcome.Reason), Report: raw,
	})
	if err != nil {
		log.Fatalf("persist: %v", err)
	}
	log.Printf("stored apibas run %s (%s, %s)", id, rep.ScenarioID, build)
}
