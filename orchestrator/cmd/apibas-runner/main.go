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

	"github.com/audspect/bas/internal/apibas/catalog"
	"github.com/audspect/bas/internal/apibas/contract"
	"github.com/audspect/bas/internal/apibas/fixture"
	"github.com/audspect/bas/internal/apibas/runner"
)

func main() {
	target := flag.String("target", "http://127.0.0.1:8099", "lab base URL")
	scenarioID := flag.String("scenario", "API-BAS-AUTHZ-001", "scenario ID from the catalog")
	fixtureName := flag.String("fixture", "orders-two-tenant", "fixture the target was seeded with")
	allow := flag.String("allow", "", "comma-separated extra hosts the runner may reach (lab only)")
	flag.Parse()

	if err := checkTarget(*target, *allow); err != nil {
		log.Fatal(err)
	}
	fx, ok := map[string]fixture.Fixture{
		"orders-two-tenant":   fixture.OrdersTwoTenant(),
		"orders-no-protected": fixture.OrdersNoProtected(),
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
		State:   admin,
		Reset:   admin,
		HTTP:    &http.Client{Timeout: 10 * time.Second},
	})
	if err != nil {
		log.Fatal(err)
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
