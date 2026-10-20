// Command apibas-lab serves one variant of the Audspect API BAS lab target.
//
// It is a test target, not part of the orchestrator server. It is not mounted
// by cmd/server and must only run on an isolated lab host.
//
// Credentials come from the environment and are never printed:
//
//	APIBAS_CUSTOMER_A_TOKEN, APIBAS_CUSTOMER_B_TOKEN, APIBAS_LAB_ADMIN_TOKEN
package main

import (
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/audspect/bas/internal/apibas/fixture"
	"github.com/audspect/bas/internal/apibas/lab"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:8099", "listen address (loopback by default)")
	mode := flag.String("mode", "vulnerable", "vulnerable | fixed")
	fixtureName := flag.String("fixture", "orders-two-tenant", "fixture to seed")
	faults := flag.String("fault", "", "comma-separated dependency faults to hold active, for example authz-store-down")
	flag.Parse()

	fx, ok := fixtures()[*fixtureName]
	if !ok {
		log.Fatalf("unknown fixture %q", *fixtureName)
	}
	cfg, err := configFromEnv(lab.Mode(*mode), fx)
	if err != nil {
		log.Fatal(err)
	}
	for f := range strings.SplitSeq(*faults, ",") {
		if f = strings.TrimSpace(f); f != "" {
			cfg.Faults = append(cfg.Faults, f)
		}
	}
	l, err := lab.New(cfg)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("apibas-lab mode=%s fixture=%s listening on %s", *mode, fx.Name, *addr)
	if err := http.ListenAndServe(*addr, l.Handler()); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatal(err)
	}
}

// fixtures lists every fixture the lab and runner both understand.
func fixtures() map[string]fixture.Fixture {
	return map[string]fixture.Fixture{
		"orders-two-tenant":   fixture.OrdersTwoTenant(),
		"orders-no-protected": fixture.OrdersNoProtected(),
		"orders-paged":        fixture.OrdersPaged(),
	}
}

func configFromEnv(mode lab.Mode, fx fixture.Fixture) (lab.Config, error) {
	a := os.Getenv("APIBAS_CUSTOMER_A_TOKEN")
	b := os.Getenv("APIBAS_CUSTOMER_B_TOKEN")
	admin := os.Getenv("APIBAS_LAB_ADMIN_TOKEN")
	if a == "" || b == "" || admin == "" {
		return lab.Config{}, fmt.Errorf("set APIBAS_CUSTOMER_A_TOKEN, APIBAS_CUSTOMER_B_TOKEN and APIBAS_LAB_ADMIN_TOKEN")
	}
	tokens := map[string]string{a: "cust-a", b: "cust-b"}
	var revoked []string
	// The revoked token must be known to the lab, or the vulnerable build would
	// refuse it as invalid and AUTHN-002 would pass for the wrong reason.
	if rev := os.Getenv("APIBAS_CUSTOMER_A_REVOKED_TOKEN"); rev != "" {
		tokens[rev] = "cust-a"
		revoked = append(revoked, rev)
	}
	return lab.Config{
		Mode:       mode,
		Fixture:    fx,
		Tokens:     tokens,
		Revoked:    revoked,
		AdminToken: admin,
	}, nil
}
