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

	"github.com/audspect/bas/internal/apibas/fixture"
	"github.com/audspect/bas/internal/apibas/lab"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:8099", "listen address (loopback by default)")
	mode := flag.String("mode", "vulnerable", "vulnerable | fixed")
	fixtureName := flag.String("fixture", "orders-two-tenant", "fixture to seed")
	flag.Parse()

	fx, ok := fixtures()[*fixtureName]
	if !ok {
		log.Fatalf("unknown fixture %q", *fixtureName)
	}
	cfg, err := configFromEnv(lab.Mode(*mode), fx)
	if err != nil {
		log.Fatal(err)
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
	}
}

func configFromEnv(mode lab.Mode, fx fixture.Fixture) (lab.Config, error) {
	a := os.Getenv("APIBAS_CUSTOMER_A_TOKEN")
	b := os.Getenv("APIBAS_CUSTOMER_B_TOKEN")
	admin := os.Getenv("APIBAS_LAB_ADMIN_TOKEN")
	if a == "" || b == "" || admin == "" {
		return lab.Config{}, fmt.Errorf("set APIBAS_CUSTOMER_A_TOKEN, APIBAS_CUSTOMER_B_TOKEN and APIBAS_LAB_ADMIN_TOKEN")
	}
	return lab.Config{
		Mode:       mode,
		Fixture:    fx,
		Tokens:     map[string]string{a: "cust-a", b: "cust-b"},
		AdminToken: admin,
	}, nil
}
