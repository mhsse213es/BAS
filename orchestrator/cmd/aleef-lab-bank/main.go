// Command aleef-lab-bank serves the synthetic bank API for manual Aleef testing on a lab host.
//
// It runs the FIXED policy (no seeded defects) and seeds three identities whose tokens come from
// environment variables. It is a lab tool: bind it to a lab interface only, never a public one.
//
//	ALEEF_LAB_TOKEN_ALICE=... ALEEF_LAB_TOKEN_BOB=... ALEEF_LAB_TOKEN_CAROL=... \
//	  go run ./cmd/aleef-lab-bank -addr 192.168.11.152:8089
package main

import (
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/audspect/bas/internal/aleef/bank"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:8089", "listen address (use a lab interface, not 0.0.0.0 on a public host)")
	flag.Parse()
	if err := run(*addr); err != nil {
		log.Fatal(err)
	}
}

func run(addr string) error {
	alice, bob, carol := os.Getenv("ALEEF_LAB_TOKEN_ALICE"), os.Getenv("ALEEF_LAB_TOKEN_BOB"), os.Getenv("ALEEF_LAB_TOKEN_CAROL")
	if alice == "" || bob == "" || carol == "" {
		return errors.New("set ALEEF_LAB_TOKEN_ALICE, ALEEF_LAB_TOKEN_BOB and ALEEF_LAB_TOKEN_CAROL")
	}
	srv, err := bank.New(bank.Config{
		Policy: bank.FixedPolicy(),
		Tokens: map[string]bank.Principal{
			alice: {ID: "cust-a", Role: bank.RoleCustomer},
			bob:   {ID: "cust-b", Role: bank.RoleCustomer},
			carol: {ID: "appr-c", Role: bank.RoleApprover},
		},
	})
	if err != nil {
		return err
	}
	srv.AddAccount("cust-a", 100000)
	srv.AddAccount("cust-b", 50000)
	srv.AddDocument("cust-a", "kyc-alice.pdf")
	srv.AddDocument("cust-b", "kyc-bob.pdf")
	fmt.Printf("synthetic bank (fixed build) listening on http://%s  (OpenAPI: /openapi.json)\n", addr)
	return http.ListenAndServe(addr, srv.Handler())
}
