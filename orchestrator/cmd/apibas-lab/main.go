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
	"crypto/x509"
	"encoding/pem"
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
	useTLS := flag.Bool("tls", false, "serve HTTPS with a generated lab CA and server certificate")
	caOut := flag.String("tls-ca", "", "with -tls, write the lab CA certificate (PEM) to this path, for issuing client certificates")
	clientOut := flag.String("tls-client-cert", "", "with -tls, write a client certificate for cust-b (PEM) to this path, signed by the lab CA")
	clientKeyOut := flag.String("tls-client-key", "", "with -tls and -tls-client-cert, write the client certificate key (PKCS#8 PEM) to this path")
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
	var pki *lab.PKI
	if *useTLS {
		if pki, err = lab.NewPKI(); err != nil {
			log.Fatal(err)
		}
		cfg.ClientCAs = pki.CAPool
		if *caOut != "" {
			if err := os.WriteFile(*caOut, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: pki.CA.Raw}), 0o644); err != nil {
				log.Fatal(err)
			}
		}
		if *clientOut != "" {
			if *clientKeyOut == "" {
				log.Fatal("-tls-client-cert needs -tls-client-key")
			}
			cert, err := pki.IssueClientCert("cust-b")
			if err != nil {
				log.Fatal(err)
			}
			key, err := x509.MarshalPKCS8PrivateKey(cert.PrivateKey)
			if err != nil {
				log.Fatal(err)
			}
			if err := os.WriteFile(*clientOut, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]}), 0o600); err != nil {
				log.Fatal(err)
			}
			if err := os.WriteFile(*clientKeyOut, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key}), 0o600); err != nil {
				log.Fatal(err)
			}
		}
	}
	l, err := lab.New(cfg)
	if err != nil {
		log.Fatal(err)
	}
	if !*useTLS {
		log.Printf("apibas-lab mode=%s fixture=%s listening on %s", *mode, fx.Name, *addr)
		if err := http.ListenAndServe(*addr, l.Handler()); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatal(err)
		}
		return
	}
	srv := &http.Server{Addr: *addr, Handler: l.Handler(), TLSConfig: l.TLSConfig(pki.Server)}
	log.Printf("apibas-lab mode=%s fixture=%s listening on %s (TLS)", *mode, fx.Name, *addr)
	if err := srv.ListenAndServeTLS("", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatal(err)
	}
}

// fixtures lists every fixture the lab and runner both understand.
func fixtures() map[string]fixture.Fixture {
	return map[string]fixture.Fixture{
		"orders-two-tenant":   fixture.OrdersTwoTenant(),
		"orders-no-protected": fixture.OrdersNoProtected(),
		"orders-paged":        fixture.OrdersPaged(),
		"nbfc-two-borrower":   fixture.NBFCTwoBorrower(),
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
	// NBFC pack identities are optional. Each set variable names one caller, as the fixture names it.
	for env, caller := range map[string]string{
		"APIBAS_NBFC_BORROWER_A_TOKEN": "borrower-a",
		"APIBAS_NBFC_BORROWER_B_TOKEN": "borrower-b",
		"APIBAS_NBFC_OFFICER_TOKEN":    "loan-officer",
		"APIBAS_NBFC_ADMIN_TOKEN":      "nbfc-admin",
	} {
		if v := os.Getenv(env); v != "" {
			tokens[v] = caller
		}
	}
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
