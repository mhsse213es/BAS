// carbanak-ledger-sim is a lab-only simulated banking ledger for the Carbanak BFSI
// scenarios. It is started by hand on the test endpoint. It never connects to a
// real banking system.
package main

import (
	"flag"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/audspect/bas/internal/carbanakledger"
)

func main() {
	configPath := flag.String("config", "", "path to the ledger JSON config (required)")
	flag.Parse()
	if *configPath == "" {
		fail("--config is required")
	}

	cfg, err := carbanakledger.LoadConfig(*configPath)
	if err != nil {
		fail(err.Error())
	}
	allowNonLocal := os.Getenv("BAS_CARBANAK_ALLOW_NONLOCAL") == "1"
	if err := carbanakledger.CheckListenAddr(cfg.ListenAddr, cfg.LabHostname, allowNonLocal); err != nil {
		fail(err.Error())
	}

	log, err := carbanakledger.Open(cfg.AuditPath)
	if err != nil {
		fail(err.Error())
	}

	now := time.Now
	if v := os.Getenv("BAS_CARBANAK_FIXED_TIME"); v != "" {
		fixed, err := time.Parse(time.RFC3339, v)
		if err != nil {
			fail(fmt.Sprintf("BAS_CARBANAK_FIXED_TIME: %v", err))
		}
		now = func() time.Time { return fixed }
	}

	srv, err := carbanakledger.NewServer(cfg, log, now)
	if err != nil {
		fail(err.Error())
	}
	ln, err := carbanakledger.Listen(cfg.ListenAddr)
	if err != nil {
		fail(err.Error())
	}
	fmt.Printf("carbanak-ledger-sim listening on %s\n", cfg.ListenAddr)
	if err := http.Serve(ln, srv); err != nil {
		fail(err.Error())
	}
}

func fail(msg string) {
	fmt.Fprintln(os.Stderr, "ERROR: "+msg)
	os.Exit(2)
}
