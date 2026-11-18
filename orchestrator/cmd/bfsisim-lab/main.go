// Command bfsisim-lab runs the BFSI service-discovery stub used by the
// cobalt-group-bfsi-discovery scenarios (bfsi-01..04).
//
// It is a test target, not part of the orchestrator server, and must only
// run on an isolated lab host. Set BFSI_SIMULATOR_HOST / BFSI_SIMULATOR_PORT
// on the agent running the scenario to point it at this process (defaults:
// localhost:9999, matching the scenarios' lib.ps1).
package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"

	"flag"

	"github.com/audspect/bas/internal/bfsisim"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:9999", "listen address (loopback by default)")
	flag.Parse()

	sim := bfsisim.NewSimulator(*addr)
	if err := sim.Start(); err != nil {
		log.Fatalf("bfsisim-lab: %v", err)
	}
	log.Printf("bfsisim-lab: listening on %s", sim.Addr())
	log.Printf("bfsisim-lab: services %v", sim.RegisteredServices())

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	<-stop

	log.Print("bfsisim-lab: shutting down")
	_ = sim.Stop(context.Background())
}
