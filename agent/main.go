//go:generate rsrc -manifest bas_agent.exe.manifest -ico logo.ico -arch amd64 -o rsrc.syso

package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"
)

const (
	version           = "2.1.0"
	heartbeatInterval = 30 * time.Second
)

func main() {
	log.SetFlags(log.Ldate | log.Ltime | log.Lmsgprefix)
	if p := initFileLogging(); p != "" {
		log.Printf("[*] agent log file: %s", p)
	}

	flagInstall := flag.Bool("install", false, "Install agent as a system service (requires root/admin)")
	flagUninstall := flag.Bool("uninstall", false, "Uninstall agent system service")
	flagServer := flag.String("server", "", "Override BAS_SERVER_URL")
	flagEnv := flag.String("env", "Production", "Override BAS_ENV_LABEL")
	flagSecret := flag.String("secret", "", "Agent shared secret (encrypted at rest via DPAPI on Windows)")
	flagCARoot := flag.String("ca-root", "", "Path to the deployment CA root PEM (required for mTLS enrollment; fetch via GET /api/config/connection)")

	registerPlatformFlags()
	flag.Parse()

	if platformHandleFlags() {
		return
	}

	if *flagInstall {
		serverURL := *flagServer
		if serverURL == "" {
			serverURL = os.Getenv("BAS_SERVER_URL")
		}
		if serverURL == "" {
			fmt.Fprintln(os.Stderr, "error: provide --server <url> or set BAS_SERVER_URL")
			os.Exit(1)
		}
		secret := *flagSecret
		if secret == "" {
			secret = os.Getenv("BAS_AGENT_SECRET")
		}
		if *flagCARoot != "" {
			pemBytes, err := os.ReadFile(*flagCARoot)
			if err != nil {
				fmt.Fprintf(os.Stderr, "error: read --ca-root file: %v\n", err)
				os.Exit(1)
			}
			// saveDeploymentCARoot validates that pemBytes parses as an
			// X.509 certificate before writing anything.
			if err := saveDeploymentCARoot(pemBytes); err != nil {
				fmt.Fprintf(os.Stderr, "error: --ca-root %s: %v\n", *flagCARoot, err)
				os.Exit(1)
			}
			fmt.Println("[+] deployment CA root installed")
		}
		if err := svcInstall(serverURL, *flagEnv, secret); err != nil {
			fmt.Fprintf(os.Stderr, "install failed: %v\n", err)
			os.Exit(1)
		}
		return
	}

	if *flagUninstall {
		if err := svcUninstall(); err != nil {
			fmt.Fprintf(os.Stderr, "uninstall failed: %v\n", err)
			os.Exit(1)
		}
		return
	}

	platformPreStart()

	if *flagServer != "" {
		os.Setenv("BAS_SERVER_URL", *flagServer)
	}
	if *flagEnv != "Production" {
		os.Setenv("BAS_ENV_LABEL", *flagEnv)
	}

	cfg := loadConfig()
	id := collectIdentity()

	fmt.Printf("\n")
	fmt.Printf("  BAS Agent v%s\n", version)
	fmt.Printf("  Hostname  : %s\n", id.Hostname)
	fmt.Printf("  AgentID   : %s\n", id.AgentID)
	fmt.Printf("  IP        : %s\n", id.IPAddress)
	fmt.Printf("  OS        : %s\n", id.OSVersion)
	fmt.Printf("  Server    : %s\n", cfg.ServerURL)
	fmt.Printf("  Env       : %s\n", cfg.EnvLabel)
	platformPrintBannerExtras(id)
	fmt.Printf("\n")

	// Certificate bootstrap/renewal runs BEFORE newAgent: newAgent builds
	// the long-lived HTTP client, log shipper and (via a.cfg()) the WS
	// dialer from cfg, so cfg must already carry the resolved mTLS
	// ServerURL and MTLS flag -- building them first is what left a
	// freshly bootstrapped agent with a non-mTLS client until restart.
	cfg, outcome := resolveOperationalConfig(context.Background(), cfg, id.AgentID)
	if outcome == outcomeBlocked {
		// An already-enrolled identity whose mTLS path is currently
		// unusable NEVER operates over legacy transport -- block here,
		// retrying with backoff, before newAgent (and therefore any
		// network communication at all) ever starts. If an operator
		// resets the enrollment marker to force a genuine re-bootstrap,
		// the next retry picks that up automatically via isEnrolled().
		attempt := 0
		for outcome == outcomeBlocked {
			delay := bootstrapRetryBackoff(attempt)
			log.Printf("[!] blocked pending mTLS recovery -- retrying in %s (attempt %d)", delay.Round(time.Second), attempt+1)
			time.Sleep(delay)
			attempt++
			cfg, outcome = resolveOperationalConfig(context.Background(), cfg, id.AgentID)
		}
	}
	agent := newAgent(cfg, id)
	agent.enrollWithServer()

	if outcome == outcomeLegacyPending {
		// Never-enrolled, initial bootstrap failed: operate on legacy
		// transport now (cfg as built above) while retrying bootstrap in
		// the background. retryBootstrapUntilEnrolled upgrades the running
		// agent's transport permanently the moment it succeeds.
		go agent.retryBootstrapUntilEnrolled(context.Background())
	}

	go agent.connectWS()
	go agent.startLocalAPI()
	go agent.runSpoolDrainer()
	go agent.runDisconnectWatchdog()
	go agent.runPressureLoop()
	agent.sendHeartbeat("idle")

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	ticker := time.NewTicker(heartbeatInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			agent.sendHeartbeat(agent.getStatus())
		case <-quit:
			log.Println("[*] Shutting down — finalizing active scenario if any...")
			agent.shutdownFinalize(shutdownGrace)
			agent.sendHeartbeat("offline")
			platformRestoreOnShutdown()
			return
		}
	}
}
