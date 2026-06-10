//go:generate rsrc -manifest bas_agent.exe.manifest -arch amd64 -o rsrc.syso

package main

import (
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
	wsReconnectDelay  = 5 * time.Second
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

	agent := newAgent(cfg, id)
	agent.enrollWithServer()

	go agent.connectWS()
	go agent.startLocalAPI()
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
			log.Println("[*] Shutting down — interrupting active scenario if any...")
			agent.scenarioMu.Lock()
			if agent.cancelScenario != nil {
				agent.cancelScenario()
			}
			agent.scenarioMu.Unlock()
			time.Sleep(3 * time.Second)
			agent.sendHeartbeat("offline")
			platformRestoreOnShutdown()
			return
		}
	}
}
