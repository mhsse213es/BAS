package main

import (
	"flag"
	"log"
	"os"
	"time"
)

const heartbeatInterval = 30 * time.Second

func main() {
	log.SetFlags(log.Ldate | log.Ltime | log.Lmsgprefix)

	flagInstall := flag.Bool("install", false, "Install agent as a Windows service (requires Administrator)")
	flagUninstall := flag.Bool("uninstall", false, "Uninstall agent Windows service")
	flagServer := flag.String("server", "", "Override BAS_SERVER_URL")
	flagEnv := flag.String("env", "Production", "Override BAS_ENV_LABEL")
	flagSecret := flag.String("secret", "", "Agent shared secret")
	flag.Parse()

	if *flagInstall {
		serverURL := *flagServer
		if serverURL == "" {
			serverURL = os.Getenv("BAS_SERVER_URL")
		}
		if err := svcInstall(serverURL, *flagEnv, *flagSecret); err != nil {
			log.Fatalf("[!] service install failed: %v", err)
		}
		log.Println("[+] service installed and started")
		return
	}
	if *flagUninstall {
		if err := svcUninstall(); err != nil {
			log.Fatalf("[!] service uninstall failed: %v", err)
		}
		log.Println("[+] service uninstalled")
		return
	}
	if isWindowsService() {
		if err := svcRun(); err != nil {
			log.Fatalf("[!] service run failed: %v", err)
		}
		return
	}

	log.Printf("[*] Audspect Legacy Windows Agent v%s starting", agentVersion)
	cfg := loadConfig()
	if cfg.ServerURL == "" {
		log.Fatal("[!] BAS_SERVER_URL is not set")
	}
	id := buildIdentity()
	log.Printf("[*] identity: host=%s os=%s", id.Hostname, id.OSVersion)

	client := NewClient(cfg)
	resp, err := client.Enroll(id)
	if err != nil {
		log.Printf("[!] enrollment failed: %v -- continuing; will retry on next heartbeat", err)
	} else {
		log.Printf("[+] enrolled -- state=%s trusted=%v", resp.State, resp.Trusted)
	}

	go func() {
		ticker := time.NewTicker(heartbeatInterval)
		defer ticker.Stop()
		for range ticker.C {
			if _, err := client.SendHeartbeat(id, "idle"); err != nil {
				log.Printf("[!] heartbeat failed: %v", err)
			}
		}
	}()

	connectWS(cfg, id)
}
