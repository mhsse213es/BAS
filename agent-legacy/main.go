package main

import (
	"log"
	"time"
)

const heartbeatInterval = 30 * time.Second

func main() {
	log.SetFlags(log.Ldate | log.Ltime | log.Lmsgprefix)
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
