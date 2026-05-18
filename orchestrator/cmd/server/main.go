package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/bcrypt"

	"github.com/audspect/bas/config"
	"github.com/audspect/bas/internal/api"
	"github.com/audspect/bas/internal/db"
	"github.com/audspect/bas/internal/models"
	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/ws"
)

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	cfgPath := "config.json"
	if len(os.Args) > 1 {
		cfgPath = os.Args[1]
	}

	cfg, err := config.Load(cfgPath)
	if err != nil {
		log.Fatalf("[FATAL] config: %v", err)
	}

	// ── Database ──────────────────────────────────────────────────────────
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	pool, err := db.Connect(ctx, cfg.DatabaseURL)
	cancel()
	if err != nil {
		log.Fatalf("[FATAL] db connect: %v", err)
	}
	defer pool.Close()
	log.Println("[+] PostgreSQL connected")

	if err := db.EnsureSchema(context.Background(), pool); err != nil {
		log.Fatalf("[FATAL] schema bootstrap: %v", err)
	}
	log.Println("[+] Schema verified")

	if err := seedDefaultAdmin(pool); err != nil {
		log.Printf("[!] admin seed: %v", err)
	}

	// ── Scenario Engine ───────────────────────────────────────────────────
	engine := scenario.NewEngine(cfg.ScenariosDir)
	if err := engine.Load(); err != nil {
		log.Printf("[!] scenario load warning: %v", err)
	}
	log.Printf("[+] Loaded %d scenarios from %s", engine.Count(), cfg.ScenariosDir)

	// ── WebSocket Hub + HTTP Router ───────────────────────────────────────
	hub := ws.NewHub()
	handler := api.New(pool, hub, engine, cfg.JWTSecret).
		WithCaldera(cfg.CalderaURL, cfg.CalderaAPIKey)
	router := api.Mount(handler, hub, cfg.JWTSecret)

	// ── Agent Staleness Monitor ───────────────────────────────────────────
	// Marks agents offline if no heartbeat received within 90 seconds and
	// broadcasts the change so the dashboard updates in real time.
	go runStalenessMonitor(pool, hub)

	srv := &http.Server{
		Addr:         fmt.Sprintf(":%d", cfg.HTTPPort),
		Handler:      router,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 90 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	go func() {
		log.Printf("[*] BAS Orchestrator listening on :%d", cfg.HTTPPort)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("[FATAL] listen: %v", err)
		}
	}()

	// ── Graceful Shutdown ─────────────────────────────────────────────────
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Println("[*] Shutting down gracefully...")
	shutCtx, shutCancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer shutCancel()
	if err := srv.Shutdown(shutCtx); err != nil {
		log.Printf("[!] shutdown error: %v", err)
	}
	log.Println("[*] Server stopped.")
}

// runStalenessMonitor ticks every 30s and marks agents offline when their
// last heartbeat is older than 90 seconds. Broadcasts each change so the
// dashboard reflects the real status without a manual refresh.
func runStalenessMonitor(pool *pgxpool.Pool, hub *ws.Hub) {
	const staleAfter = 90 * time.Second
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		rows, err := pool.Query(context.Background(),
			`UPDATE agents
			    SET status = 'offline'
			  WHERE status != 'offline'
			    AND last_update < NOW() - $1::interval
			RETURNING agent_id, hostname, ip_address, os_version, username,
			          status, env_label, has_report, last_update`,
			staleAfter.String(),
		)
		if err != nil {
			log.Printf("[monitor] staleness query: %v", err)
			continue
		}
		for rows.Next() {
			var a models.Agent
			if err := rows.Scan(&a.AgentID, &a.Hostname, &a.IPAddress, &a.OSVersion,
				&a.Username, &a.Status, &a.EnvLabel, &a.HasReport, &a.LastUpdate); err != nil {
				continue
			}
			log.Printf("[monitor] agent %s marked offline (no heartbeat for >90s)", a.AgentID)
			hub.BroadcastBrowsers(models.WSMessage{
				Type:    models.MsgAgentUpdate,
				AgentID: a.AgentID,
				Data:    a,
			})
		}
		rows.Close()
	}
}

// seedDefaultAdmin creates admin/ChangeMe!2024 on first run if no users exist.
// The operator MUST change this password immediately after deployment.
func seedDefaultAdmin(pool *pgxpool.Pool) error {
	var count int
	err := pool.QueryRow(context.Background(), `SELECT COUNT(*) FROM users`).Scan(&count)
	if err != nil || count > 0 {
		return err
	}

	hash, err := bcrypt.GenerateFromPassword([]byte("ChangeMe!2024"), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("bcrypt: %w", err)
	}
	_, err = pool.Exec(context.Background(),
		`INSERT INTO users (username, password_hash, role) VALUES ('admin', $1, 'admin')`,
		string(hash),
	)
	if err != nil {
		return fmt.Errorf("insert admin: %w", err)
	}
	log.Println("[+] Default admin created — username: admin  password: ChangeMe!2024  ← CHANGE THIS NOW")
	return nil
}
