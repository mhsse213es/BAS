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
	"github.com/audspect/bas/internal/integrity"
	"github.com/audspect/bas/internal/license"
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

	// ── License Check ─────────────────────────────────────────────────────
	if err := license.Check(cfg.LicensePath); err != nil {
		log.Fatalf("[FATAL] %v", err)
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

	// ── ART Store (bundled atomics — resolved locally, zero endpoint footprint) ──
	var artStore *scenario.ARTStore
	if cfg.ARTDir != "" {
		var artErr error
		artStore, artErr = scenario.NewARTStore(cfg.ARTDir)
		if artErr != nil {
			log.Printf("[!] ART store: %v — ART scenarios will be unavailable", artErr)
		} else {
			log.Printf("[+] ART loaded: %d techniques from %s", artStore.Count(), cfg.ARTDir)
		}
	}

	// ── Binary integrity manifest ─────────────────────────────────────────
	manifest := integrity.LoadManifest("./agents/BINARIES.sha256")
	if manifest.Loaded() {
		log.Println("[+] Binary integrity manifest loaded — agent hash verification enabled")
	} else {
		log.Println("[~] No binary manifest found — agent hash verification disabled")
	}

	// ── WebSocket Hub + HTTP Router ───────────────────────────────────────
	hub := ws.NewHub()
	handler := api.New(pool, hub, engine, cfg.JWTSecret).
		WithCaldera(cfg.CalderaURL, cfg.CalderaAPIKey).
		WithART(artStore).
		WithAgentSecret(cfg.AgentSecret).
		WithManifest(manifest)
	router := api.Mount(handler, hub, cfg.JWTSecret, cfg.AgentSecret)

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
			          status, env_label, has_report, binary_hash, binary_trusted, last_update`,
			staleAfter.String(),
		)
		if err != nil {
			log.Printf("[monitor] staleness query: %v", err)
			continue
		}
		for rows.Next() {
			var a models.Agent
			if err := rows.Scan(&a.AgentID, &a.Hostname, &a.IPAddress, &a.OSVersion,
				&a.Username, &a.Status, &a.EnvLabel, &a.HasReport,
				&a.BinaryHash, &a.BinaryTrusted, &a.LastUpdate); err != nil {
				continue
			}
			log.Printf("[monitor] agent %s marked offline (no heartbeat for >90s)", a.AgentID)
			hub.BroadcastBrowsers(models.WSMessage{
				Type:    models.MsgAgentUpdate,
				AgentID: a.AgentID,
				Data:    a,
			})

			// Mark any runs that are still "running" for this agent as partial.
			// This handles hard kills where the agent never got to submit results.
			stuckRows, err := pool.Query(context.Background(),
				`UPDATE scenario_runs
				 SET status = 'partial', completed_at = NOW()
				 WHERE agent_id = $1 AND status = 'running'
				 RETURNING id, scenario_id`,
				a.AgentID,
			)
			if err == nil {
				for stuckRows.Next() {
					var runID, scenID string
					stuckRows.Scan(&runID, &scenID)
					log.Printf("[monitor] run %s marked partial (agent %s went offline)", runID, a.AgentID)
					hub.BroadcastBrowsers(models.WSMessage{
						Type:    models.MsgScenarioResult,
						AgentID: a.AgentID,
						Data: map[string]interface{}{
							"runId":      runID,
							"scenarioId": scenID,
							"agentId":    a.AgentID,
							"status":     "partial",
						},
					})
				}
				stuckRows.Close()
			}
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
	log.Println("[+] Default admin seeded (username: admin) — change the password immediately via Settings → Users")
	return nil
}
