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
	handler := api.New(pool, hub, engine, cfg.JWTSecret)
	router := api.Mount(handler, hub, cfg.JWTSecret)

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
