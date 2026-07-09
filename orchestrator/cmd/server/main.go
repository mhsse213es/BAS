package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/config"
	"github.com/audspect/bas/internal/api"
	"github.com/audspect/bas/internal/auth"
	"github.com/audspect/bas/internal/compliance"
	"github.com/audspect/bas/internal/connector"
	"github.com/audspect/bas/internal/db"
	"github.com/audspect/bas/internal/detect"
	"github.com/audspect/bas/internal/exercise"
	exercisetracker "github.com/audspect/bas/internal/exercise/tracker"
	"github.com/audspect/bas/internal/integrity"
	"github.com/audspect/bas/internal/license"
	"github.com/audspect/bas/internal/models"
	"github.com/audspect/bas/internal/relationships"
	"github.com/audspect/bas/internal/reporting"
	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/ticketing"
	"github.com/audspect/bas/internal/verification"
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

	// ── Cryptographic subsystem ───────────────────────────────────────────
	auth.SetIterations(cfg.PBKDF2Iterations)
	if err := auth.CryptoSelfTest(); err != nil {
		log.Fatalf("[FATAL] crypto self-test: %v", err)
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
	if err := db.EnsureContentSchema(context.Background(), pool); err != nil {
		log.Fatalf("[FATAL] content schema bootstrap: %v", err)
	}
	log.Println("[+] Schema verified")

	// ── Seed ART content into Postgres (disk is the seed source, DB the runtime
	// source of truth). Idempotent — unchanged techniques are left untouched and
	// payload binaries stay on disk (only metadata is recorded).
	if tc, pc, sErr := scenario.SeedContent(context.Background(), pool,
		cfg.ARTDir, cfg.ARTPayloadDir, cfg.KEVFile, cfg.ARTContentVersion, false); sErr != nil {
		log.Printf("[!] ART content seed: %v", sErr)
	} else {
		log.Printf("[+] ART content seeded: %d techniques, %d payloads (version %q)", tc, pc, cfg.ARTContentVersion)
		// Surface which external binaries the loaded atomics reference but we don't
		// ship, so an operator knows exactly what to add/rename. Advisory only —
		// these tests skip cleanly at dispatch. Capped in the log to stay readable;
		// the full list is available via GET /api/art/content/status.
		if missing, mErr := scenario.MissingPayloads(context.Background(), pool); mErr != nil {
			log.Printf("[!] missing-payload lookup: %v", mErr)
		} else if n := len(missing); n > 0 {
			shown := missing
			suffix := ""
			if n > 15 {
				shown, suffix = missing[:15], " …"
			}
			log.Printf("[i] %d atomic payload(s) not present (tests will skip): %s%s",
				n, strings.Join(shown, ", "), suffix)
			log.Printf("    full list: GET /api/art/content/status (missingPayloads)")
		}
	}

	// EPSS enrichment — optional, seeded from FIRST EPSS CSV if provided.
	if n, sErr := scenario.SeedEPSS(context.Background(), pool, cfg.EPSSFile); sErr != nil {
		log.Printf("[!] EPSS seed: %v", sErr)
	} else if n > 0 {
		log.Printf("[+] EPSS scores seeded: %d CVE entries", n)
	}

	if err := ensureAdminUser(pool, cfg.AdminEmail, cfg.AdminPassword); err != nil {
		log.Printf("[!] admin sync: %v", err)
	}

	// ── Scenario Engine ───────────────────────────────────────────────────
	engine := scenario.NewEngine(cfg.ScenariosDir)
	if err := engine.Load(); err != nil {
		log.Printf("[!] scenario load warning: %v", err)
	}
	log.Printf("[+] Loaded %d scenarios from %s", engine.Count(), cfg.ScenariosDir)

	// ── ART Store (DB-backed — seeded above; disk was only the seed source) ──
	// Payload binaries stay on disk; the store indexes their metadata/path from
	// Postgres and ships them to the agent at dispatch. Atomics whose payload is
	// absent are skipped cleanly. Techniques come pre-parsed from art_atomic_tests.
	payloadStore, psErr := scenario.NewPayloadStoreFromDB(context.Background(), pool)
	if psErr != nil {
		log.Printf("[!] payload store: %v — payload-backed atomics will be skipped", psErr)
		payloadStore = scenario.NewPayloadStore("") // empty store → clean skips
	}
	log.Printf("[+] ART payload store: %d binaries (from Postgres)", payloadStore.Count())
	var artStore *scenario.ARTStore
	if store, artErr := scenario.NewARTStoreFromDB(context.Background(), pool, payloadStore); artErr != nil {
		log.Printf("[!] ART store: %v — ART scenarios will be unavailable", artErr)
	} else {
		artStore = store
		log.Printf("[+] ART loaded: %d techniques (from Postgres)", artStore.Count())
	}

	// ── Binary integrity manifest ─────────────────────────────────────────
	// LoadManifestVerified checks BINARIES.sha256.sig before parsing.
	// A tampered or unsigned manifest is fatal — never trust it silently.
	manifest, manifestErr := integrity.LoadManifestVerified("./agents/BINARIES.sha256")
	if manifestErr != nil {
		log.Fatalf("[FATAL] binary integrity manifest tampered or invalid: %v", manifestErr)
	}
	if manifest.Loaded() {
		log.Println("[+] Binary integrity manifest loaded and signature verified — agent hash verification enabled")
	} else {
		log.Println("[~] No binary manifest found — agent hash verification disabled")
	}

	// ── Compliance Mapper ─────────────────────────────────────────────────
	complianceMapper, cmErr := compliance.NewMapper()
	if cmErr != nil {
		log.Printf("[!] compliance mapper: %v — compliance reports unavailable", cmErr)
	} else {
		log.Printf("[+] Compliance mapper loaded (%d frameworks)", len(complianceMapper.Frameworks()))
	}

	// ── Verification Store (Detection Validation SP2) ─────────────────────
	// Independent store for analyst/API attestations + evidence. Reporting
	// consumes it read-only; the API writes to it.
	verificationStore := verification.NewStore(pool)
	log.Println("[+] Verification store ready")

	// ── CVE-ATT&CK Relationship Store ──────────────────────────────────────
	relationshipStore := relationships.NewStore(pool)
	log.Println("[+] Relationship store ready")

	// ── Reporting Engine ──────────────────────────────────────────────────
	reportingEngine := reporting.NewEngine(pool).
		WithScenarios(engine).
		WithVerifications(verificationStore)
	log.Println("[+] Reporting engine ready")

	// ── Ticketing Manager ─────────────────────────────────────────────────
	ticketingManager := ticketing.NewManager(pool)
	ticketingManager.Start(context.Background())
	log.Println("[+] Ticketing manager ready")

	// ── Threat-Intel Connector ────────────────────────────────────────────
	var mispClient *connector.MISPClient
	if cfg.MISPUrl != "" && cfg.MISPApiKey != "" {
		mispClient = connector.NewMISPClient(cfg.MISPUrl, cfg.MISPApiKey, cfg.ThreatIntelSectors, cfg.ThreatIntelRegions)
		log.Printf("[+] MISP connector configured: %s", cfg.MISPUrl)
	}
	var openctiClient *connector.OpenCTIClient
	if cfg.OpenCTIUrl != "" && cfg.OpenCTIApiKey != "" {
		openctiClient = connector.NewOpenCTIClient(cfg.OpenCTIUrl, cfg.OpenCTIApiKey, cfg.ThreatIntelSectors)
		log.Printf("[+] OpenCTI connector configured: %s", cfg.OpenCTIUrl)
	}
	gen := connector.NewGenerator(cfg.ScenariosDir)
	scheduler := connector.NewScheduler(mispClient, openctiClient, gen, engine, cfg.ThreatIntelPollHours)
	scheduler.Start()
	defer scheduler.Stop()

	// ── Exercise Engine ───────────────────────────────────────────────────
	if err := db.EnsureExerciseSchema(context.Background(), pool); err != nil {
		log.Fatalf("[FATAL] exercise schema: %v", err)
	}
	exStore := exercise.NewStore(pool)
	exChain := exercise.NewEvidenceChain(exStore)
	var smtpInj *exercise.SMTPInjector
	if cfg.SMTPHost != "" {
		smtpInj = exercise.NewSMTPInjector(exercise.SMTPConfig{
			Host:           cfg.SMTPHost,
			Port:           cfg.SMTPPort,
			Username:       cfg.SMTPUser,
			Password:       cfg.SMTPPass,
			FromAddr:       cfg.SMTPFrom,
			FromName:       cfg.SMTPFromName,
			TrackerBaseURL: cfg.PublicBaseURL,
		}, exStore)
	}
	exRegistry := exercise.NewRegistry()
	exScheduler := exercise.NewPollScheduler(5 * time.Second)
	exExecutor := exercise.NewExecutor(exStore, exChain, exRegistry, exScheduler, nil)
	exExecutor.RegisterBuiltins(smtpInj)
	exExecutor.RegisterBuiltinTriggers()
	if err := exStore.SeedBuiltinTemplates(context.Background()); err != nil {
		log.Printf("warn: seed built-in exercise templates: %v", err)
	}
	exExecutor.Start()
	exTracker := exercisetracker.New(exStore, exChain)
	log.Println("[+] Exercise engine ready")

	// ── WebSocket Hub + HTTP Router ───────────────────────────────────────
	hub := ws.NewHub()
	handler := api.New(pool, hub, engine, cfg.JWTSecret).
		WithCaldera(cfg.CalderaURL, cfg.CalderaAPIKey).
		WithART(artStore).
		WithContentSeed(cfg.ARTDir, cfg.ARTPayloadDir, cfg.KEVFile, cfg.ARTContentVersion).
		WithEPSSFile(cfg.EPSSFile).
		WithAgentSecret(cfg.AgentSecret).
		WithManifest(manifest).
		WithCompliance(complianceMapper).
		WithReporting(reportingEngine).
		WithScheduler(scheduler).
		WithTicketing(ticketingManager).
		WithLicensePath(cfg.LicensePath).
		WithExercise(exStore, exExecutor, exChain).
		WithVerificationStore(verificationStore).
		WithRelationshipStore(relationshipStore)
	router := api.Mount(handler, hub, cfg.JWTSecret, cfg.AgentSecret, StaticHandler(), exTracker)

	// ── Agent Staleness Monitor ───────────────────────────────────────────
	// Marks agents offline if no heartbeat received within 90 seconds and
	// broadcasts the change so the dashboard updates in real time.
	go runStalenessMonitor(pool, hub)

	// ── ITSM Auto-Revalidation Loop ───────────────────────────────────────
	// Every 2 minutes: checks for findings whose ITSM ticket was resolved but
	// BAS has not yet re-confirmed. Dispatches a targeted single-technique
	// posture re-run on the original agent. Results in the audit log + WS push.
	go handler.StartRevalidationLoop(context.Background())

	// ── Attack-Path Scheduler ─────────────────────────────────────────────
	// Ticks every 60 s and re-dispatches fleet-wide attack-path collection
	// when the operator-configured interval has elapsed.
	api.StartAttackPathScheduler(context.Background(), pool, hub)

	// ── Attack-Path Job Monitor ───────────────────────────────────────────
	// Every 15 s: enforces ack-window (dispatched→delivery_failed if no ACK
	// within 30 s) and expires_at (running/queued→timed_out).
	handler.StartAPJobMonitor(context.Background())

	// ── Filesystem Integrity Watcher ──────────────────────────────────────
	// Polls protected on-disk paths every 15 seconds. Any unexpected
	// modification, deletion, or creation is logged, persisted to
	// tamper_events, and broadcast to all dashboard browsers via WebSocket.
	// Builtin scenario & manifest changes also set DispatchBlocked to true.
	integrity.WatchPaths([]struct {
		Path     string
		Severity string
	}{
		{Path: "./agents/BINARIES.sha256", Severity: "critical"},
		{Path: cfg.LicensePath, Severity: "critical"},
	})
	integrity.WatchDir(cfg.ScenariosDir, "critical")
	go integrity.StartWatcher(context.Background(), pool, hub)
	log.Println("[+] Filesystem integrity watcher started")

	// ── Detection Retention ───────────────────────────────────────────────
	// Prunes raw detection alert blobs older than 30 days daily (summaries are
	// kept forever) so large BAS environments don't accumulate huge JSON blobs.
	detect.StartRetention(context.Background(), pool)

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
	// Single source of truth for the offline threshold, shared with the API's
	// read-path (effectiveAgentStatus) and dispatch-path (runIsStale) checks.
	staleAfter := api.AgentOfflineAfter
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		rows, err := pool.Query(context.Background(),
			`UPDATE agents
			    SET status = 'offline'
			  WHERE status != 'offline'
			    AND last_update < NOW() - $1::interval
			RETURNING agent_id, hostname, ip_address, os_version, username,
			          status, env_label, has_report, binary_hash, binary_trusted, last_update,
			          COALESCE(state, 'active'), enrolled_at`,
			staleAfter.String(),
		)
		if err != nil {
			log.Printf("[monitor] staleness query: %v", err)
			continue
		}
		for rows.Next() {
			var a models.Agent
			var stateStr string
			if err := rows.Scan(&a.AgentID, &a.Hostname, &a.IPAddress, &a.OSVersion,
				&a.Username, &a.Status, &a.EnvLabel, &a.HasReport,
				&a.BinaryHash, &a.BinaryTrusted, &a.LastUpdate,
				&stateStr, &a.EnrolledAt); err != nil {
				continue
			}
			a.State = models.AgentState(stateStr)
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

// ensureAdminUser runs on every startup and guarantees the primary admin user
// matches BAS_ADMIN_EMAIL / BAS_ADMIN_PASSWORD from the environment exactly.
// It uses a single atomic CTE so no race is possible between check and write:
//   - If no admin-role user exists → INSERT one.
//   - If one exists → UPDATE its username and password to match the config.
// This means setup.conf is always the source of truth; no manual DB work is
// needed after a rebuild or credential rotation.
func ensureAdminUser(pool *pgxpool.Pool, adminUsername, adminPassword string) error {
	if adminUsername == "" {
		adminUsername = "admin"
	}
	mustChange := false
	if adminPassword == "" {
		adminPassword = "ChangeMe!2024"
		mustChange = true
	}

	hash, err := auth.HashPassword(adminPassword)
	if err != nil {
		return fmt.Errorf("hash admin password: %w", err)
	}

	// Atomic upsert: find the oldest admin, update it; if none exists, insert.
	// The two branches are mutually exclusive so the UPDATE touches 0 rows when
	// the INSERT fires, and vice-versa.
	_, err = pool.Exec(context.Background(), `
		WITH existing AS (
			SELECT id FROM users WHERE role = 'admin' ORDER BY created_at ASC LIMIT 1
		),
		ins AS (
			INSERT INTO users (username, password_hash, role, is_active, must_change_pw)
			SELECT $1, $2, 'admin', true, $3
			WHERE NOT EXISTS (SELECT 1 FROM existing)
		)
		UPDATE users
		   SET username       = $1,
		       password_hash  = $2,
		       is_active      = true,
		       must_change_pw = $3
		 WHERE id IN (SELECT id FROM existing)
	`, adminUsername, hash, mustChange)
	if err != nil {
		return fmt.Errorf("ensure admin: %w", err)
	}

	log.Printf("[+] Admin credentials synced from config (username: %s)", adminUsername)
	return nil
}
