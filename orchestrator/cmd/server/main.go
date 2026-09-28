package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/config"
	"github.com/audspect/bas/internal/api"
	"github.com/audspect/bas/internal/auth"
	"github.com/audspect/bas/internal/observability"
	"github.com/audspect/bas/internal/compliance"
	"github.com/audspect/bas/internal/connector"
	"github.com/audspect/bas/internal/controlhealth"
	"github.com/audspect/bas/internal/correlation"
	"github.com/audspect/bas/internal/db"
	"github.com/audspect/bas/internal/detect"
	"github.com/audspect/bas/internal/dnssink"
	"github.com/audspect/bas/internal/emsweep"
	"github.com/audspect/bas/internal/endpointrisk"
	"github.com/audspect/bas/internal/exercise"
	exercisetracker "github.com/audspect/bas/internal/exercise/tracker"
	"github.com/audspect/bas/internal/initiatives"
	"github.com/audspect/bas/internal/integrity"
	"github.com/audspect/bas/internal/ioc"
	"github.com/audspect/bas/internal/iocregistry"
	"github.com/audspect/bas/internal/jobs"
	"github.com/audspect/bas/internal/license"
	"github.com/audspect/bas/internal/models"
	"github.com/audspect/bas/internal/notifications"
	"github.com/audspect/bas/internal/openaev"
	"github.com/audspect/bas/internal/pki"
	"github.com/audspect/bas/internal/relationships"
	"github.com/audspect/bas/internal/remediation"
	"github.com/audspect/bas/internal/reporting"
	"github.com/audspect/bas/internal/rulelib"
	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/search"
	"github.com/audspect/bas/internal/sftpsink"
	"github.com/audspect/bas/internal/smtpsink"
	"github.com/audspect/bas/internal/taxii"
	"github.com/audspect/bas/internal/threatpriority"
	"github.com/audspect/bas/internal/ticketing"
	"github.com/audspect/bas/internal/verification"
	"github.com/audspect/bas/internal/verifysync"
	"github.com/audspect/bas/internal/vexsweep"
	"github.com/audspect/bas/internal/ws"
)

// Version is the running build's version, baked in at build time via
// packaging/build.sh's `-X main.Version=${VERSION}` ldflag (VERSION is
// derived from the nearest git tag). Left at "dev" for local/unpackaged
// builds. Propagated to internal/api.Version in main() so /ready can
// report it to the frontend.
var Version = "dev"

// runHealthcheck is invoked as `orchestrator --healthcheck` by Docker's
// container HEALTHCHECK (packaging/compose/docker-compose.yml). Probes the
// enrollment listener (:9444), not the mTLS listener (:9443) -- 9443
// requires a client certificate, which this in-process self-check has no
// way to present, so a probe against it would always report unhealthy
// regardless of real app health. GET /health on 9444 is unauthenticated by
// design (api.MountEnrollment). The image is gcr.io/distroless/
// static-debian12 -- no shell, no wget/curl -- so this must be the binary
// checking itself in-process via an argv flag (array-form CMD, no shell
// involved). Reads HTTP_PORT_ENROLL directly rather than going through
// config.Load(), since that requires DATABASE_URL/JWT_SECRET this
// short-lived self-check has no need for. Returns a process exit code (0 =
// healthy) -- that exit code is the only signal Docker's HEALTHCHECK reads.
func runHealthcheck() int {
	port := 9444
	if v := os.Getenv("HTTP_PORT_ENROLL"); v != "" {
		fmt.Sscanf(v, "%d", &port)
	}
	client := &http.Client{
		Timeout: 3 * time.Second,
		Transport: &http.Transport{
			// The enrollment listener's server identity is the deployment
			// CA's own self-signed certificate (see ca.TLSCertificate()) --
			// this is a loopback liveness probe, not a security boundary,
			// so skipping verification here is correct, not a shortcut.
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
	resp, err := client.Get(fmt.Sprintf("https://127.0.0.1:%d/health", port))
	if err != nil {
		return 1
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 1
	}
	return 0
}

// resolveDashboardTLSCert picks the certificate the dashboard listener
// presents: an operator-supplied one (cfg.DashboardTLSCertPath/KeyPath --
// install.sh's BAS_TLS/TLS_CERT/TLS_KEY option) when both are set, or
// fallback (the deployment CA's own certificate, same as the mTLS and
// enrollment listeners use) otherwise. Extracted as its own function --
// rather than left inline in main() -- specifically so this decision is
// unit-testable: BAS_TLS=false (fallback) is the default for every
// existing and new install, so its behavior needs direct test coverage,
// not just a read-through of main()'s startup sequence.
func resolveDashboardTLSCert(cfg config.Config, fallback tls.Certificate) (tls.Certificate, error) {
	if cfg.DashboardTLSCertPath == "" || cfg.DashboardTLSKeyPath == "" {
		return fallback, nil
	}
	return tls.LoadX509KeyPair(cfg.DashboardTLSCertPath, cfg.DashboardTLSKeyPath)
}

func main() {
	if len(os.Args) > 1 && os.Args[1] == "--healthcheck" {
		os.Exit(runHealthcheck())
	}

	log.SetFlags(log.LstdFlags | log.Lshortfile)
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, nil)))
	api.Version = Version

	cfgPath := "config.json"
	if len(os.Args) > 1 {
		cfgPath = os.Args[1]
	}

	cfg, err := config.Load(cfgPath)
	if err != nil {
		log.Fatalf("[FATAL] config: %v", err)
	}
	// Resolves to cfg.ScenariosDir unchanged when it already exists (always
	// true in Docker/prod, where SCENARIOS_DIR is set explicitly). Falls back
	// to a sibling "../scenarios" for a bare `go run ./cmd/server` launched
	// from orchestrator/, where the default CWD-relative "scenarios" doesn't
	// exist. See resolveScenariosDir in static.go.
	cfg.ScenariosDir = resolveScenariosDir(cfg.ScenariosDir)

	// ── Cryptographic subsystem ───────────────────────────────────────────
	auth.SetIterations(cfg.PBKDF2Iterations)
	if err := auth.CryptoSelfTest(); err != nil {
		log.Fatalf("[FATAL] crypto self-test: %v", err)
	}

	// ── License Check ─────────────────────────────────────────────────────
	if err := license.Check(cfg.LicensePath); err != nil {
		log.Fatalf("[FATAL] %v", err)
	}
	if license.PublicKeyPEM == "KEYGEN_REQUIRED" {
		// Dev-mode bypass, mirroring Check()'s own condition above — no
		// bas.lic is expected to exist yet, so skip Get/Evaluate entirely
		// rather than fatal on a file that was never meant to be there.
		license.SetInitial(license.Info{State: license.StateValid})
	} else {
		lic, licErr := license.Get(cfg.LicensePath)
		if licErr != nil {
			log.Fatalf("[FATAL] %v", licErr) // Check() just verified this file parses; only reachable on a race with file deletion
		}
		initialLicenseInfo, licErr := license.Evaluate(lic, time.Now().UTC())
		if licErr != nil {
			log.Fatalf("[FATAL] %v", licErr)
		}
		license.SetInitial(initialLicenseInfo)
		switch initialLicenseInfo.State {
		case license.StateLocked:
			log.Printf("[license] LOCKED — grace period expired on %s. Serving lockout-only mode.", initialLicenseInfo.LockoutAt.Format(time.RFC3339))
		case license.StateGrace:
			log.Printf("[license] WARNING: in grace period — %d day(s) remaining before lockout on %s", initialLicenseInfo.DaysRemaining, initialLicenseInfo.LockoutAt.Format(time.RFC3339))
		}
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
	if err := db.EnsureIOCSchema(context.Background(), pool); err != nil {
		log.Fatalf("[FATAL] ioc schema bootstrap: %v", err)
	}
	if err := db.EnsureIOCEnrichmentSchema(context.Background(), pool); err != nil {
		log.Fatalf("[FATAL] ioc enrichment schema bootstrap: %v", err)
	}
	if err := db.EnsureAgentGroupSchema(context.Background(), pool); err != nil {
		log.Fatalf("[FATAL] agent group schema bootstrap: %v", err)
	}
	if err := db.EnsureAgentUninstallSchema(context.Background(), pool); err != nil {
		log.Fatalf("[FATAL] agent uninstall schema bootstrap: %v", err)
	}
	log.Println("[+] Schema verified")

	// ── DB role hardening (opt-in) ────────────────────────────────────────
	// Demote the runtime role to NOSUPERUSER/NOBYPASSRLS so RLS can enforce.
	// No-op unless BAS_DB_BREAKGLASS_PASSWORD is set. MUST run after all schema
	// DDL above — it drops this session's superuser privileges.
	if err := db.HardenRuntimeRole(context.Background(), pool, cfg.DBBreakGlassPassword); err != nil {
		log.Fatalf("[FATAL] db role hardening: %v", err)
	}

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

	// ── Caldera ability store (variant-testing base-command source) ─────────
	// Loaded once at startup like artStore above -- an empty store when
	// CALDERA_URL is unset or unreachable, never fatal (see NewCalderaStore).
	calderaStore := scenario.NewCalderaStore(cfg.CalderaURL, cfg.CalderaAPIKey)

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

	// ── Control Health Mapper ───────────────────────────────────────────────
	controlHealthMapper, chErr := controlhealth.NewMapper()
	if chErr != nil {
		log.Printf("[!] control health mapper: %v — control health summary unavailable", chErr)
	} else {
		log.Printf("[+] Control health mapper loaded (%d categories)", len(controlHealthMapper.Categories()))
	}

	// ── Endpoint Risk Taxonomy (Security Config & Identity Posture) ───────
	endpointRiskTaxonomy, erErr := endpointrisk.NewTaxonomy()
	if erErr != nil {
		log.Printf("[!] endpoint risk taxonomy: %v — Security Configuration/Identity categories unavailable", erErr)
	} else {
		log.Printf("[+] Endpoint risk taxonomy loaded")
	}

	// ── Application Risk EOL/High-Risk Software Catalog ────────────────────
	eolCatalog, eolErr := endpointrisk.NewCatalog()
	if eolErr != nil {
		log.Printf("[!] EOL software catalog: %v — Application Risk category unavailable", eolErr)
	} else {
		log.Printf("[+] EOL software catalog loaded")
	}

	// ── Endpoint Remediation Catalog ────────────────────────────────────────
	remediationCatalog, remErr := remediation.NewCatalog()
	if remErr != nil {
		log.Printf("[!] remediation catalog: %v — one-click remediation unavailable", remErr)
	} else {
		log.Printf("[+] Remediation catalog loaded")
	}

	// ── Verification Store (Detection Validation SP2) ─────────────────────
	// Independent store for analyst/API attestations + evidence. Reporting
	// consumes it read-only; the API writes to it.
	verificationStore := verification.NewStore(pool)
	log.Println("[+] Verification store ready")

	// ── Automatic Verdict Persistence (Purple Team Phase A0) ───────────────
	// Automatic (on-host) verification results were never persisted to
	// verification_history — only manual/API attestations were. This poller
	// closes that gap so Store.CurrentForRun/History are complete for every
	// consumer, not just human-reviewed expectations.
	verifyJob := verifysync.NewJob(pool, verificationStore, engine)
	verifySyncScheduler := exercise.NewPollScheduler(5 * time.Minute)
	verifySyncScheduler.Start(verifyJob.Tick)
	log.Println("[+] Automatic verdict persistence poller started")

	// ── CVE-ATT&CK Relationship Store ──────────────────────────────────────
	relationshipStore := relationships.NewStore(pool)
	log.Println("[+] Relationship store ready")

	// ── Detection Rule Library (SP2) ────────────────────────────────────────
	// Constructed once and shared: the API serves it directly (rulelib_handlers.go)
	// and the reporting engine consumes it read-only for Attack Path Detection
	// Coverage (SP3).
	rulesEngine := rulelib.NewEngine()
	log.Println("[+] Rule Library ready")

	// ── Reporting Engine ──────────────────────────────────────────────────
	reportingEngine := reporting.NewEngine(pool).
		WithScenarios(engine).
		WithVerifications(verificationStore).
		WithRuleLibrary(rulesEngine).
		WithSectorRegion(cfg.ThreatIntelSectors, cfg.ThreatIntelRegions)
	log.Println("[+] Reporting engine ready")

	// ── Ticketing Manager ─────────────────────────────────────────────────
	ticketingManager := ticketing.NewManager(pool)
	ticketingManager.Start(context.Background())
	log.Println("[+] Ticketing manager ready")

	// ── Threat-Intel Connector (layered: air-gapped bundle floor + live overlay) ─
	// threat_intel_config is now the authoritative source for MISP/OpenCTI/OTX
	// (DB-backed, UI-editable -- see docs/superpowers/specs/2026-08-10-threat-intel-connector-config-design.md).
	// SeedFromEnv migrates any already-set .env values into the DB exactly
	// once, on the first boot after this change ships, so an existing
	// deployment (e.g. one already running with MISP_URL/MISP_API_KEY set)
	// keeps working with zero manual action.
	if err := connector.SeedFromEnv(context.Background(), pool, connector.SeedConfig{
		MISPUrl: cfg.MISPUrl, MISPApiKey: cfg.MISPApiKey,
		OpenCTIUrl: cfg.OpenCTIUrl, OpenCTIApiKey: cfg.OpenCTIApiKey,
		OTXAPIKey: cfg.OTXAPIKey,
	}); err != nil {
		log.Printf("[!] threat-intel config seed warning: %v", err)
	}
	tiSources, err := connector.LoadSourcesFromDB(context.Background(), pool, cfg.ThreatIntelSectors, cfg.ThreatIntelRegions)
	if err != nil {
		log.Printf("[!] threat-intel config load warning: %v", err)
	}
	for _, src := range tiSources {
		log.Printf("[+] %s connector configured", src.Name())
	}
	gen := connector.NewGenerator(cfg.ScenariosDir, cfg.ThreatIntelSectors, cfg.ThreatIntelRegions, engine.Profiles())
	priorityEngine := threatpriority.NewEngine(pool, engine, cfg.ThreatIntelSectors, cfg.ThreatIntelRegions)
	correlationEngine := correlation.NewEngine(pool, engine)
	scheduler := connector.NewScheduler(tiSources, gen, engine, cfg.ThreatIntelPollHours, pool, priorityEngine)
	tiActivitySources, err := connector.LoadActivitySourcesFromDB(context.Background(), pool)
	if err != nil {
		log.Printf("[!] threat-intel activity source load warning: %v", err)
	}
	scheduler.WithActivitySources(tiActivitySources)
	// Air-gapped bundle: the scheduler now owns detecting ti-bundle.json
	// itself (checkBundleSource, re-checked on every sync) instead of only
	// once here at boot -- a bundle dropped in later (or removed) takes
	// effect on the next sync tick, no restart needed. WithBundleDir must
	// be set before Start() since Start()'s "anything to do?" guard reads
	// it too (a bundle-only deployment with zero live connectors still
	// needs its sync loop running to ever notice the file appear).
	scheduler.WithBundleDir(cfg.TIBundleDir, integrity.VerifyScenarioFile)
	scheduler.Start()
	defer scheduler.Stop()

	// Global Search Phase 1 -- maintained multi-entity search index.
	// Reindex once synchronously at startup (a ticker-based scheduler only
	// fires after its first interval elapses, which would otherwise leave
	// search_documents empty for the first tick) then keep it fresh on a
	// 60s timer, reusing the same exercise.PollScheduler abstraction the
	// OpenAEV connector below already uses rather than a new one.
	if err := search.ReindexAll(context.Background(), pool, engine, rulesEngine, complianceMapper); err != nil {
		log.Printf("[!] search: initial reindex failed: %v", err)
	}
	searchScheduler := exercise.NewPollScheduler(60 * time.Second)
	searchScheduler.Start(func(ctx context.Context) {
		if err := search.ReindexAll(ctx, pool, engine, rulesEngine, complianceMapper); err != nil {
			log.Printf("[!] search: reindex failed: %v", err)
		}
	})
	defer searchScheduler.Stop()

	// ── OpenAEV Connector ─────────────────────────────────────────────────
	// connector.Scheduler above is hardcoded to MISP/OpenCTI/Generator — not
	// reusable here. exercise.PollScheduler is the actual generic ticker
	// abstraction in this codebase, so this reuses that instead. Ticks hourly
	// (fixed) but the job itself re-reads poll_interval_hours from
	// openaev_config each tick and no-ops if not due yet — this way an Admin
	// UI change to the interval takes effect without a server restart.
	openaevScheduler := exercise.NewPollScheduler(1 * time.Hour)
	openaevScheduler.Start(func(ctx context.Context) {
		var baseURL, token string
		var enabled bool
		var pollHours int
		var lastSyncAt *time.Time
		if err := pool.QueryRow(ctx,
			`SELECT base_url, bearer_token, enabled, poll_interval_hours, last_sync_at FROM openaev_config WHERE id = 1`,
		).Scan(&baseURL, &token, &enabled, &pollHours, &lastSyncAt); err != nil || !enabled {
			return // not configured / disabled — no-op, not an error
		}
		if lastSyncAt != nil && time.Since(*lastSyncAt) < time.Duration(pollHours)*time.Hour {
			return // not due yet
		}
		store := openaev.NewSQLStore(pool)
		importer := openaev.NewImporter(store)
		provider := openaev.NewCompositeProvider(
			openaev.NewRESTProvider(baseURL, token),
			openaev.NewExerciseRESTProvider(baseURL, token),
		)
		result, syncErr := importer.SyncAll(ctx, provider)
		status := "ok"
		lastErr := ""
		created, updated, skipped, errored := 0, 0, 0, 0
		if syncErr != nil {
			status = "error"
			lastErr = syncErr.Error()
		} else {
			created, updated, skipped, errored = result.Created, result.Updated, result.Skipped, result.Errored
		}
		pool.Exec(ctx,
			`UPDATE openaev_config SET last_sync_at = NOW(), last_sync_status = $1, last_error = $2,
			   last_sync_created = $3, last_sync_updated = $4, last_sync_skipped = $5, last_sync_errored = $6
			 WHERE id = 1`,
			status, lastErr, created, updated, skipped, errored)
		log.Printf("[openaev] sync: created=%d updated=%d skipped=%d errored=%d", created, updated, skipped, errored)
	})
	defer openaevScheduler.Stop()

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
	var smsInj *exercise.SMSInjector
	if cfg.SMSGatewayURL != "" {
		smsInj = exercise.NewSMSInjector(exercise.SMSGatewayConfig{
			URL:       cfg.SMSGatewayURL,
			AuthToken: cfg.SMSGatewayToken,
			From:      cfg.SMSGatewayFrom,
		})
	}
	var slackInj *exercise.SlackInjector
	if cfg.SlackWebhookURL != "" {
		slackInj = exercise.NewSlackInjector(cfg.SlackWebhookURL)
	}
	var teamsInj *exercise.TeamsInjector
	if cfg.TeamsWebhookURL != "" {
		teamsInj = exercise.NewTeamsInjector(cfg.TeamsWebhookURL)
	}
	exRegistry := exercise.NewRegistry()
	exMetrics := observability.NewMetricsRegistry()
	exScheduler := exercise.NewPollScheduler(5 * time.Second).WithMetrics(exMetrics)
	exExecutor := exercise.NewExecutor(exStore, exChain, exRegistry, exScheduler, nil).WithMetrics(exMetrics)
	exExecutor.WithVerification(verificationStore)
	exExecutor.RegisterBuiltins(smtpInj, smsInj, slackInj, teamsInj)
	exExecutor.RegisterBuiltinTriggers()
	if err := exStore.SeedBuiltinTemplates(context.Background()); err != nil {
		log.Printf("warn: seed built-in exercise templates: %v", err)
	}
	exExecutor.Start()
	exTracker := exercisetracker.New(exStore, exChain)
	log.Println("[+] Exercise engine ready")

	// ── WebSocket Hub + HTTP Router ───────────────────────────────────────
	var iocProvider ioc.Provider
	var otxAPIKey string
	if err := pool.QueryRow(context.Background(),
		`SELECT api_key FROM threat_intel_config WHERE connector='otx' AND enabled=true`,
	).Scan(&otxAPIKey); err != nil {
		otxAPIKey = "" // no row, or not enabled -- same as OTX_API_KEY unset before this change
	}
	if otxAPIKey != "" {
		var err error
		iocProvider, err = ioc.NewProvider(ioc.Config{Provider: "otx", APIKey: otxAPIKey})
		if err != nil {
			log.Printf("[!] ioc provider init warning: %v", err)
		} else {
			log.Println("[+] IOC threat-intel provider ready (OTX)")
			reportingEngine.WithThreatIntelProvider(iocProvider.Name())
		}
	}

	// Full Variant Sweep — server-owned orchestration (survives reloads/
	// browser crashes). Ticks every 5s, matching the Exercise engine's own
	// cadence, since variant runs take real wall-clock time (agent
	// execution + result submission) -- no need for tighter polling.
	vexSweepStore := vexsweep.NewStore(pool)
	vexSweepScheduler := exercise.NewPollScheduler(5 * time.Second)
	vexSweepDispatcher := vexsweep.NewDispatcher(vexSweepStore, func(ctx context.Context, variantRunID string) (string, error) {
		var status string
		err := pool.QueryRow(ctx, `SELECT status FROM variant_runs WHERE id = $1`, variantRunID).Scan(&status)
		return status, err
	})

	// Endpoint Mastery Full Sweep — same server-owned orchestration pattern
	// as Full Variant Sweep, ticking every 5s.
	emSweepStore := emsweep.NewStore(pool)
	emSweepScheduler := exercise.NewPollScheduler(5 * time.Second)
	emSweepDispatcher := emsweep.NewDispatcher(emSweepStore, func(ctx context.Context, scenarioRunID string) (string, error) {
		var status string
		err := pool.QueryRow(ctx, `SELECT status FROM scenario_runs WHERE id = $1`, scenarioRunID).Scan(&status)
		return status, err
	})

	// Generic TAXII 2.1 connector -- deliberately its own Manager, not
	// wired into the connector.Scheduler above (Phase 1 has no ThreatActor
	// output; see docs/superpowers/specs/2026-08-13-taxii-connector-phase1-design.md).
	taxiiStore := taxii.NewStore(pool)
	taxiiManager := taxii.NewManager(pool, taxiiStore)

	// Fleet Job Engine -- generic Job/JobTarget infrastructure. Ticks every
	// 5s, same cadence as vexSweepScheduler. internal/jobs knows nothing
	// about remediation; WithJobsDispatcher (below) wires in the one V1
	// consumer, batch remediation.
	jobsStore := jobs.NewStore(pool)
	jobsDispatcher := jobs.NewDispatcher(jobsStore)
	jobsScheduler := exercise.NewPollScheduler(5 * time.Second)

	// Phase 7 -- Job-Event Notifications. No separate ticker: events are
	// emitted synchronously from jobsDispatcher.Tick() and CancelJob via
	// the NotifyFn hook wired in WithJobsDispatcher/WithNotifications below.
	notificationsStore := notifications.NewStore(pool)

	// Initiative layer -- groups related Jobs (possibly of different types)
	// into one auditable security initiative. No ticker of its own; it's
	// purely a relationship/aggregation layer over the Job Engine above.
	initiativesStore := initiatives.NewStore(pool)

	hub := ws.NewHub()
	licenseMonitorCtx, licenseMonitorCancel := context.WithCancel(context.Background())
	defer licenseMonitorCancel()
	license.StartMonitor(licenseMonitorCtx, cfg.LicensePath, 5*time.Minute, func() {
		hub.CloseAllAgentConnections()
	})
	ca, err := pki.LoadOrGenerateCA(cfg.PKIDir)
	if err != nil {
		log.Fatalf("[FATAL] load/generate deployment CA: %v", err)
	}

	handler := api.New(pool, hub, engine, cfg.JWTSecret).
		WithCaldera(cfg.CalderaURL, cfg.CalderaAPIKey).
		WithART(artStore).
		WithCalderaStore(calderaStore).
		WithContentSeed(cfg.ARTDir, cfg.ARTPayloadDir, cfg.KEVFile, cfg.ARTContentVersion).
		WithEPSSFile(cfg.EPSSFile).
		WithAgentSecret(cfg.AgentSecret).
		WithPKI(ca).
		WithMetricsToken(cfg.MetricsToken).
		WithMetrics(exMetrics).
		WithManifest(manifest).
		WithCompliance(complianceMapper).
		WithControlHealth(controlHealthMapper).
		WithEndpointRiskTaxonomy(endpointRiskTaxonomy).
		WithEOLCatalog(eolCatalog).
		WithRemediationCatalog(remediationCatalog).
		WithJobsDispatcher(jobsStore, jobsDispatcher).
		WithInitiatives(initiativesStore).
		WithNotifications(notificationsStore).
		WithReporting(reportingEngine).
		WithScheduler(scheduler).
		WithThreatPriority(priorityEngine).
		WithCorrelation(correlationEngine).
		WithTicketing(ticketingManager).
		WithLicensePath(cfg.LicensePath).
		WithPublicBaseURL(cfg.PublicBaseURL).
		WithExercise(exStore, exExecutor, exChain).
		WithVerificationStore(verificationStore).
		WithRelationshipStore(relationshipStore).
		WithRuleLibrary(rulesEngine).
		WithVexSweep(vexSweepStore, vexSweepDispatcher).
		WithEMSweep(emSweepStore, emSweepDispatcher).
		WithTAXII(taxiiStore, taxiiManager).
		WithIOCProvider(iocProvider)

	vexSweepScheduler.Start(func(ctx context.Context) {
		if err := vexSweepDispatcher.Tick(ctx); err != nil {
			log.Printf("[vexsweep] tick: %v", err)
		}
	})
	defer vexSweepScheduler.Stop()

	emSweepScheduler.Start(func(ctx context.Context) {
		if err := emSweepDispatcher.Tick(ctx); err != nil {
			log.Printf("[emsweep] tick: %v", err)
		}
	})
	defer emSweepScheduler.Stop()

	// Never-started run watchdog — see ReapNeverStartedRuns for why this is
	// needed: SendToAgent (ws.Hub) reports success once a message is
	// queued, not once it's actually delivered, so a large dispatch that
	// fails mid-write can leave a run "running" at 0-of-0 forever with
	// nothing to surface the failure. 30s tick is generous against the 60s
	// guard -- catches a stuck run within one, at most two, ticks.
	dispatchWatchdogScheduler := exercise.NewPollScheduler(30 * time.Second)
	dispatchWatchdogScheduler.Start(func(ctx context.Context) {
		if err := handler.ReapNeverStartedRuns(ctx); err != nil {
			log.Printf("[dispatch] never-started watchdog: %v", err)
		}
		// Runs the same tick, independently -- one failing must not skip
		// the other. See ReapAbandonedRuns for why this exists: an agent
		// that never reconnects at all (vs. a brief blip its own
		// disconnectGracePeriod watchdog already self-heals) would
		// otherwise leave its run "Running" until the unrelated, purely
		// reactive 2h staleRunGuard happens to fire.
		if err := handler.ReapAbandonedRuns(ctx); err != nil {
			log.Printf("[dispatch] abandoned-run watchdog: %v", err)
		}
		// Runs the same tick too -- the run-level wall-clock budget
		// (staleRunGuard, 2h). Previously enforced only reactively at a
		// new dispatch to the same agent; this makes it proactive so a
		// run wedged on a still-reachable agent doesn't sit "running"
		// forever. See ReapStaleRuns.
		if err := handler.ReapStaleRuns(ctx); err != nil {
			log.Printf("[dispatch] stale-run watchdog: %v", err)
		}
	})
	defer dispatchWatchdogScheduler.Stop()

	if err := taxiiManager.Start(context.Background()); err != nil {
		log.Printf("[taxii] manager start: %v", err)
	}
	defer taxiiManager.Stop()

	jobsScheduler.Start(func(ctx context.Context) {
		if err := jobsDispatcher.Tick(ctx); err != nil {
			log.Printf("[jobs] tick: %v", err)
		}
	})
	defer jobsScheduler.Stop()

	slaScheduler := exercise.NewPollScheduler(5 * time.Minute)
	slaScheduler.Start(func(ctx context.Context) {
		if err := handler.TickSLABreaches(ctx); err != nil {
			log.Printf("[sla] tick: %v", err)
		}
	})
	defer slaScheduler.Stop()

	rateLimitPerMin := 0
	if cfg.RateLimitEnabled {
		rateLimitPerMin = cfg.RateLimitPerMin
	}
	router := api.Mount(handler, hub, cfg.JWTSecret, cfg.AgentSecret, StaticHandler(), rateLimitPerMin, cfg.RateLimitBurst, exTracker)

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

	// ── Dashboard Snapshot Scheduler ──────────────────────────────────────
	// Snapshots fleet-wide risk/exposure/detection-coverage into
	// dashboard_snapshots once a day, powering the Executive Dashboard tab's
	// trend charts.
	api.StartDashboardScheduler(context.Background(), pool)

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
		// The manifest's signature. Without it, deleting the .sig would go
		// unnoticed while the orchestrator ran; the next restart would fail
		// closed, but only then.
		{Path: "./agents/BINARIES.sha256.sig", Severity: "critical"},
		{Path: cfg.LicensePath, Severity: "critical"},
		// index.html is hash-verified at startup (StaticHandler), but that check
		// runs ONCE. http.FileServer reads from disk per request, so a console
		// edited while the orchestrator is running was served immediately and
		// went undetected until the next restart — an attacker could alter
		// displayed scores, hide findings, or inject script. Watching it closes
		// the running-process window.
		{Path: filepath.Join(resolveWWWRoot(), "index.html"), Severity: "critical"},
	})
	integrity.WatchDir(cfg.ScenariosDir, "critical")
	go integrity.StartWatcher(context.Background(), pool, hub)
	log.Println("[+] Filesystem integrity watcher started")

	// ── Detection Retention ───────────────────────────────────────────────
	// Prunes raw detection alert blobs older than 30 days daily (summaries are
	// kept forever) so large BAS environments don't accumulate huge JSON blobs.
	detect.StartRetention(context.Background(), pool)

	// ── IOC Expiration ───────────────────────────────────────────────────
	// Transitions stale iocs rows to 'expired' daily -- the first real use of
	// that lifecycle status since Phase 0+A defined it.
	iocregistry.StartExpiration(context.Background(), pool, iocregistry.DefaultStaleAfter)

	// ── DNS Tunneling Exfiltration Sink ───────────────────────────────────
	// Second channel of the DLP sink-verification architecture (see
	// docs/superpowers/specs/2026-08-19-dns-tunneling-exfiltration-channel-design.md).
	// Independently enable/disable-able; a bind failure is logged and
	// reflected in Status(), never fatal to the rest of the orchestrator.
	if cfg.DNSSinkEnabled {
		dnssink.StartListener(context.Background(), ":53", dnssink.DomainSuffix, pool)
	} else {
		log.Println("[dnssink] disabled via DNS_SINK_ENABLED=false")
	}

	// ── SFTP Exfiltration Sink ────────────────────────────────────────────
	// Third channel of the DLP sink-verification architecture (see
	// docs/superpowers/specs/2026-09-01-sftp-exfiltration-channel-design.md).
	// Independently enable/disable-able; a bind failure is logged and
	// reflected in Status(), never fatal to the rest of the orchestrator.
	if cfg.SFTPSinkEnabled {
		sftpsink.StartListener(context.Background(), ":22", pool)
	} else {
		log.Println("[sftpsink] disabled via SFTP_SINK_ENABLED=false")
	}

	// ── SMTP Exfiltration Sink ────────────────────────────────────────────
	// Fourth channel of the DLP sink-verification architecture (see
	// docs/superpowers/specs/2026-09-01-smtp-exfiltration-channel-design.md).
	// Independently enable/disable-able; a bind failure is logged and
	// reflected in Status(), never fatal to the rest of the orchestrator.
	if cfg.SMTPSinkEnabled {
		smtpsink.StartListener(context.Background(), ":587", pool)
	} else {
		log.Println("[smtpsink] disabled via SMTP_SINK_ENABLED=false")
	}

	clientCAPool := x509.NewCertPool()
	clientCAPool.AddCert(ca.Certificate())
	serverTLSCert, err := ca.TLSCertificate()
	if err != nil {
		log.Fatalf("[FATAL] build server TLS identity from CA: %v", err)
	}

	// 9443 — mandatory mTLS, canonical secure endpoint for enrolled agents
	// (normal operation + certificate renewal). Never weaken this to
	// VerifyClientCertIfGiven -- see spec Section 1.
	mtlsHandler := api.WithMTLSIdentity(router)
	mtlsSrv := &http.Server{
		Addr:    fmt.Sprintf(":%d", cfg.HTTPPort),
		Handler: mtlsHandler,
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{serverTLSCert},
			ClientAuth:   tls.RequireAndVerifyClientCert,
			ClientCAs:    clientCAPool,
		},
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 90 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	// 9444 — TLS server-authenticated only, NO client cert required.
	// Permanent infrastructure for onboarding brand-new agents (not a
	// migration bridge) -- see spec Section 1 for why this listener must
	// exist even after B2 retires the legacy port.
	enrollSrv := &http.Server{
		Addr:    fmt.Sprintf(":%d", cfg.EnrollHTTPPort),
		Handler: api.MountEnrollment(handler), // enrollment + /health ONLY, never the full router
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{serverTLSCert},
			ClientAuth:   tls.NoClientCert,
		},
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 90 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	// 9000 — temporary legacy plaintext listener, unchanged behavior, for
	// pre-migration agents only. Retired entirely by the separately-scoped
	// B2 work.
	legacySrv := &http.Server{
		Addr:         fmt.Sprintf(":%d", cfg.LegacyHTTPPort),
		Handler:      api.WithLegacyListenerTag(router), // logged/counted distinctly (spec Section 4 step 4)
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 90 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	// Dashboard (default :9543) — browser dashboard: static SPA, JWT-
	// authenticated API, /ws/browser. Server-cert-only TLS, no client-cert
	// requirement -- a browser has none, and this listener exists
	// specifically so browser traffic doesn't need one (unlike the mTLS
	// agent listener). Uses an operator-supplied certificate
	// (cfg.DashboardTLSCertPath/KeyPath, from install.sh's pre-existing
	// BAS_TLS/TLS_CERT/TLS_KEY option, previously dormant) when configured,
	// falling back to the deployment CA's own self-signed certificate
	// otherwise -- browsers show a warning for the self-signed fallback,
	// which is expected and documented in docs/guides/upgrade-guide.md,
	// not a bug.
	dashboardTLSCert, err := resolveDashboardTLSCert(*cfg, serverTLSCert)
	if err != nil {
		log.Fatalf("[FATAL] load dashboard TLS cert/key (TLS_CERT=%s, TLS_KEY=%s): %v", cfg.DashboardTLSCertPath, cfg.DashboardTLSKeyPath, err)
	}
	dashboardSrv := &http.Server{
		Addr:    fmt.Sprintf(":%d", cfg.DashboardHTTPPort),
		Handler: router,
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{dashboardTLSCert},
			ClientAuth:   tls.NoClientCert,
		},
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 90 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	go func() {
		log.Printf("[*] BAS Orchestrator mTLS listening on :%d", cfg.HTTPPort)
		if err := mtlsSrv.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
			log.Fatalf("[FATAL] mTLS listen: %v", err)
		}
	}()
	go func() {
		log.Printf("[*] BAS Orchestrator enrollment listener on :%d", cfg.EnrollHTTPPort)
		if err := enrollSrv.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
			log.Fatalf("[FATAL] enrollment listen: %v", err)
		}
	}()
	go func() {
		log.Printf("[*] BAS Orchestrator legacy listener on :%d (temporary — retired by B2)", cfg.LegacyHTTPPort)
		if err := legacySrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("[FATAL] legacy listen: %v", err)
		}
	}()
	go func() {
		log.Printf("[*] BAS Orchestrator dashboard listening on :%d", cfg.DashboardHTTPPort)
		if err := dashboardSrv.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
			log.Fatalf("[FATAL] dashboard listen: %v", err)
		}
	}()

	// ── Graceful Shutdown ─────────────────────────────────────────────────
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Println("[*] Shutting down gracefully...")
	shutCtx, shutCancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer shutCancel()
	for _, s := range []*http.Server{mtlsSrv, enrollSrv, legacySrv, dashboardSrv} {
		if err := s.Shutdown(shutCtx); err != nil {
			log.Printf("[!] shutdown error: %v", err)
		}
	}
	log.Println("[*] Server stopped.")
}

// runStalenessMonitor ticks every 30s and marks agents offline when their
// last heartbeat is older than 90 seconds. Broadcasts each change so the
// dashboard reflects the real status without a manual refresh.
func runStalenessMonitor(pool *pgxpool.Pool, hub *ws.Hub) {
	// Single source of truth for the offline threshold, shared with the API's
	// read-path (models.EffectiveAgentStatus) and dispatch-path (runIsStale) checks.
	staleAfter := models.AgentOfflineAfter
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
//
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
