package config

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strconv"
)

type Config struct {
	DatabaseURL       string `json:"database_url"`
	JWTSecret         string `json:"jwt_secret"`
	AgentSecret       string `json:"agent_secret,omitempty"`
	HTTPPort          int    `json:"http_port"`
	ScenariosDir      string `json:"scenarios_dir"`
	ARTDir            string `json:"art_dir,omitempty"`
	ARTPayloadDir     string `json:"art_payload_dir,omitempty"`     // server-side store of ART external payloads (operator-provided)
	ARTContentVersion string `json:"art_content_version,omitempty"` // content-pack version; reseed is skipped when unchanged
	KEVFile           string `json:"kev_file,omitempty"`            // CISA KEV catalog JSON (baked into image); seeds the cves table
	EPSSFile          string `json:"epss_file,omitempty"`           // FIRST EPSS CSV/CSV.GZ (optional); seeds cve_epss for KEV-linked CVEs
	CalderaURL        string `json:"caldera_url,omitempty"`
	CalderaAPIKey     string `json:"caldera_api_key,omitempty"`
	OTXAPIKey         string `json:"otx_api_key,omitempty"`
	LicensePath       string `json:"license_path,omitempty"`
	AdminPassword     string `json:"admin_password,omitempty"`
	AdminEmail        string `json:"admin_email,omitempty"` // used as the admin username on first-run seed

	// PBKDF2Iterations controls the PBKDF2-HMAC-SHA256 iteration count for
	// password hashing. Minimum enforced at runtime: 310000 (NIST SP 800-132).
	// Set higher for deployments with additional time budget (e.g. 600000).
	PBKDF2Iterations int `json:"pbkdf2_iterations,omitempty"`

	// Exercise Engine — SMTP injector + tracker base URL
	SMTPHost      string `json:"smtp_host,omitempty"`
	SMTPPort      int    `json:"smtp_port,omitempty"`
	SMTPUser      string `json:"smtp_user,omitempty"`
	SMTPPass      string `json:"smtp_pass,omitempty"`
	SMTPFrom      string `json:"smtp_from,omitempty"`
	SMTPFromName  string `json:"smtp_from_name,omitempty"`
	PublicBaseURL string `json:"public_base_url,omitempty"` // e.g. "https://bas.internal" for tracking pixel URLs

	// Exercise Engine — communication injectors (SMS gateway + chat webhooks)
	SMSGatewayURL   string `json:"sms_gateway_url,omitempty"`
	SMSGatewayToken string `json:"sms_gateway_token,omitempty"`
	SMSGatewayFrom  string `json:"sms_gateway_from,omitempty"`
	SlackWebhookURL string `json:"slack_webhook_url,omitempty"`
	TeamsWebhookURL string `json:"teams_webhook_url,omitempty"`

	// Threat-intel connector (MISP / OpenCTI)
	MISPUrl              string   `json:"misp_url,omitempty"`
	MISPApiKey           string   `json:"misp_api_key,omitempty"`
	OpenCTIUrl           string   `json:"opencti_url,omitempty"`
	OpenCTIApiKey        string   `json:"opencti_api_key,omitempty"`
	ThreatIntelPollHours int      `json:"threat_intel_poll_hours,omitempty"` // default 24
	ThreatIntelSectors   []string `json:"threat_intel_sectors,omitempty"`    // e.g. ["financial-services","banking"]
	ThreatIntelRegions   []string `json:"threat_intel_regions,omitempty"`    // e.g. ["Asia","India"]

	// Air-gapped threat-intel: dir holding a signed ti-bundle.json (bundle floor;
	// live MISP/OpenCTI above overlay on top when configured).
	TIBundleDir string `json:"ti_bundle_dir,omitempty"`

	// DB role hardening (opt-in): when set, the orchestrator demotes its runtime
	// Postgres role to NOSUPERUSER/NOBYPASSRLS at startup (so RLS can enforce)
	// after creating a bas_breakglass recovery superuser with this password.
	// Unset = hardening inactive (default). Env: BAS_DB_BREAKGLASS_PASSWORD.
	DBBreakGlassPassword string `json:"db_breakglass_password,omitempty"`

	// API rate limiting (opt-in): a single global token-bucket limit protecting
	// against a runaway client, not a per-tenant/commercial quota system (that
	// belongs to the future Audspect Cloud offering, not this on-prem product).
	// Disabled by default so existing installs are never surprise-limited on
	// upgrade -- same discipline as DBBreakGlassPassword above.
	// Env: API_RATE_LIMIT_ENABLED=true, API_RATE_LIMIT=1000/min, API_RATE_BURST=200.
	RateLimitEnabled bool `json:"rate_limit_enabled,omitempty"`
	RateLimitPerMin  int  `json:"rate_limit_per_min,omitempty"`
	RateLimitBurst   int  `json:"rate_limit_burst,omitempty"`

	// DNSSinkEnabled controls the DNS-tunneling exfiltration listener
	// (internal/dnssink). Defaults to true -- unlike RateLimitEnabled above,
	// this is a detection-capability feature, not an opt-in safety limit, so
	// it should be on by default; a bind failure (e.g. port 53 already
	// owned) is logged and reflected in the listener's own Status(), never
	// fatal to the rest of the orchestrator, so leaving it enabled by
	// default carries no risk to existing installs. Env: DNS_SINK_ENABLED.
	DNSSinkEnabled bool `json:"dns_sink_enabled,omitempty"`

	// SFTPSinkEnabled controls the SFTP exfiltration listener
	// (internal/sftpsink). Defaults to true for the same reason
	// DNSSinkEnabled does -- a bind failure is logged and reflected in the
	// listener's own Status(), never fatal to the rest of the orchestrator.
	// Env: SFTP_SINK_ENABLED.
	SFTPSinkEnabled bool `json:"sftp_sink_enabled,omitempty"`

	// SMTPSinkEnabled controls the SMTP exfiltration listener
	// (internal/smtpsink). Defaults to true for the same reason
	// DNSSinkEnabled/SFTPSinkEnabled do -- a bind failure is logged and
	// reflected in the listener's own Status(), never fatal to the rest
	// of the orchestrator. Env: SMTP_SINK_ENABLED.
	SMTPSinkEnabled bool `json:"smtp_sink_enabled,omitempty"`

	// MetricsToken, when set, requires "Authorization: Bearer <token>" on
	// GET /metrics. Empty (the default) leaves it open -- same opt-in
	// posture as DBBreakGlassPassword and RateLimitEnabled.
	MetricsToken string `json:"metrics_token,omitempty"`

	// Agent trust model (B1/B3) — deployment CA + per-agent mTLS.
	// See docs/superpowers/specs/2026-09-27-agent-trust-model-b1-b3-b4-design.md.
	// PKIDir holds the deployment CA's keypair/cert (ca-key.pem, ca-cert.pem),
	// generated on first startup if absent. EnrollHTTPPort serves initial
	// bootstrap CSR submission over TLS with NO client cert required.
	// LegacyHTTPPort is the temporary plaintext listener for pre-migration
	// agents, retired entirely by the separately-scoped B2 work.
	PKIDir          string `json:"pki_dir,omitempty"`
	EnrollHTTPPort  int    `json:"enroll_http_port,omitempty"`
	LegacyHTTPPort  int    `json:"legacy_http_port,omitempty"`
}

// Load reads config from a JSON file, then overrides with environment variables.
// In Kubernetes the file is optional — DATABASE_URL and JWT_SECRET come from Secrets.
func Load(path string) (*Config, error) {
	cfg := &Config{
		HTTPPort:         9000,
		ScenariosDir:     "scenarios",
		ARTDir:           "/art-atomics",
		ARTPayloadDir:    "/art-payloads",
		KEVFile:          "/content/cisa-kev.json",
		PBKDF2Iterations: 310000,
		TIBundleDir:      "/intel-bundles",
		RateLimitPerMin:  1000,
		RateLimitBurst:   200,
		DNSSinkEnabled:   true,
		SFTPSinkEnabled:  true,
		SMTPSinkEnabled:  true,
		PKIDir:           "/etc/audspect/pki",
		EnrollHTTPPort:   9444,
		LegacyHTTPPort:   9000,
	}

	// Try file first (local dev)
	var jwtFromFile, agentFromFile bool
	if f, err := os.Open(path); err == nil {
		defer f.Close()
		if err := json.NewDecoder(f).Decode(cfg); err != nil {
			return nil, fmt.Errorf("decode config: %w", err)
		}
		// Track which secrets came from the JSON file so we can warn below.
		jwtFromFile = cfg.JWTSecret != ""
		agentFromFile = cfg.AgentSecret != ""
	}

	// Environment variables override file values (Kubernetes / Docker)
	if v := os.Getenv("DATABASE_URL"); v != "" {
		cfg.DatabaseURL = v
	}
	if v := os.Getenv("BAS_DB_BREAKGLASS_PASSWORD"); v != "" {
		cfg.DBBreakGlassPassword = v
	}
	if v := os.Getenv("JWT_SECRET"); v != "" {
		cfg.JWTSecret = v
	}
	if v := os.Getenv("HTTP_PORT"); v != "" {
		fmt.Sscanf(v, "%d", &cfg.HTTPPort)
	}
	if v := os.Getenv("SCENARIOS_DIR"); v != "" {
		cfg.ScenariosDir = v
	}
	if v := os.Getenv("ART_DIR"); v != "" {
		cfg.ARTDir = v
	}
	if v := os.Getenv("ART_PAYLOAD_DIR"); v != "" {
		cfg.ARTPayloadDir = v
	}
	if v := os.Getenv("ART_CONTENT_VERSION"); v != "" {
		cfg.ARTContentVersion = v
	}
	if v := os.Getenv("KEV_FILE"); v != "" {
		cfg.KEVFile = v
	}
	if v := os.Getenv("EPSS_FILE"); v != "" {
		cfg.EPSSFile = v
	}
	if v := os.Getenv("CALDERA_URL"); v != "" {
		cfg.CalderaURL = v
	}
	if v := os.Getenv("CALDERA_API_KEY"); v != "" {
		cfg.CalderaAPIKey = v
	}
	if v := os.Getenv("OTX_API_KEY"); v != "" {
		cfg.OTXAPIKey = v
	}
	if v := os.Getenv("AGENT_SECRET"); v != "" {
		cfg.AgentSecret = v
	}
	if v := os.Getenv("SMTP_HOST"); v != "" {
		cfg.SMTPHost = v
	}
	if v := os.Getenv("SMTP_PORT"); v != "" {
		fmt.Sscanf(v, "%d", &cfg.SMTPPort)
	}
	if v := os.Getenv("SMTP_USER"); v != "" {
		cfg.SMTPUser = v
	}
	if v := os.Getenv("SMTP_PASS"); v != "" {
		cfg.SMTPPass = v
	}
	if v := os.Getenv("SMTP_FROM"); v != "" {
		cfg.SMTPFrom = v
	}
	if v := os.Getenv("SMTP_FROM_NAME"); v != "" {
		cfg.SMTPFromName = v
	}
	if v := os.Getenv("PUBLIC_BASE_URL"); v != "" {
		cfg.PublicBaseURL = v
	}
	if v := os.Getenv("SMS_GATEWAY_URL"); v != "" {
		cfg.SMSGatewayURL = v
	}
	if v := os.Getenv("SMS_GATEWAY_TOKEN"); v != "" {
		cfg.SMSGatewayToken = v
	}
	if v := os.Getenv("SMS_GATEWAY_FROM"); v != "" {
		cfg.SMSGatewayFrom = v
	}
	if v := os.Getenv("SLACK_WEBHOOK_URL"); v != "" {
		cfg.SlackWebhookURL = v
	}
	if v := os.Getenv("TEAMS_WEBHOOK_URL"); v != "" {
		cfg.TeamsWebhookURL = v
	}
	if v := os.Getenv("MISP_URL"); v != "" {
		cfg.MISPUrl = v
	}
	if v := os.Getenv("MISP_API_KEY"); v != "" {
		cfg.MISPApiKey = v
	}
	if v := os.Getenv("OPENCTI_URL"); v != "" {
		cfg.OpenCTIUrl = v
	}
	if v := os.Getenv("OPENCTI_API_KEY"); v != "" {
		cfg.OpenCTIApiKey = v
	}
	if v := os.Getenv("THREAT_INTEL_POLL_HOURS"); v != "" {
		fmt.Sscanf(v, "%d", &cfg.ThreatIntelPollHours)
	}
	if v := os.Getenv("TI_BUNDLE_DIR"); v != "" {
		cfg.TIBundleDir = v
	}
	if v := os.Getenv("BAS_LICENSE_PATH"); v != "" {
		cfg.LicensePath = v
	}
	if v := os.Getenv("BAS_ADMIN_PASSWORD"); v != "" {
		cfg.AdminPassword = v
	}
	if v := os.Getenv("BAS_ADMIN_EMAIL"); v != "" {
		cfg.AdminEmail = v
	}
	if v := os.Getenv("BAS_PBKDF2_ITERATIONS"); v != "" {
		fmt.Sscanf(v, "%d", &cfg.PBKDF2Iterations)
	}
	if v := os.Getenv("API_RATE_LIMIT_ENABLED"); v != "" {
		if b, err := strconv.ParseBool(v); err == nil {
			cfg.RateLimitEnabled = b
		}
	}
	if v := os.Getenv("API_RATE_LIMIT"); v != "" {
		fmt.Sscanf(v, "%d/min", &cfg.RateLimitPerMin)
	}
	if v := os.Getenv("API_RATE_BURST"); v != "" {
		fmt.Sscanf(v, "%d", &cfg.RateLimitBurst)
	}
	if v := os.Getenv("DNS_SINK_ENABLED"); v != "" {
		if b, err := strconv.ParseBool(v); err == nil {
			cfg.DNSSinkEnabled = b
		}
	}
	if v := os.Getenv("SFTP_SINK_ENABLED"); v != "" {
		if b, err := strconv.ParseBool(v); err == nil {
			cfg.SFTPSinkEnabled = b
		}
	}
	if v := os.Getenv("SMTP_SINK_ENABLED"); v != "" {
		if b, err := strconv.ParseBool(v); err == nil {
			cfg.SMTPSinkEnabled = b
		}
	}
	if v := os.Getenv("METRICS_TOKEN"); v != "" {
		cfg.MetricsToken = v
	}
	if v := os.Getenv("PKI_DIR"); v != "" {
		cfg.PKIDir = v
	}
	if v := os.Getenv("HTTP_PORT_ENROLL"); v != "" {
		fmt.Sscanf(v, "%d", &cfg.EnrollHTTPPort)
	}
	if v := os.Getenv("HTTP_PORT_LEGACY"); v != "" {
		fmt.Sscanf(v, "%d", &cfg.LegacyHTTPPort)
	}

	if cfg.DatabaseURL == "" {
		return nil, fmt.Errorf("database_url required (set DATABASE_URL env var or config file)")
	}
	if cfg.JWTSecret == "" {
		return nil, fmt.Errorf("jwt_secret required (set JWT_SECRET env var or config file)")
	}

	// ── Security: warn when sensitive secrets live in the JSON file ────────
	// Secrets in config.json are readable by anyone with filesystem access.
	// Best practice: move them to environment variables or a secrets manager.
	if jwtFromFile && os.Getenv("JWT_SECRET") == "" {
		log.Println("[security] WARNING: jwt_secret found in config.json — " +
			"move to JWT_SECRET env var or a secrets manager to harden this deployment")
	}
	if agentFromFile && os.Getenv("AGENT_SECRET") == "" {
		log.Println("[security] WARNING: agent_secret found in config.json — " +
			"move to AGENT_SECRET env var to harden this deployment")
	}

	return cfg, nil
}
