package config

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
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
