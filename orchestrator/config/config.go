package config

import (
	"encoding/json"
	"fmt"
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
	CalderaURL        string `json:"caldera_url,omitempty"`
	CalderaAPIKey     string `json:"caldera_api_key,omitempty"`
	LicensePath       string `json:"license_path,omitempty"`
	AdminPassword     string `json:"admin_password,omitempty"`

	// Threat-intel connector (MISP / OpenCTI)
	MISPUrl              string   `json:"misp_url,omitempty"`
	MISPApiKey           string   `json:"misp_api_key,omitempty"`
	OpenCTIUrl           string   `json:"opencti_url,omitempty"`
	OpenCTIApiKey        string   `json:"opencti_api_key,omitempty"`
	ThreatIntelPollHours int      `json:"threat_intel_poll_hours,omitempty"` // default 24
	ThreatIntelSectors   []string `json:"threat_intel_sectors,omitempty"`    // e.g. ["financial-services","banking"]
	ThreatIntelRegions   []string `json:"threat_intel_regions,omitempty"`    // e.g. ["Asia","India"]
}

// Load reads config from a JSON file, then overrides with environment variables.
// In Kubernetes the file is optional — DATABASE_URL and JWT_SECRET come from Secrets.
func Load(path string) (*Config, error) {
	cfg := &Config{
		HTTPPort:      9000,
		ScenariosDir:  "scenarios",
		ARTDir:        "/art-atomics",
		ARTPayloadDir: "/art-payloads",
		KEVFile:       "/content/cisa-kev.json",
	}

	// Try file first (local dev)
	if f, err := os.Open(path); err == nil {
		defer f.Close()
		if err := json.NewDecoder(f).Decode(cfg); err != nil {
			return nil, fmt.Errorf("decode config: %w", err)
		}
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
	if v := os.Getenv("CALDERA_URL"); v != "" {
		cfg.CalderaURL = v
	}
	if v := os.Getenv("CALDERA_API_KEY"); v != "" {
		cfg.CalderaAPIKey = v
	}
	if v := os.Getenv("AGENT_SECRET"); v != "" {
		cfg.AgentSecret = v
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
	if v := os.Getenv("BAS_LICENSE_PATH"); v != "" {
		cfg.LicensePath = v
	}
	if v := os.Getenv("BAS_ADMIN_PASSWORD"); v != "" {
		cfg.AdminPassword = v
	}

	if cfg.DatabaseURL == "" {
		return nil, fmt.Errorf("database_url required (set DATABASE_URL env var or config file)")
	}
	if cfg.JWTSecret == "" {
		return nil, fmt.Errorf("jwt_secret required (set JWT_SECRET env var or config file)")
	}
	return cfg, nil
}
