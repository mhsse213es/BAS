package config

import (
	"encoding/json"
	"fmt"
	"os"
)

type Config struct {
	DatabaseURL   string `json:"database_url"`
	JWTSecret     string `json:"jwt_secret"`
	HTTPPort      int    `json:"http_port"`
	ScenariosDir  string `json:"scenarios_dir"`
	CalderaURL    string `json:"caldera_url,omitempty"`
	CalderaAPIKey string `json:"caldera_api_key,omitempty"`
}

// Load reads config from a JSON file, then overrides with environment variables.
// In Kubernetes the file is optional — DATABASE_URL and JWT_SECRET come from Secrets.
func Load(path string) (*Config, error) {
	cfg := &Config{
		HTTPPort:     9000,
		ScenariosDir: "scenarios",
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

	if cfg.DatabaseURL == "" {
		return nil, fmt.Errorf("database_url required (set DATABASE_URL env var or config file)")
	}
	if cfg.JWTSecret == "" {
		return nil, fmt.Errorf("jwt_secret required (set JWT_SECRET env var or config file)")
	}
	return cfg, nil
}
