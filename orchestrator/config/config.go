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

func Load(path string) (*Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open config %s: %w", path, err)
	}
	defer f.Close()

	cfg := &Config{
		HTTPPort:     9000,
		ScenariosDir: "scenarios",
	}
	if err := json.NewDecoder(f).Decode(cfg); err != nil {
		return nil, fmt.Errorf("decode config: %w", err)
	}
	if cfg.DatabaseURL == "" {
		return nil, fmt.Errorf("database_url is required in config")
	}
	if cfg.JWTSecret == "" {
		return nil, fmt.Errorf("jwt_secret is required in config")
	}
	return cfg, nil
}
