package main

import (
	"os"
	"testing"
)

func TestLoadConfig_ReadsFromEnv(t *testing.T) {
	os.Setenv("BAS_SERVER_URL", "http://example.com:9000")
	os.Setenv("BAS_ENV_LABEL", "Production")
	os.Setenv("BAS_AGENT_SECRET", "s3cr3t")
	defer os.Unsetenv("BAS_SERVER_URL")
	defer os.Unsetenv("BAS_ENV_LABEL")
	defer os.Unsetenv("BAS_AGENT_SECRET")

	cfg := loadConfig()
	if cfg.ServerURL != "http://example.com:9000" {
		t.Errorf("ServerURL = %q, want http://example.com:9000", cfg.ServerURL)
	}
	if cfg.EnvLabel != "Production" {
		t.Errorf("EnvLabel = %q, want Production", cfg.EnvLabel)
	}
	if cfg.AgentSecret != "s3cr3t" {
		t.Errorf("AgentSecret = %q, want s3cr3t", cfg.AgentSecret)
	}
}
