package config

import (
	"os"
	"testing"
)

func TestLoad_PKIDefaults(t *testing.T) {
	os.Setenv("DATABASE_URL", "postgres://test")
	os.Setenv("JWT_SECRET", "test-secret")
	defer os.Unsetenv("DATABASE_URL")
	defer os.Unsetenv("JWT_SECRET")

	cfg, err := Load("/nonexistent/config.json")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.PKIDir != "/etc/audspect/pki" {
		t.Errorf("PKIDir = %q, want /etc/audspect/pki", cfg.PKIDir)
	}
	if cfg.EnrollHTTPPort != 9444 {
		t.Errorf("EnrollHTTPPort = %d, want 9444", cfg.EnrollHTTPPort)
	}
	if cfg.LegacyHTTPPort != 9000 {
		t.Errorf("LegacyHTTPPort = %d, want 9000", cfg.LegacyHTTPPort)
	}
}

func TestLoad_PKIEnvOverrides(t *testing.T) {
	os.Setenv("DATABASE_URL", "postgres://test")
	os.Setenv("JWT_SECRET", "test-secret")
	os.Setenv("PKI_DIR", "/custom/pki")
	os.Setenv("HTTP_PORT_ENROLL", "9555")
	os.Setenv("HTTP_PORT_LEGACY", "9001")
	defer os.Unsetenv("DATABASE_URL")
	defer os.Unsetenv("JWT_SECRET")
	defer os.Unsetenv("PKI_DIR")
	defer os.Unsetenv("HTTP_PORT_ENROLL")
	defer os.Unsetenv("HTTP_PORT_LEGACY")

	cfg, err := Load("/nonexistent/config.json")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.PKIDir != "/custom/pki" {
		t.Errorf("PKIDir = %q, want /custom/pki", cfg.PKIDir)
	}
	if cfg.EnrollHTTPPort != 9555 {
		t.Errorf("EnrollHTTPPort = %d, want 9555", cfg.EnrollHTTPPort)
	}
	if cfg.LegacyHTTPPort != 9001 {
		t.Errorf("LegacyHTTPPort = %d, want 9001", cfg.LegacyHTTPPort)
	}
}
