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

func TestLoad_DashboardDefaults(t *testing.T) {
	os.Setenv("DATABASE_URL", "postgres://test")
	os.Setenv("JWT_SECRET", "test-secret")
	defer os.Unsetenv("DATABASE_URL")
	defer os.Unsetenv("JWT_SECRET")

	cfg, err := Load("/nonexistent/config.json")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.DashboardHTTPPort != 9543 {
		t.Errorf("DashboardHTTPPort = %d, want 9543", cfg.DashboardHTTPPort)
	}
	if cfg.DashboardTLSCertPath != "" || cfg.DashboardTLSKeyPath != "" {
		t.Errorf("DashboardTLSCertPath/DashboardTLSKeyPath should default empty (self-signed CA cert fallback), got %q/%q", cfg.DashboardTLSCertPath, cfg.DashboardTLSKeyPath)
	}
}

func TestLoad_DashboardEnvOverrides(t *testing.T) {
	os.Setenv("DATABASE_URL", "postgres://test")
	os.Setenv("JWT_SECRET", "test-secret")
	os.Setenv("HTTP_PORT_DASHBOARD", "9555")
	os.Setenv("TLS_CERT", "/etc/bas/certs/bas.crt")
	os.Setenv("TLS_KEY", "/etc/bas/certs/bas.key")
	defer os.Unsetenv("DATABASE_URL")
	defer os.Unsetenv("JWT_SECRET")
	defer os.Unsetenv("HTTP_PORT_DASHBOARD")
	defer os.Unsetenv("TLS_CERT")
	defer os.Unsetenv("TLS_KEY")

	cfg, err := Load("/nonexistent/config.json")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.DashboardHTTPPort != 9555 {
		t.Errorf("DashboardHTTPPort = %d, want 9555", cfg.DashboardHTTPPort)
	}
	if cfg.DashboardTLSCertPath != "/etc/bas/certs/bas.crt" {
		t.Errorf("DashboardTLSCertPath = %q, want /etc/bas/certs/bas.crt", cfg.DashboardTLSCertPath)
	}
	if cfg.DashboardTLSKeyPath != "/etc/bas/certs/bas.key" {
		t.Errorf("DashboardTLSKeyPath = %q, want /etc/bas/certs/bas.key", cfg.DashboardTLSKeyPath)
	}
}

func TestLoad_RejectsCollidingListenerPorts(t *testing.T) {
	os.Setenv("DATABASE_URL", "postgres://test")
	os.Setenv("JWT_SECRET", "test-secret")
	os.Setenv("HTTP_PORT", "9443")
	os.Setenv("HTTP_PORT_LEGACY", "9443") // deliberately colliding with HTTP_PORT
	defer os.Unsetenv("DATABASE_URL")
	defer os.Unsetenv("JWT_SECRET")
	defer os.Unsetenv("HTTP_PORT")
	defer os.Unsetenv("HTTP_PORT_LEGACY")

	_, err := Load("/nonexistent/config.json")
	if err == nil {
		t.Fatal("expected Load to reject colliding HTTP_PORT and HTTP_PORT_LEGACY (both 9443), got nil error")
	}
}

func TestLoad_DistinctPortsSucceed(t *testing.T) {
	os.Setenv("DATABASE_URL", "postgres://test")
	os.Setenv("JWT_SECRET", "test-secret")
	defer os.Unsetenv("DATABASE_URL")
	defer os.Unsetenv("JWT_SECRET")

	// All four ports at their real defaults (9443/9444/9000/9543) -- must
	// NOT be rejected by the same validation the collision test exercises.
	if _, err := Load("/nonexistent/config.json"); err != nil {
		t.Fatalf("Load with all-default (distinct) ports should succeed, got: %v", err)
	}
}
