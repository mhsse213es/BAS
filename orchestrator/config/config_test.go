package config

import (
	"os"
	"strings"
	"testing"
)

func TestLoad_PKIDefaults(t *testing.T) {
	os.Setenv("DATABASE_URL", "postgres://test")
	os.Setenv("DATABASE_ADMIN_URL", "postgres://test-admin")
	os.Setenv("BAS_APP_DB_PASSWORD", "test-app-password")
	os.Setenv("JWT_SECRET", "test-secret-32-bytes-long-enough")
	defer os.Unsetenv("DATABASE_URL")
	defer os.Unsetenv("DATABASE_ADMIN_URL")
	defer os.Unsetenv("BAS_APP_DB_PASSWORD")
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
	os.Setenv("DATABASE_ADMIN_URL", "postgres://test-admin")
	os.Setenv("BAS_APP_DB_PASSWORD", "test-app-password")
	os.Setenv("JWT_SECRET", "test-secret-32-bytes-long-enough")
	os.Setenv("PKI_DIR", "/custom/pki")
	os.Setenv("HTTP_PORT_ENROLL", "9555")
	os.Setenv("HTTP_PORT_LEGACY", "9001")
	defer os.Unsetenv("DATABASE_URL")
	defer os.Unsetenv("DATABASE_ADMIN_URL")
	defer os.Unsetenv("BAS_APP_DB_PASSWORD")
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
	os.Setenv("DATABASE_ADMIN_URL", "postgres://test-admin")
	os.Setenv("BAS_APP_DB_PASSWORD", "test-app-password")
	os.Setenv("JWT_SECRET", "test-secret-32-bytes-long-enough")
	defer os.Unsetenv("DATABASE_URL")
	defer os.Unsetenv("DATABASE_ADMIN_URL")
	defer os.Unsetenv("BAS_APP_DB_PASSWORD")
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
	os.Setenv("DATABASE_ADMIN_URL", "postgres://test-admin")
	os.Setenv("BAS_APP_DB_PASSWORD", "test-app-password")
	os.Setenv("JWT_SECRET", "test-secret-32-bytes-long-enough")
	os.Setenv("HTTP_PORT_DASHBOARD", "9555")
	os.Setenv("TLS_CERT", "/etc/bas/certs/bas.crt")
	os.Setenv("TLS_KEY", "/etc/bas/certs/bas.key")
	defer os.Unsetenv("DATABASE_URL")
	defer os.Unsetenv("DATABASE_ADMIN_URL")
	defer os.Unsetenv("BAS_APP_DB_PASSWORD")
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
	os.Setenv("DATABASE_ADMIN_URL", "postgres://test-admin")
	os.Setenv("BAS_APP_DB_PASSWORD", "test-app-password")
	os.Setenv("JWT_SECRET", "test-secret-32-bytes-long-enough")
	os.Setenv("HTTP_PORT", "9443")
	os.Setenv("HTTP_PORT_LEGACY", "9443") // deliberately colliding with HTTP_PORT
	defer os.Unsetenv("DATABASE_URL")
	defer os.Unsetenv("DATABASE_ADMIN_URL")
	defer os.Unsetenv("BAS_APP_DB_PASSWORD")
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
	os.Setenv("DATABASE_ADMIN_URL", "postgres://test-admin")
	os.Setenv("BAS_APP_DB_PASSWORD", "test-app-password")
	os.Setenv("JWT_SECRET", "test-secret-32-bytes-long-enough")
	defer os.Unsetenv("DATABASE_URL")
	defer os.Unsetenv("DATABASE_ADMIN_URL")
	defer os.Unsetenv("BAS_APP_DB_PASSWORD")
	defer os.Unsetenv("JWT_SECRET")

	// All four ports at their real defaults (9443/9444/9000/9543) -- must
	// NOT be rejected by the same validation the collision test exercises.
	if _, err := Load("/nonexistent/config.json"); err != nil {
		t.Fatalf("Load with all-default (distinct) ports should succeed, got: %v", err)
	}
}

func TestLoad_LegacyListenerEnabledDefaultsTrue(t *testing.T) {
	os.Setenv("DATABASE_URL", "postgres://test")
	os.Setenv("DATABASE_ADMIN_URL", "postgres://test-admin")
	os.Setenv("BAS_APP_DB_PASSWORD", "test-app-password")
	os.Setenv("JWT_SECRET", "test-secret-32-bytes-long-enough")
	os.Unsetenv("BAS_LEGACY_LISTENER_ENABLED")
	defer os.Unsetenv("DATABASE_URL")
	defer os.Unsetenv("DATABASE_ADMIN_URL")
	defer os.Unsetenv("BAS_APP_DB_PASSWORD")
	defer os.Unsetenv("JWT_SECRET")

	cfg, err := Load("/nonexistent/config.json")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !cfg.LegacyListenerEnabled {
		t.Error("expected LegacyListenerEnabled to default true when BAS_LEGACY_LISTENER_ENABLED is unset -- every existing deployment must behave unchanged")
	}
}

func TestLoad_LegacyListenerEnabledFalseOverride(t *testing.T) {
	os.Setenv("DATABASE_URL", "postgres://test")
	os.Setenv("DATABASE_ADMIN_URL", "postgres://test-admin")
	os.Setenv("BAS_APP_DB_PASSWORD", "test-app-password")
	os.Setenv("JWT_SECRET", "test-secret-32-bytes-long-enough")
	os.Setenv("BAS_LEGACY_LISTENER_ENABLED", "false")
	defer os.Unsetenv("DATABASE_URL")
	defer os.Unsetenv("DATABASE_ADMIN_URL")
	defer os.Unsetenv("BAS_APP_DB_PASSWORD")
	defer os.Unsetenv("JWT_SECRET")
	defer os.Unsetenv("BAS_LEGACY_LISTENER_ENABLED")

	cfg, err := Load("/nonexistent/config.json")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.LegacyListenerEnabled {
		t.Error("expected LegacyListenerEnabled=false when BAS_LEGACY_LISTENER_ENABLED=false")
	}
}

func TestLoad_DatabaseAdminURLRequired(t *testing.T) {
	os.Setenv("DATABASE_URL", "postgres://bas_app:pw@localhost/bas_platform")
	os.Setenv("JWT_SECRET", "test-secret-32-bytes-long-enough")
	os.Setenv("BAS_APP_DB_PASSWORD", "test-app-password")
	os.Unsetenv("DATABASE_ADMIN_URL")
	defer os.Unsetenv("DATABASE_URL")
	defer os.Unsetenv("JWT_SECRET")
	defer os.Unsetenv("BAS_APP_DB_PASSWORD")

	_, err := Load("/nonexistent/config.json")
	if err == nil {
		t.Fatal("expected an error when DATABASE_ADMIN_URL is unset, got nil")
	}
}

func TestLoad_DatabaseAdminURLFromEnv(t *testing.T) {
	os.Setenv("DATABASE_URL", "postgres://bas_app:pw@localhost/bas_platform")
	os.Setenv("DATABASE_ADMIN_URL", "postgres://bas_user:pw@localhost/bas_platform")
	os.Setenv("JWT_SECRET", "test-secret-32-bytes-long-enough")
	os.Setenv("BAS_APP_DB_PASSWORD", "test-app-password")
	defer os.Unsetenv("DATABASE_URL")
	defer os.Unsetenv("DATABASE_ADMIN_URL")
	defer os.Unsetenv("JWT_SECRET")
	defer os.Unsetenv("BAS_APP_DB_PASSWORD")

	cfg, err := Load("/nonexistent/config.json")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.DatabaseAdminURL != "postgres://bas_user:pw@localhost/bas_platform" {
		t.Errorf("DatabaseAdminURL = %q, want the env value", cfg.DatabaseAdminURL)
	}
}

// TestLoad_ToleratesStrayBreakglassEnvVar locks in the upgrade requirement
// from docs/superpowers/specs/2026-09-30-runtime-role-separation-design.md:
// an existing deployment's .env may still set the now-retired
// BAS_DB_BREAKGLASS_PASSWORD (from before HardenRuntimeRole was removed).
// Load() must not fail just because that stray var is present -- nothing
// reads it anymore, so it should be silently ignored.
func TestLoad_ToleratesStrayBreakglassEnvVar(t *testing.T) {
	os.Setenv("DATABASE_URL", "postgres://bas_app:pw@localhost/bas_platform")
	os.Setenv("DATABASE_ADMIN_URL", "postgres://bas_user:pw@localhost/bas_platform")
	os.Setenv("JWT_SECRET", "test-secret-32-bytes-long-enough")
	os.Setenv("BAS_APP_DB_PASSWORD", "test-app-password")
	os.Setenv("BAS_DB_BREAKGLASS_PASSWORD", "stray-value-from-an-old-.env")
	defer os.Unsetenv("DATABASE_URL")
	defer os.Unsetenv("DATABASE_ADMIN_URL")
	defer os.Unsetenv("JWT_SECRET")
	defer os.Unsetenv("BAS_APP_DB_PASSWORD")
	defer os.Unsetenv("BAS_DB_BREAKGLASS_PASSWORD")

	if _, err := Load("/nonexistent/config.json"); err != nil {
		t.Fatalf("Load should tolerate a stray BAS_DB_BREAKGLASS_PASSWORD, got: %v", err)
	}
}

func TestLoad_AppDBPasswordRequired(t *testing.T) {
	os.Setenv("DATABASE_URL", "postgres://bas_app:pw@localhost/bas_platform")
	os.Setenv("DATABASE_ADMIN_URL", "postgres://bas_user:pw@localhost/bas_platform")
	os.Setenv("JWT_SECRET", "test-secret-32-bytes-long-enough")
	os.Unsetenv("BAS_APP_DB_PASSWORD")
	defer os.Unsetenv("DATABASE_URL")
	defer os.Unsetenv("DATABASE_ADMIN_URL")
	defer os.Unsetenv("JWT_SECRET")

	_, err := Load("/nonexistent/config.json")
	if err == nil {
		t.Fatal("expected an error when BAS_APP_DB_PASSWORD is unset, got nil")
	}
}

// F4: HS256 security depends entirely on JWT_SECRET's entropy, so a
// short/weak secret must be rejected, not merely a missing one.
func TestLoad_JWTSecretTooShort_Rejected(t *testing.T) {
	os.Setenv("DATABASE_URL", "postgres://test")
	os.Setenv("DATABASE_ADMIN_URL", "postgres://test-admin")
	os.Setenv("BAS_APP_DB_PASSWORD", "test-app-password")
	os.Setenv("JWT_SECRET", "this-is-only-31-bytes-long-xxx") // 30 bytes (name is approximate), deliberately under 32
	defer os.Unsetenv("DATABASE_URL")
	defer os.Unsetenv("DATABASE_ADMIN_URL")
	defer os.Unsetenv("BAS_APP_DB_PASSWORD")
	defer os.Unsetenv("JWT_SECRET")

	_, err := Load("/nonexistent/config.json")
	if err == nil {
		t.Fatal("expected an error for a JWT_SECRET under 32 bytes, got nil")
	}
}

func TestLoad_JWTSecretExactly32Bytes_Accepted(t *testing.T) {
	os.Setenv("DATABASE_URL", "postgres://test")
	os.Setenv("DATABASE_ADMIN_URL", "postgres://test-admin")
	os.Setenv("BAS_APP_DB_PASSWORD", "test-app-password")
	os.Setenv("JWT_SECRET", "test-secret-32-bytes-long-enough") // exactly 32 bytes
	defer os.Unsetenv("DATABASE_URL")
	defer os.Unsetenv("DATABASE_ADMIN_URL")
	defer os.Unsetenv("BAS_APP_DB_PASSWORD")
	defer os.Unsetenv("JWT_SECRET")

	if _, err := Load("/nonexistent/config.json"); err != nil {
		t.Fatalf("Load: %v, want a 32-byte secret to be accepted", err)
	}
}

func TestLoad_JWTSecretKnownDefault_Rejected(t *testing.T) {
	os.Setenv("DATABASE_URL", "postgres://test")
	os.Setenv("DATABASE_ADMIN_URL", "postgres://test-admin")
	os.Setenv("BAS_APP_DB_PASSWORD", "test-app-password")
	// Long enough to pass the length check alone, but a known placeholder
	// value that must never reach production.
	os.Setenv("JWT_SECRET", "changeme-changeme-changeme-change")
	defer os.Unsetenv("DATABASE_URL")
	defer os.Unsetenv("DATABASE_ADMIN_URL")
	defer os.Unsetenv("BAS_APP_DB_PASSWORD")
	defer os.Unsetenv("JWT_SECRET")

	_, err := Load("/nonexistent/config.json")
	if err == nil {
		t.Fatal("expected an error for a known-default/placeholder JWT_SECRET, got nil")
	}
}

func TestLoad_AppDBPasswordFromEnv(t *testing.T) {
	os.Setenv("DATABASE_URL", "postgres://bas_app:pw@localhost/bas_platform")
	os.Setenv("DATABASE_ADMIN_URL", "postgres://bas_user:pw@localhost/bas_platform")
	os.Setenv("JWT_SECRET", "test-secret-32-bytes-long-enough")
	os.Setenv("BAS_APP_DB_PASSWORD", "rotated-password")
	defer os.Unsetenv("DATABASE_URL")
	defer os.Unsetenv("DATABASE_ADMIN_URL")
	defer os.Unsetenv("JWT_SECRET")
	defer os.Unsetenv("BAS_APP_DB_PASSWORD")

	cfg, err := Load("/nonexistent/config.json")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.AppDBPassword != "rotated-password" {
		t.Errorf("AppDBPassword = %q, want the env value", cfg.AppDBPassword)
	}
}

func TestLoad_CSPMode(t *testing.T) {
	t.Setenv("DATABASE_URL", "postgres://test")
	t.Setenv("DATABASE_ADMIN_URL", "postgres://test-admin")
	t.Setenv("BAS_APP_DB_PASSWORD", "test-app-password")
	t.Setenv("JWT_SECRET", "test-secret-32-bytes-long-enough")
	for _, tc := range []struct {
		env, want string
		wantErr   bool
	}{
		{"", "enforce", false},
		{"enforce", "enforce", false},
		{"report-only", "report-only", false},
		{" Report-Only ", "report-only", false},
		{"ENFORCE", "enforce", false},
		{"off", "", true},
		{"none", "", true},
		{"reportonly", "", true},
	} {
		t.Run(tc.env, func(t *testing.T) {
			t.Setenv("BAS_CSP_MODE", tc.env)
			cfg, err := Load("/nonexistent/config.json")
			if tc.wantErr {
				if err == nil || !strings.Contains(err.Error(), "BAS_CSP_MODE") {
					t.Fatalf("Load() err = %v, want a BAS_CSP_MODE error", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("Load() err = %v", err)
			}
			if cfg.CSPMode != tc.want {
				t.Fatalf("CSPMode = %q, want %q", cfg.CSPMode, tc.want)
			}
		})
	}
}
