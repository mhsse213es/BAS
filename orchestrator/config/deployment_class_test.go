package config

import (
	"encoding/json"
	"testing"

	"github.com/audspect/bas/internal/injectionapproval"
)

func loadWithClass(t *testing.T, value string, set bool) injectionapproval.Classification {
	t.Helper()
	t.Setenv("DATABASE_URL", "postgres://test")
	t.Setenv("DATABASE_ADMIN_URL", "postgres://test-admin")
	t.Setenv("BAS_APP_DB_PASSWORD", "test-app-password")
	t.Setenv("JWT_SECRET", "test-secret-32-bytes-long-enough")
	if set {
		t.Setenv("BAS_DEPLOYMENT_CLASS", value)
	} else {
		t.Setenv("BAS_DEPLOYMENT_CLASS", "")
	}
	cfg, err := Load("/nonexistent/config.json")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	return cfg.Classification()
}

// The deployment class defaults to customer, the stricter class, unless it is exactly "lab".
func TestLoad_DeploymentClassDefaultsToCustomer(t *testing.T) {
	cases := []struct {
		name  string
		value string
		set   bool
		want  injectionapproval.Classification
	}{
		{"unset", "", false, injectionapproval.Customer},
		{"empty", "", true, injectionapproval.Customer},
		{"explicit customer", "customer", true, injectionapproval.Customer},
		{"lab", "lab", true, injectionapproval.Lab},
		{"lab with surrounding space", "  lab  ", true, injectionapproval.Lab},
		{"upper case is not lab", "LAB", true, injectionapproval.Customer},
		{"misspelling is not lab", "labb", true, injectionapproval.Customer},
		{"unknown value", "production", true, injectionapproval.Customer},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := loadWithClass(t, c.value, c.set); got != c.want {
				t.Fatalf("BAS_DEPLOYMENT_CLASS=%q (set=%v): got %q, want %q", c.value, c.set, got, c.want)
			}
		})
	}
}

// A config file cannot declare the deployment a lab: the field is not read from JSON.
func TestDeploymentClass_NotReadFromConfigFile(t *testing.T) {
	cfg := &Config{}
	if err := json.Unmarshal([]byte(`{"deployment_class":"lab","DeploymentClass":"lab"}`), cfg); err != nil {
		t.Fatal(err)
	}
	if cfg.Classification() != injectionapproval.Customer {
		t.Fatal("a config file declared the deployment a lab")
	}
}
