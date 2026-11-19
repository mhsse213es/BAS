package api

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/audspect/bas/internal/dbsim"
)

func TestDBSimGrantPolicyAppliesOnlyToItsTarget(t *testing.T) {
	file := filepath.Join(t.TempDir(), "policy.json")
	if err := os.WriteFile(file, []byte(`{"source":"test policy","roles":{"app":{"allow":{"t":["SELECT"]}}}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(envDBSimPolicyFile, file)
	t.Setenv(envDBSimPolicyTarget, "lab-db")
	src := loadDBSimGrantSource()
	if src == nil {
		t.Fatal("policy not loaded from the bound file")
	}
	if _, ok := src.dbsimGrantPolicy(dbsim.RunJob{}, dbsim.TargetRecord{TargetRegistration: dbsim.TargetRegistration{ID: "lab-db"}}); !ok {
		t.Error("the bound target gets no policy")
	}
	if _, ok := src.dbsimGrantPolicy(dbsim.RunJob{}, dbsim.TargetRecord{TargetRegistration: dbsim.TargetRegistration{ID: "other-db"}}); ok {
		t.Error("a different target received the policy")
	}
}

func TestDBSimGrantPolicyFailsClosed(t *testing.T) {
	t.Setenv(envDBSimPolicyFile, "")
	t.Setenv(envDBSimPolicyTarget, "")
	if src := loadDBSimGrantSource(); src != nil {
		t.Fatal("no policy must load when the variables are unset")
	}
	file := filepath.Join(t.TempDir(), "bad.json")
	if err := os.WriteFile(file, []byte(`{"roles":{}}`), 0o600); err != nil { // no source: refused
		t.Fatal(err)
	}
	t.Setenv(envDBSimPolicyFile, file)
	t.Setenv(envDBSimPolicyTarget, "lab-db")
	if src := loadDBSimGrantSource(); src != nil {
		t.Fatal("an unnamed policy must be refused")
	}
	var nilSrc *dbsimGrantSource
	if _, ok := nilSrc.dbsimGrantPolicy(dbsim.RunJob{}, dbsim.TargetRecord{TargetRegistration: dbsim.TargetRegistration{ID: "lab-db"}}); ok {
		t.Fatal("a nil source must give no policy")
	}
}
