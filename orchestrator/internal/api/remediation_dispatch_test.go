package api

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/ws"
)

func TestEligibleForBASVerification_HasTechniqueID(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		registerFixtureScenario(t, h.engine, "windows-firewall-enabled")
		if !h.EligibleForBASVerification("windows-firewall-enabled") {
			t.Error("expected windows-firewall-enabled to be eligible -- its fixture step has a TechniqueID")
		}
	})
}

func TestEligibleForBASVerification_NoTechniqueID(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		dir := t.TempDir()
		// Written directly under <dir>/custom/ and loaded via Load(), not
		// Save() -- Save() calls Scenario.Validate(), which requires every
		// step to declare a technique_id, and this fixture deliberately
		// omits one (mirroring windows-bitlocker-enabled's real, honest
		// lack of an ATT&CK mapping). Load() never calls Validate(), and
		// "custom"-sourced files skip signature verification too.
		customDir := filepath.Join(dir, "custom")
		if err := os.MkdirAll(customDir, 0o755); err != nil {
			t.Fatalf("mkdir custom dir: %v", err)
		}
		content := "id: fixture-no-technique\n" +
			"name: Fixture No Technique\n" +
			"local_check: true\n" +
			"steps:\n" +
			"  - name: \"No Technique Check\"\n" +
			"    check_id: windows-bitlocker-enabled\n" +
			"    framework: custom\n" +
			"    executor: local\n" +
			"    command: \"echo PASS\"\n" +
			"    timeout_sec: 10\n"
		if err := os.WriteFile(filepath.Join(customDir, "fixture-no-technique.yaml"), []byte(content), 0o644); err != nil {
			t.Fatalf("write fixture: %v", err)
		}

		eng := scenario.NewEngine(dir)
		if err := eng.Load(); err != nil {
			t.Fatalf("engine.Load: %v", err)
		}
		h := New(pool, ws.NewHub(), eng, "")
		if h.EligibleForBASVerification("windows-bitlocker-enabled") {
			t.Error("expected windows-bitlocker-enabled NOT to be eligible -- no TechniqueID")
		}
	})
}

func TestEligibleForBASVerification_UnknownCheckID(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		if h.EligibleForBASVerification("no-such-check") {
			t.Error("expected an unknown check_id NOT to be eligible")
		}
	})
}
