package search

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/compliance"
	"github.com/audspect/bas/internal/rulelib"
	"github.com/audspect/bas/internal/scenario"
)

func TestScenariosFrom_MapsNameTagsDescription(t *testing.T) {
	tmpDir := t.TempDir()
	customDir := filepath.Join(tmpDir, "custom")
	if err := os.MkdirAll(customDir, 0o755); err != nil {
		t.Fatalf("mkdir custom: %v", err)
	}
	yaml := `id: test-art-scenario
name: Atomic Red Team PowerShell
description: Runs ART PowerShell techniques
tags: [art, powershell]
mitre_phases: [execution]
`
	if err := os.WriteFile(filepath.Join(customDir, "test.yaml"), []byte(yaml), 0o644); err != nil {
		t.Fatalf("write test scenario: %v", err)
	}

	engine := scenario.NewEngine(tmpDir)
	if err := engine.Load(); err != nil {
		t.Fatalf("engine.Load: %v", err)
	}

	docs := scenariosFrom(engine)
	if len(docs) != 1 {
		t.Fatalf("scenariosFrom() = %+v, want 1 document", docs)
	}
	d := docs[0]
	if d.DocType != "scenario" || d.SourceID != "test-art-scenario" || d.Title != "Atomic Red Team PowerShell" {
		t.Fatalf("document = %+v, want DocType=scenario SourceID=test-art-scenario Title=%q", d, "Atomic Red Team PowerShell")
	}
	if d.Description != "Runs ART PowerShell techniques" {
		t.Errorf("Description = %q, want %q", d.Description, "Runs ART PowerShell techniques")
	}
	hasArt, hasExecution := false, false
	for _, tag := range d.Tags {
		if tag == "art" {
			hasArt = true
		}
		if tag == "execution" {
			hasExecution = true
		}
	}
	if !hasArt || !hasExecution {
		t.Errorf("Tags = %v, want to include both %q (from tags:) and %q (from mitre_phases:)", d.Tags, "art", "execution")
	}
}

func TestRulesFrom_MapsRealEmbeddedRules(t *testing.T) {
	engine := rulelib.NewEngine()
	docs := rulesFrom(engine)
	if len(docs) != engine.RuleCount() {
		t.Fatalf("rulesFrom() returned %d documents, want %d (engine.RuleCount())", len(docs), engine.RuleCount())
	}

	var found bool
	for _, d := range docs {
		if d.SourceID != "AUDRULE-000001" {
			continue
		}
		found = true
		if d.DocType != "rule" {
			t.Errorf("DocType = %q, want %q", d.DocType, "rule")
		}
		if d.Title != "Suspicious PowerShell Encoded Command" {
			t.Errorf("Title = %q, want %q", d.Title, "Suspicious PowerShell Encoded Command")
		}
		if d.Description != "Detects encoded PowerShell command execution" {
			t.Errorf("Description = %q, want %q", d.Description, "Detects encoded PowerShell command execution")
		}
		hasTechnique, hasSeverity := false, false
		for _, tag := range d.Tags {
			if tag == "T1059.001" {
				hasTechnique = true
			}
			if tag == "medium" {
				hasSeverity = true
			}
		}
		if !hasTechnique {
			t.Errorf("Tags = %v, want to include technique %q", d.Tags, "T1059.001")
		}
		if !hasSeverity {
			t.Errorf("Tags = %v, want to include severity %q", d.Tags, "medium")
		}
	}
	if !found {
		t.Fatal("rulesFrom() did not include AUDRULE-000001 -- check the embedded rule bundle in internal/rulelib/ruledata/rules.json")
	}
}

func TestComplianceControlsFrom_NilMapperReturnsNoDocuments(t *testing.T) {
	docs := complianceControlsFrom(nil)
	if len(docs) != 0 {
		t.Fatalf("complianceControlsFrom(nil) = %+v, want no documents", docs)
	}
}

func TestComplianceControlsFrom_MapsRealFrameworkControls(t *testing.T) {
	mapper, err := compliance.NewMapper()
	if err != nil {
		t.Fatalf("compliance.NewMapper: %v", err)
	}
	docs := complianceControlsFrom(mapper)
	if len(docs) != len(mapper.AllControls()) {
		t.Fatalf("complianceControlsFrom() returned %d documents, want %d (len(mapper.AllControls()))", len(docs), len(mapper.AllControls()))
	}

	first := mapper.AllControls()[0]
	wantSourceID := first.FrameworkID + ":" + first.Control.ID
	var found bool
	for _, d := range docs {
		if d.SourceID != wantSourceID {
			continue
		}
		found = true
		if d.DocType != "compliance_control" {
			t.Errorf("DocType = %q, want %q", d.DocType, "compliance_control")
		}
		if d.Title != first.Control.Name {
			t.Errorf("Title = %q, want %q", d.Title, first.Control.Name)
		}
		hasFramework := false
		for _, tag := range d.Tags {
			if tag == first.FrameworkID {
				hasFramework = true
			}
		}
		if !hasFramework {
			t.Errorf("Tags = %v, want to include framework ID %q", d.Tags, first.FrameworkID)
		}
	}
	if !found {
		t.Fatalf("complianceControlsFrom() did not include namespaced SourceID %q", wantSourceID)
	}
}

func TestDetectionConnectorsFrom_MapsNameProviderNeverSecrets(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		if _, err := pool.Exec(ctx,
			`INSERT INTO detection_connectors (id, name, provider, client_secret, api_token)
			 VALUES ('dc-1', 'Prod Sentinel', 'microsoft_sentinel', 'super-secret-value', 'super-secret-token')`); err != nil {
			t.Fatalf("seed detection_connectors: %v", err)
		}

		docs, err := detectionConnectorsFrom(ctx, pool)
		if err != nil {
			t.Fatalf("detectionConnectorsFrom: %v", err)
		}
		if len(docs) != 1 {
			t.Fatalf("detectionConnectorsFrom() = %+v, want 1 document", docs)
		}
		d := docs[0]
		if d.DocType != "detection_connector" || d.SourceID != "dc-1" || d.Title != "Prod Sentinel" {
			t.Fatalf("document = %+v, want DocType=detection_connector SourceID=dc-1 Title=%q", d, "Prod Sentinel")
		}
		if strings.Contains(d.Description, "super-secret") || strings.Contains(strings.Join(d.Tags, " "), "super-secret") {
			t.Fatalf("document leaked a secret value: %+v", d)
		}
		if d.Description != "provider: microsoft_sentinel" {
			t.Errorf("Description = %q, want %q", d.Description, "provider: microsoft_sentinel")
		}
	})
}

func TestActionConnectorsFrom_MapsNameProviderNeverSecrets(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		if _, err := pool.Exec(ctx,
			`INSERT INTO action_connectors (id, name, provider, client_secret)
			 VALUES ('ac-1', 'Prod CrowdStrike', 'crowdstrike', 'super-secret-value')`); err != nil {
			t.Fatalf("seed action_connectors: %v", err)
		}

		docs, err := actionConnectorsFrom(ctx, pool)
		if err != nil {
			t.Fatalf("actionConnectorsFrom: %v", err)
		}
		if len(docs) != 1 {
			t.Fatalf("actionConnectorsFrom() = %+v, want 1 document", docs)
		}
		d := docs[0]
		if d.DocType != "action_connector" || d.SourceID != "ac-1" || d.Title != "Prod CrowdStrike" {
			t.Fatalf("document = %+v, want DocType=action_connector SourceID=ac-1 Title=%q", d, "Prod CrowdStrike")
		}
		if strings.Contains(d.Description, "super-secret") || strings.Contains(strings.Join(d.Tags, " "), "super-secret") {
			t.Fatalf("document leaked a secret value: %+v", d)
		}
	})
}
