package search

import (
	"os"
	"path/filepath"
	"testing"

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
