package connector

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/audspect/bas/internal/evidence"
)

func TestBundleSource_Fetch_CompletenessCompleteOnSuccess(t *testing.T) {
	dir := t.TempDir()
	bundle := Bundle{Version: "v1", GeneratedAt: time.Now(), Actors: []ThreatActor{
		{Name: "APT-bundle", Techniques: []TechniqueRef{{ID: "T1059"}, {ID: "T1055"}}},
	}}
	data, err := json.Marshal(bundle)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, BundleFileName), data, 0644); err != nil {
		t.Fatal(err)
	}

	b := NewBundleSource(dir, nil)
	if _, err := b.Fetch(); err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	report := b.Completeness()
	if report.Completeness != evidence.Complete {
		t.Fatalf("Completeness() = %+v, want Complete", report)
	}
}
