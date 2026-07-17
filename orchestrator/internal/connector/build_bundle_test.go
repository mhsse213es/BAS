package connector

import (
	"errors"
	"testing"
)

func TestBuildBundle_MergesAcrossSources(t *testing.T) {
	sources := []Source{
		fakeSource{name: "bundle", actors: []ThreatActor{
			{Name: "APT36", Source: "bundle", Techniques: []TechniqueRef{{ID: "T1059.001"}}},
		}},
		fakeSource{name: "misp", actors: []ThreatActor{
			{Name: "APT36", Source: "misp", Techniques: []TechniqueRef{{ID: "T1566.001"}}},
			{Name: "Lazarus", Source: "misp", Techniques: []TechniqueRef{{ID: "T1071"}}},
		}},
	}
	b, err := BuildBundle(sources, "v1")
	if err != nil {
		t.Fatalf("BuildBundle: %v", err)
	}
	if b.Version != "v1" {
		t.Fatalf("Version = %q, want v1", b.Version)
	}
	if b.GeneratedAt.IsZero() {
		t.Fatal("GeneratedAt should be set")
	}
	if len(b.Actors) != 2 {
		t.Fatalf("want 2 merged actors, got %d: %+v", len(b.Actors), b.Actors)
	}
	for _, a := range b.Actors {
		if a.Name == "APT36" && len(a.Techniques) != 2 {
			t.Fatalf("APT36 techniques not unioned: %+v", a.Techniques)
		}
	}
}

func TestBuildBundle_NoSources_ReturnsError(t *testing.T) {
	if _, err := BuildBundle(nil, "v1"); err == nil {
		t.Fatal("expected an error for zero sources, not a silently empty bundle")
	}
}

func TestBuildBundle_SourcesReturnNoActors_ReturnsError(t *testing.T) {
	sources := []Source{
		fakeSource{name: "misp"},
		fakeSource{name: "opencti", err: errors.New("connection refused")},
	}
	if _, err := BuildBundle(sources, "v1"); err == nil {
		t.Fatal("expected an error when every source returns zero actors, not a silently empty bundle")
	}
}
