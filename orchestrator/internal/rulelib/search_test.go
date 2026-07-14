package rulelib

import "testing"

func TestSearch_FiltersByTechniqueAndBackend(t *testing.T) {
	e := testEngine()
	got := e.Search(SearchFilter{Technique: "T1059.001", Backend: "elastic"})
	if len(got) != 1 || got[0].ID != "AUDRULE-000001" {
		t.Fatalf("Search(technique+backend) = %+v", got)
	}
}

func TestSearch_FiltersBySeverityAndStatus(t *testing.T) {
	e := testEngine()
	got := e.Search(SearchFilter{Severity: "high", Status: "test"})
	if len(got) != 1 || got[0].ID != "AUDRULE-000002" {
		t.Fatalf("Search(severity+status) = %+v", got)
	}
}

func TestSearch_FreeTextTitleMatch(t *testing.T) {
	e := testEngine()
	got := e.Search(SearchFilter{Query: "kerberoast"})
	if len(got) != 1 || got[0].ID != "AUDRULE-000002" {
		t.Fatalf("Search(query=kerberoast) = %+v, want case-insensitive title match", got)
	}
}

func TestSearch_NoFilters_ReturnsEverything(t *testing.T) {
	e := testEngine()
	if got := e.Search(SearchFilter{}); len(got) != 2 {
		t.Fatalf("Search(no filters) = %d rules, want 2", len(got))
	}
}
