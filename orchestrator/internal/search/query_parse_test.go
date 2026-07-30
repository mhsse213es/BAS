package search

import (
	"reflect"
	"testing"
)

func TestParseQuery_TypeFilterPlusFreeText(t *testing.T) {
	pq := ParseQuery("type:scenario ransomware")
	if pq.FreeText != "ransomware" {
		t.Errorf("FreeText = %q, want %q", pq.FreeText, "ransomware")
	}
	if pq.DocType != "scenario" {
		t.Errorf("DocType = %q, want %q", pq.DocType, "scenario")
	}
	if len(pq.InvalidFilters) != 0 {
		t.Errorf("InvalidFilters = %+v, want none", pq.InvalidFilters)
	}
}

func TestParseQuery_PluralTypeValueNormalizes(t *testing.T) {
	pq := ParseQuery("type:scenarios")
	if pq.DocType != "scenario" {
		t.Errorf("DocType = %q, want %q (plural normalized to singular)", pq.DocType, "scenario")
	}
}

func TestParseQuery_UnknownTypeValueIgnoredAndRecorded(t *testing.T) {
	pq := ParseQuery("type:bogus ransomware")
	if pq.FreeText != "ransomware" {
		t.Errorf("FreeText = %q, want %q", pq.FreeText, "ransomware")
	}
	if pq.DocType != "" {
		t.Errorf("DocType = %q, want empty (bogus value must not apply)", pq.DocType)
	}
	want := []InvalidFilter{{Name: "type", Value: "bogus"}}
	if !reflect.DeepEqual(pq.InvalidFilters, want) {
		t.Errorf("InvalidFilters = %+v, want %+v", pq.InvalidFilters, want)
	}
}

func TestParseQuery_UnsupportedFieldIgnoredAndRecorded(t *testing.T) {
	pq := ParseQuery("status:failed type:run")
	if pq.DocType != "run" {
		t.Errorf("DocType = %q, want %q", pq.DocType, "run")
	}
	want := []InvalidFilter{{Name: "status", Value: "failed"}}
	if !reflect.DeepEqual(pq.InvalidFilters, want) {
		t.Errorf("InvalidFilters = %+v, want %+v (status is not yet a supported operator)", pq.InvalidFilters, want)
	}
}

func TestParseQuery_DuplicateFieldRejectedNotLastWins(t *testing.T) {
	pq := ParseQuery("type:scenario type:actor ransomware")
	if pq.DocType != "" {
		t.Errorf("DocType = %q, want empty (duplicate type: filters must both be rejected)", pq.DocType)
	}
	if pq.FreeText != "ransomware" {
		t.Errorf("FreeText = %q, want %q", pq.FreeText, "ransomware")
	}
	if len(pq.InvalidFilters) != 1 || pq.InvalidFilters[0].Name != "type" {
		t.Fatalf("InvalidFilters = %+v, want exactly one entry for the duplicated \"type\" field", pq.InvalidFilters)
	}
}

func TestParseQuery_TypeOnlyNoFreeText(t *testing.T) {
	pq := ParseQuery("type:scenario")
	if pq.FreeText != "" {
		t.Errorf("FreeText = %q, want empty", pq.FreeText)
	}
	if pq.DocType != "scenario" {
		t.Errorf("DocType = %q, want %q", pq.DocType, "scenario")
	}
}

func TestParseQuery_NewDocTypesRecognized(t *testing.T) {
	cases := []struct {
		raw      string
		wantType string
	}{
		{"type:rule sigma", "rule"},
		{"type:compliance_control", "compliance_control"},
		{"type:detection_connector", "detection_connector"},
		{"type:action_connector", "action_connector"},
	}
	for _, tc := range cases {
		got := ParseQuery(tc.raw)
		if got.DocType != tc.wantType {
			t.Errorf("ParseQuery(%q).DocType = %q, want %q", tc.raw, got.DocType, tc.wantType)
		}
		if len(got.InvalidFilters) != 0 {
			t.Errorf("ParseQuery(%q).InvalidFilters = %+v, want none", tc.raw, got.InvalidFilters)
		}
	}
}

func TestParseQuery_EmptyInput(t *testing.T) {
	pq := ParseQuery("")
	if pq.FreeText != "" || pq.DocType != "" || len(pq.InvalidFilters) != 0 {
		t.Errorf("ParseQuery(\"\") = %+v, want all zero values", pq)
	}
}
