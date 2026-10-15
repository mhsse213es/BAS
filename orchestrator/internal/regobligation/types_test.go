package regobligation

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestObligationTypeConstants_HaveExpectedStringValues(t *testing.T) {
	cases := map[ObligationType]string{
		ObligationMandatory:   "mandatory",
		ObligationGuidance:    "guidance",
		ObligationContractual: "contractual",
		ObligationRecommended: "recommended",
	}
	for constant, want := range cases {
		if string(constant) != want {
			t.Errorf("expected %q, got %q", want, string(constant))
		}
	}
}

func TestSnapshotStatusConstants_HaveExpectedStringValues(t *testing.T) {
	if string(SnapshotCaptured) != "captured" {
		t.Errorf(`expected "captured", got %q`, string(SnapshotCaptured))
	}
	if string(SnapshotIncomplete) != "incomplete" {
		t.Errorf(`expected "incomplete", got %q`, string(SnapshotIncomplete))
	}
}

func TestObligation_JSONRoundTrip_PreservesControlMappings(t *testing.T) {
	ob := Obligation{
		ID: "ob-1", Jurisdiction: "India", Regulator: "RBI", Title: "Test obligation",
		ObligationType: ObligationMandatory, SourceReference: "RBI CSF", Version: "v1",
		EffectiveDate: time.Date(2016, 6, 2, 0, 0, 0, 0, time.UTC),
		ControlMappings: []ControlMapping{
			{CanonicalID: "cm-1", ControlName: "Segmentation", CapabilityName: "zoneisolation.isolation-check"},
		},
	}
	data, err := json.Marshal(ob)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !strings.Contains(string(data), `"controlMappings"`) {
		t.Errorf("expected controlMappings field in JSON, got %s", data)
	}
	var roundTripped Obligation
	if err := json.Unmarshal(data, &roundTripped); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(roundTripped.ControlMappings) != 1 || roundTripped.ControlMappings[0].CapabilityName != "zoneisolation.isolation-check" {
		t.Errorf("control mappings did not round-trip: %+v", roundTripped.ControlMappings)
	}
}

func TestEvidenceSnapshot_JSONRoundTrip_PreservesImportReferences(t *testing.T) {
	es := EvidenceSnapshot{
		ID: "es-1", ObligationID: "ob-1", ControlMappingID: "cm-1", CapabilityName: "zoneisolation.isolation-check",
		ImportReferences: map[string]string{"topologyImportId": "topo-1", "isolationImportId": "iso-1"},
		Status:           SnapshotCaptured, CapturedOutcome: "confirmed-violation", CapturedAt: time.Now().UTC(),
	}
	data, err := json.Marshal(es)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !strings.Contains(string(data), `"obligationId"`) || !strings.Contains(string(data), `"controlMappingId"`) {
		t.Errorf("expected obligationId and controlMappingId fields in JSON, got %s", data)
	}
	var roundTripped EvidenceSnapshot
	if err := json.Unmarshal(data, &roundTripped); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if roundTripped.ImportReferences["topologyImportId"] != "topo-1" {
		t.Errorf("import references did not round-trip: %+v", roundTripped.ImportReferences)
	}
}
