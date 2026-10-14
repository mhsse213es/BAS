package networkefficacy

import (
	"strings"
	"testing"
	"time"
)

const sampleEVE = `{"timestamp":"2026-10-14T10:00:00.000000+0000","event_type":"flow","src_ip":"10.0.1.5","dest_ip":"10.0.2.5"}
{"timestamp":"2026-10-14T10:00:05.000000+0000","event_type":"alert","src_ip":"10.0.1.5","src_port":51000,"dest_ip":"10.0.2.5","dest_port":443,"proto":"TCP","alert":{"signature":"ET SCAN Suspicious inbound","severity":2}}
{"timestamp":"2026-10-14T10:00:06.000000+0000","event_type":"alert","src_ip":"192.168.9.9","src_port":51000,"dest_ip":"192.168.9.10","dest_port":22,"proto":"TCP","alert":{"signature":"ET SCAN unrelated","severity":3}}
`

func TestParseSuricataEVE_ExtractsOnlyAlertEvents(t *testing.T) {
	records, err := ParseSuricataEVE(strings.NewReader(sampleEVE))
	if err != nil {
		t.Fatalf("ParseSuricataEVE: %v", err)
	}
	if len(records) != 2 {
		t.Fatalf("got %d records, want 2 -- the \"flow\" event_type line must be skipped", len(records))
	}
	if records[0].AlertName != "ET SCAN Suspicious inbound" || records[0].DestIP != "10.0.2.5" || records[0].Port != 443 {
		t.Fatalf("got %+v, fields not extracted correctly", records[0])
	}
}

func TestParseSuricataEVE_MalformedLineErrors(t *testing.T) {
	bad := `{"timestamp":"2026-10-14T10:00:00.000000+0000","event_type":"alert"` // truncated JSON
	if _, err := ParseSuricataEVE(strings.NewReader(bad)); err == nil {
		t.Fatal("want an error for malformed EVE JSON, not a silently empty result")
	}
}

func TestParseSuricataEVE_EmptyInputReturnsEmptyNotError(t *testing.T) {
	records, err := ParseSuricataEVE(strings.NewReader(""))
	if err != nil {
		t.Fatalf("ParseSuricataEVE: %v", err)
	}
	if len(records) != 0 {
		t.Fatalf("got %d records, want 0", len(records))
	}
}

func TestFixtureIDSProvider_ReturnsMatchingAlert(t *testing.T) {
	records, err := ParseSuricataEVE(strings.NewReader(sampleEVE))
	if err != nil {
		t.Fatalf("ParseSuricataEVE: %v", err)
	}
	p := NewFixtureIDSProvider(records)
	flow := Flow{SourceCIDR: "10.0.1.0/24", DestCIDR: "10.0.2.0/24", Port: 443, Protocol: "tcp"}
	ts, _ := time.Parse(time.RFC3339, "2026-10-14T10:00:05Z")
	window := TimeWindow{Start: ts.Add(-time.Minute), End: ts.Add(time.Minute)}
	got, err := p.IDSEvidenceFor(flow, window)
	if err != nil {
		t.Fatalf("IDSEvidenceFor: %v", err)
	}
	if len(got) != 1 || got[0].AlertName != "ET SCAN Suspicious inbound" {
		t.Fatalf("got %+v, want exactly the one alert matching this flow -- the unrelated 192.168.x alert must not match", got)
	}
}
