package detect

import (
	"reflect"
	"testing"
)

func ev(seq int, corr, outcome string, status int) Event {
	return Event{Seq: seq, CorrelationID: corr, Action: "GET /x", Outcome: outcome, Identity: "customer-b", Status: status}
}

func TestIngestRejectsInvalidEvents(t *testing.T) {
	bad := []Event{
		{Seq: 0, CorrelationID: "c", Action: "a", Outcome: "failure", Identity: "i", Status: 401},
		{Seq: 1, CorrelationID: "", Action: "a", Outcome: "failure", Identity: "i", Status: 401},
		{Seq: 2, CorrelationID: "c", Action: "a", Outcome: "bogus", Identity: "i", Status: 401},
		{Seq: 3, CorrelationID: "c", Action: "a", Outcome: "failure", Identity: "", Status: 401},
		{Seq: 4, CorrelationID: "c", Action: "a", Outcome: "failure", Identity: "i", Status: 42},
	}
	for _, e := range bad {
		if err := NewElasticFixture().Ingest([]Event{e}); err == nil {
			t.Errorf("event %+v accepted, want rejection", e)
		}
	}
}

func TestIngestRejectsDuplicateSeq(t *testing.T) {
	f := NewElasticFixture()
	if err := f.Ingest([]Event{ev(1, "c", "success", 200)}); err != nil {
		t.Fatal(err)
	}
	if err := f.Ingest([]Event{ev(1, "c", "failure", 401)}); err == nil {
		t.Fatal("duplicate seq accepted")
	}
}

func TestRepeatedFailuresFireOnThirdOnly(t *testing.T) {
	f := NewElasticFixture()
	_ = f.Ingest([]Event{ev(1, "c", "failure", 401), ev(2, "c", "failure", 401)})
	if n := len(f.Alerts("c")); n != 0 {
		t.Fatalf("two failures produced %d alerts, want 0", n)
	}
	_ = f.Ingest([]Event{ev(3, "c", "failure", 401)})
	alerts := f.Alerts("c")
	if len(alerts) != 1 || alerts[0].RuleID != "APIBAS-REL-001" || alerts[0].TriggerSeq != 3 {
		t.Fatalf("alerts = %+v, want one APIBAS-REL-001 triggered at seq 3", alerts)
	}
}

func TestCorrelationIsolation(t *testing.T) {
	f := NewElasticFixture()
	_ = f.Ingest([]Event{ev(1, "run-a", "failure", 401), ev(2, "run-a", "failure", 401), ev(3, "run-b", "failure", 401)})
	if n := len(f.Alerts("run-a")); n != 0 {
		t.Fatalf("run-a got %d alerts from run-b's event", n)
	}
}

func TestThrottledFiresOnFirst(t *testing.T) {
	f := NewElasticFixture()
	_ = f.Ingest([]Event{ev(1, "c", "throttled", 429)})
	if alerts := f.Alerts("c"); len(alerts) != 1 || alerts[0].RuleID != "APIBAS-REL-002" {
		t.Fatalf("alerts = %+v, want APIBAS-REL-002", alerts)
	}
}

func TestGradeHonoursSeverityAndCorrelation(t *testing.T) {
	alerts := []Alert{{RuleID: "APIBAS-REL-002", Severity: SeverityMedium, CorrelationID: "c"}}
	if got := Grade(alerts, "APIBAS-REL-002", SeverityHigh, "c"); got != "missed" {
		t.Errorf("medium alert against high minimum = %s, want missed", got)
	}
	if got := Grade(alerts, "APIBAS-REL-002", SeverityMedium, "other"); got != "missed" {
		t.Errorf("alert for another correlation = %s, want missed", got)
	}
	if got := Grade(alerts, "APIBAS-REL-002", SeverityMedium, "c"); got != "detected" {
		t.Errorf("matching alert = %s, want detected", got)
	}
}

func TestAlertsAreDeterministic(t *testing.T) {
	events := []Event{ev(1, "c", "failure", 401), ev(2, "c", "throttled", 429), ev(3, "c", "failure", 401), ev(4, "c", "failure", 401)}
	a := NewElasticFixture()
	_ = a.Ingest(events)
	b := NewElasticFixture()
	_ = b.Ingest([]Event{events[3], events[1], events[0], events[2]})
	if !reflect.DeepEqual(a.Alerts("c"), b.Alerts("c")) {
		t.Fatal("alerts depend on ingestion order")
	}
}

func TestParseSeverity(t *testing.T) {
	if s, ok := ParseSeverity("high"); !ok || s != SeverityHigh {
		t.Fatalf("high = %v %v", s, ok)
	}
	if _, ok := ParseSeverity("urgent"); ok {
		t.Fatal("unknown severity accepted")
	}
}
