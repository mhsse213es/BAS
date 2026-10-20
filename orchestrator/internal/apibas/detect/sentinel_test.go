package detect

import (
	"reflect"
	"testing"
)

func row(seq int, corr string, status int) SentinelRecord {
	return SentinelRecord{RowSeq: seq, CorrelationId: corr, OperationName: "GET /x", Caller: "customer-b", HttpStatusCode: status}
}

func TestNormalizeMapsStatusToOutcome(t *testing.T) {
	cases := map[int]string{200: "success", 401: "failure", 429: "throttled", 503: "error"}
	for status, want := range cases {
		e, err := row(1, "c", status).Normalize()
		if err != nil {
			t.Fatalf("status %d: %v", status, err)
		}
		if e.Outcome != want {
			t.Errorf("status %d outcome = %s, want %s", status, e.Outcome, want)
		}
	}
}

func TestNormalizeRejectsRowWithoutStatus(t *testing.T) {
	if _, err := row(1, "c", 0).Normalize(); err == nil {
		t.Fatal("row with no HttpStatusCode accepted")
	}
}

func TestSentinelRowsRoundTripThroughRecord(t *testing.T) {
	e := Event{Seq: 3, CorrelationID: "c", Action: "PATCH /x", Outcome: "failure", Identity: "customer-a", Status: 403, ObjectOwner: "customer-b"}
	back, err := ToSentinelRecord(e).Normalize()
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(e, back) {
		t.Fatalf("round trip changed the event: %+v != %+v", back, e)
	}
}

// Same underlying activity, two adapters: the same rules must produce the same alerts,
// differing only in their source label. This is the vendor-neutral check.
func TestSentinelAndElasticProduceSameAlerts(t *testing.T) {
	events := []Event{
		ev(1, "c", "failure", 401), ev(2, "c", "failure", 401), ev(3, "c", "throttled", 429),
		ev(4, "c", "failure", 401), ev(5, "c", "success", 200),
	}
	elastic := NewElasticFixture()
	if err := elastic.Ingest(events); err != nil {
		t.Fatal(err)
	}
	sentinel := NewSentinelFixture()
	var rows []SentinelRecord
	for _, e := range events {
		rows = append(rows, ToSentinelRecord(e))
	}
	if err := sentinel.IngestRecords(rows); err != nil {
		t.Fatal(err)
	}
	ea, sa := elastic.Alerts("c"), sentinel.Alerts("c")
	if len(ea) != len(sa) {
		t.Fatalf("elastic produced %d alerts, sentinel %d", len(ea), len(sa))
	}
	for i := range ea {
		if ea[i].RuleID != sa[i].RuleID || ea[i].TriggerSeq != sa[i].TriggerSeq || ea[i].Severity != sa[i].Severity {
			t.Errorf("alert %d differs: elastic %+v sentinel %+v", i, ea[i], sa[i])
		}
		if sa[i].Source != SourceSentinel || ea[i].Source != SourceElastic {
			t.Errorf("alert %d carries the wrong source label", i)
		}
	}
}

func TestSentinelInvalidRowStoresNothing(t *testing.T) {
	f := NewSentinelFixture()
	err := f.IngestRecords([]SentinelRecord{row(1, "c", 401), row(2, "c", 0)})
	if err == nil {
		t.Fatal("batch with an invalid row accepted")
	}
	if n := len(f.Alerts("c")); n != 0 {
		t.Fatalf("invalid batch left %d alerts", n)
	}
}

func TestSentinelCorrelationIsolation(t *testing.T) {
	f := NewSentinelFixture()
	_ = f.IngestRecords([]SentinelRecord{row(1, "run-a", 401), row(2, "run-a", 401), row(3, "run-b", 401)})
	if n := len(f.Alerts("run-a")); n != 0 {
		t.Fatalf("run-a got %d alerts from run-b's row", n)
	}
}

func TestProvenanceNamesEachSourceAsFixture(t *testing.T) {
	for _, src := range []string{SourceElastic, SourceSentinel} {
		if p := ProvenanceFor(src); p == "" || p[:len("fixture-validated")] != "fixture-validated" {
			t.Errorf("provenance for %s = %q, want fixture-validated label", src, p)
		}
	}
}
