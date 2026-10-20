package detect

import "fmt"

// SourceSentinel names the Microsoft Sentinel fixture.
const SourceSentinel = "microsoft-sentinel"

// SentinelProvenance labels every detection result from the Sentinel fixture. It is a
// fixture result: no live Sentinel workspace was queried.
const SentinelProvenance = "fixture-validated: microsoft-sentinel detection fixture; not validated against a live Sentinel workspace"

// ProvenanceFor returns the provenance label for a detection source.
func ProvenanceFor(source string) string {
	if source == SourceSentinel {
		return SentinelProvenance
	}
	return Provenance
}

// SentinelRecord is one row as a Sentinel fixture receives it. The field names follow
// the Log Analytics security-table columns the rules need. Only those columns are
// modelled.
type SentinelRecord struct {
	RowSeq         int    `json:"RowSeq"`
	CorrelationId  string `json:"CorrelationId"`
	OperationName  string `json:"OperationName"`
	Caller         string `json:"Caller"`
	HttpStatusCode int    `json:"HttpStatusCode"`
	ResourceOwner  string `json:"ResourceOwner,omitempty"`
}

// Normalize maps a Sentinel row onto the shared event shape and validates it. The
// outcome follows the HTTP status, the same way the lab's own events are classified.
func (r SentinelRecord) Normalize() (Event, error) {
	if r.HttpStatusCode == 0 {
		return Event{}, fmt.Errorf("sentinel row %d has no HttpStatusCode", r.RowSeq)
	}
	e := Event{
		Seq:           r.RowSeq,
		CorrelationID: r.CorrelationId,
		Action:        r.OperationName,
		Outcome:       outcomeForStatus(r.HttpStatusCode),
		Identity:      r.Caller,
		Status:        r.HttpStatusCode,
		ObjectOwner:   r.ResourceOwner,
	}
	return e, e.Validate()
}

// ToSentinelRecord is the inverse mapping. Sentinel's record has one owner column, so only the first owner
// (ObjectOwner) is written. An event naming a second foreign owner is not fully represented here. No scenario
// routes through Sentinel today; widening the record needs its own change., used when a shared event must be fed to the
// Sentinel fixture. It keeps every column the rules read.
func ToSentinelRecord(e Event) SentinelRecord {
	return SentinelRecord{
		RowSeq:         e.Seq,
		CorrelationId:  e.CorrelationID,
		OperationName:  e.Action,
		Caller:         e.Identity,
		HttpStatusCode: e.Status,
		ResourceOwner:  e.ObjectOwner,
	}
}

func outcomeForStatus(status int) string {
	switch {
	case status == 429:
		return "throttled"
	case status >= 500:
		return "error"
	case status >= 400:
		return "failure"
	}
	return "success"
}

// SentinelFixture applies the shared rule set to Sentinel rows. Its alerts are
// labelled with the Sentinel source, so a report can never mistake one for the other.
type SentinelFixture struct {
	events []Event
}

// NewSentinelFixture returns an empty Sentinel fixture.
func NewSentinelFixture() *SentinelFixture {
	return &SentinelFixture{}
}

// Name implements Adapter.
func (f *SentinelFixture) Name() string { return SourceSentinel }

// Ingest implements Adapter for already-normalised events.
func (f *SentinelFixture) Ingest(events []Event) error {
	return ingestInto(&f.events, events)
}

// IngestRecords normalises and validates Sentinel rows, then stores them. If any row
// is invalid, nothing is stored.
func (f *SentinelFixture) IngestRecords(records []SentinelRecord) error {
	events := make([]Event, 0, len(records))
	for _, r := range records {
		e, err := r.Normalize()
		if err != nil {
			return err
		}
		events = append(events, e)
	}
	return f.Ingest(events)
}

// Alerts implements Adapter. The rules are the same ones the Elastic fixture uses.
func (f *SentinelFixture) Alerts(correlationID string) []Alert {
	return evaluate(f.events, ElasticRules, correlationID, SourceSentinel)
}
