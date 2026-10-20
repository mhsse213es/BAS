// Package detect is a deterministic, vendor-neutral detection fixture. It accepts
// normalised security events, evaluates threshold rules modelled on Elastic Security
// detection rules, and produces alerts keyed by correlation ID. It is not a SIEM and
// makes no claim about any live product: every result it produces is labelled with
// Provenance, so it cannot be read as live SIEM validation.
package detect

import (
	"fmt"
	"sort"
)

// Provenance labels every detection result from this package.
const Provenance = "fixture-validated: elastic-security detection fixture; not validated against a live SIEM"

// SourceElastic names the Elastic Security fixture.
const SourceElastic = "elastic-security"

// Event is the normalised shape every adapter ingests. The lab emits events in this shape.
type Event struct {
	Seq           int    `json:"seq"`
	CorrelationID string `json:"correlation_id"`
	Action        string `json:"action"`
	Outcome       string `json:"outcome"`
	Identity      string `json:"identity"`
	Status        int    `json:"status"`
}

var validOutcomes = map[string]bool{"success": true, "failure": true, "throttled": true, "error": true}

// Validate checks the fields every rule relies on.
func (e Event) Validate() error {
	switch {
	case e.Seq <= 0:
		return fmt.Errorf("event seq must be positive, got %d", e.Seq)
	case e.CorrelationID == "":
		return fmt.Errorf("event %d has no correlation_id", e.Seq)
	case e.Action == "":
		return fmt.Errorf("event %d has no action", e.Seq)
	case !validOutcomes[e.Outcome]:
		return fmt.Errorf("event %d has unknown outcome %q", e.Seq, e.Outcome)
	case e.Identity == "":
		return fmt.Errorf("event %d has no identity", e.Seq)
	case e.Status < 100 || e.Status > 599:
		return fmt.Errorf("event %d has invalid status %d", e.Seq, e.Status)
	}
	return nil
}

// Severity orders alerts. Higher values are more severe.
type Severity int

// Severity levels, lowest to highest.
const (
	SeverityLow Severity = iota + 1
	SeverityMedium
	SeverityHigh
	SeverityCritical
)

// ParseSeverity reads a severity name.
func ParseSeverity(name string) (Severity, bool) {
	switch name {
	case "low":
		return SeverityLow, true
	case "medium":
		return SeverityMedium, true
	case "high":
		return SeverityHigh, true
	case "critical":
		return SeverityCritical, true
	}
	return 0, false
}

// Alert is one rule firing for one correlation ID.
type Alert struct {
	RuleID        string
	RuleName      string
	Severity      Severity
	CorrelationID string
	TriggerSeq    int
	Source        string
}

// Rule is a threshold rule: it fires once, on the Threshold-th matching event for a
// correlation ID.
type Rule struct {
	ID        string
	Name      string
	Severity  Severity
	Threshold int
	Match     func(Event) bool
}

// ElasticRules are the fixture's rules, in evaluation order.
var ElasticRules = []Rule{
	{
		ID: "APIBAS-REL-001", Name: "Repeated authentication failures", Severity: SeverityHigh, Threshold: 3,
		Match: func(e Event) bool { return e.Outcome == "failure" && e.Status == 401 },
	},
	{
		ID: "APIBAS-REL-002", Name: "Request throttled", Severity: SeverityMedium, Threshold: 1,
		Match: func(e Event) bool { return e.Outcome == "throttled" },
	},
	{
		ID: "APIBAS-REL-003", Name: "Server fault on request path", Severity: SeverityLow, Threshold: 1,
		Match: func(e Event) bool { return e.Outcome == "error" },
	},
}

// Adapter is the vendor-neutral surface. Microsoft Sentinel, Splunk and QRadar
// adapters would implement the same three methods.
type Adapter interface {
	Name() string
	Ingest(events []Event) error
	Alerts(correlationID string) []Alert
}

// ElasticFixture evaluates ElasticRules over ingested events.
type ElasticFixture struct {
	events []Event
}

// NewElasticFixture returns an empty fixture.
func NewElasticFixture() *ElasticFixture {
	return &ElasticFixture{}
}

// Name implements Adapter.
func (f *ElasticFixture) Name() string { return SourceElastic }

// Ingest validates every event before storing any of them. Sequence numbers must be
// unique, and events are kept in sequence order, so results do not depend on input order.
func (f *ElasticFixture) Ingest(events []Event) error {
	seen := make(map[int]bool, len(f.events)+len(events))
	for _, e := range f.events {
		seen[e.Seq] = true
	}
	for _, e := range events {
		if err := e.Validate(); err != nil {
			return err
		}
		if seen[e.Seq] {
			return fmt.Errorf("duplicate event seq %d", e.Seq)
		}
		seen[e.Seq] = true
	}
	f.events = append(f.events, events...)
	sort.Slice(f.events, func(i, j int) bool { return f.events[i].Seq < f.events[j].Seq })
	return nil
}

// Alerts evaluates every rule over the events for one correlation ID. A rule fires
// once, on its Threshold-th matching event. Events under other correlation IDs never
// count.
func (f *ElasticFixture) Alerts(correlationID string) []Alert {
	var out []Alert
	for _, rule := range ElasticRules {
		count := 0
		for _, e := range f.events {
			if e.CorrelationID != correlationID || !rule.Match(e) {
				continue
			}
			count++
			if count == rule.Threshold {
				out = append(out, Alert{
					RuleID: rule.ID, RuleName: rule.Name, Severity: rule.Severity,
					CorrelationID: correlationID, TriggerSeq: e.Seq, Source: SourceElastic,
				})
			}
		}
	}
	return out
}

// Grade returns "detected" when an alert for the expected rule exists for this
// correlation ID at or above the minimum severity, and "missed" otherwise.
func Grade(alerts []Alert, expectRule string, minSeverity Severity, correlationID string) string {
	for _, a := range alerts {
		if a.RuleID == expectRule && a.CorrelationID == correlationID && a.Severity >= minSeverity {
			return "detected"
		}
	}
	return "missed"
}
