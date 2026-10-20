// Package detect is a deterministic, vendor-neutral detection fixture. It accepts
// normalised security events, evaluates threshold rules modelled on Elastic Security
// detection rules, and produces alerts keyed by correlation ID. It is not a SIEM and
// makes no claim about any live product: every result it produces is labelled with
// Provenance, so it cannot be read as live SIEM validation.
package detect

import (
	"fmt"
	"sort"
	"strings"
)

// Detection results. A result is detected only when a rule fired from delivered events. It is
// not_detected when the events were complete and no rule fired, and inconclusive when the telemetry
// was incomplete, so absence cannot be read as evidence.
const (
	Detected     = "detected"
	NotDetected  = "not_detected"
	Inconclusive = "inconclusive"
)

// Provenance labels every detection result from this package.
const Provenance = "fixture-validated: elastic-security detection fixture; not validated against a live SIEM"

// SourceElastic names the Elastic Security fixture.
const SourceElastic = "elastic-security"

// Event is the normalised shape every adapter ingests. The lab emits events in this shape.
type Event struct {
	// ObjectOwner is the first owner the request named (ObjectOwners[0] when that is set). It is kept
	// for single-owner consumers. Rules that ask about foreign ownership read ObjectOwners, so a
	// request that names a second owner is not judged by the first alone.
	ObjectOwner string `json:"object_owner,omitempty"`
	// ObjectOwners is every distinct owner the request named, in the order the lab found them. Owners
	// are the lab's own identifiers, never text taken from the request. The lab bounds the list.
	ObjectOwners  []string `json:"object_owners,omitempty"`
	Seq           int      `json:"seq"`
	CorrelationID string   `json:"correlation_id"`
	Action        string   `json:"action"`
	Outcome       string   `json:"outcome"`
	Identity      string   `json:"identity"`
	Status        int      `json:"status"`
	// Signature lists the injection-pattern classes the request carried (see Signature* below). It holds
	// classes only, never the text that matched, so a body is never stored through this field.
	Signature []string `json:"signature,omitempty"`
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
	case len(e.ObjectOwners) > maxEventOwners:
		return fmt.Errorf("event %d names %d owners, more than the %d the contract allows", e.Seq, len(e.ObjectOwners), maxEventOwners)
	case hasEmptyOwner(e.ObjectOwners):
		return fmt.Errorf("event %d has an empty owner", e.Seq)
	case len(e.ObjectOwners) > 0 && e.ObjectOwner != e.ObjectOwners[0]:
		return fmt.Errorf("event %d: object_owner %q must equal object_owners[0] %q", e.Seq, e.ObjectOwner, e.ObjectOwners[0])
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

// maxEventOwners bounds the owners one event may name. It matches the lab's cap.
const maxEventOwners = 16

func hasEmptyOwner(owners []string) bool {
	for _, o := range owners {
		if o == "" {
			return true
		}
	}
	return false
}

// owners returns the owners an event names. An event from a consumer that sets only ObjectOwner is
// read as one owner, so single-owner events keep their meaning.
func (e Event) owners() []string {
	if len(e.ObjectOwners) > 0 {
		return e.ObjectOwners
	}
	if e.ObjectOwner != "" {
		return []string{e.ObjectOwner}
	}
	return nil
}

// foreignOwned reports whether the event names an object owned by someone other than the identity that
// made the request. Any named owner that differs counts, so a second foreign owner is not hidden by a
// first owner that is the caller's own.
func foreignOwned(e Event) bool {
	for _, o := range e.owners() {
		if o != "" && o != e.Identity {
			return true
		}
	}
	return false
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
	{
		ID: "APIBAS-REL-004", Name: "Access to an object owned by another identity", Severity: SeverityHigh, Threshold: 1,
		Match: foreignOwned,
	},
	{
		// REL-005 counts every request of one run. A burst of ten requests is a counted-request abuse
		// pattern whatever their outcome, because the SIEM sees the volume, not the result.
		ID: "APIBAS-REL-005", Name: "Counted-request burst in one run", Severity: SeverityMedium, Threshold: BurstThreshold,
		Match: func(e Event) bool { return true },
	},
	{
		// REL-006 fires on a request whose target or body carries an injection pattern class.
		ID: "APIBAS-REL-006", Name: "Injection-shaped request", Severity: SeverityHigh, Threshold: 1,
		Match: func(e Event) bool { return hasInjectionSignature(e.Signature) },
	},
	{
		// REL-007 fires on a call to a function the fixture classes as privileged, by any identity. The list
		// is fixed here and does not depend on the lab's responses.
		ID: "APIBAS-REL-007", Name: "Privileged function invoked", Severity: SeverityHigh, Threshold: 1,
		Match: func(e Event) bool { return privilegedFunction(e.Action) },
	},
	{
		// REL-008 fires on access to a sensitive projection (a statement, card, audit or view) of an object
		// owned by another identity. It is keyed on the projection, not only on the owner.
		ID: "APIBAS-REL-008", Name: "Sensitive projection of another identity's object", Severity: SeverityHigh, Threshold: 1,
		Match: func(e Event) bool {
			return sensitiveProjection(e.Action) && foreignOwned(e)
		},
	},
}

// BurstThreshold is the number of requests in one run that REL-005 treats as a counted-request burst.
const BurstThreshold = 10

// Injection pattern classes. Each is a class name only; the matched text is never kept.
const (
	SignatureSQL      = "sql_tautology"
	SignatureTraverse = "traversal"
	SignatureLDAP     = "ldap_wildcard"
	SignatureTemplate = "template"
)

func hasInjectionSignature(classes []string) bool {
	for _, c := range classes {
		switch c {
		case SignatureSQL, SignatureTraverse, SignatureLDAP, SignatureTemplate:
			return true
		}
	}
	return false
}

// privilegedFunction reports whether a request action (METHOD path) names a function the fixture classes
// as privileged: deleting an order, reading its audit trail, rotating a key, or changing a key's status.
func privilegedFunction(action string) bool {
	switch {
	case strings.HasPrefix(action, "DELETE /api/authz/orders/"):
		return true
	case strings.HasPrefix(action, "GET /api/authz/orders/") && strings.HasSuffix(action, "/audit"):
		return true
	case action == "POST /api/keys/rotate":
		return true
	case strings.HasPrefix(action, "PATCH /api/keys/orders/") && strings.HasSuffix(action, "/status"):
		return true
	}
	return false
}

// sensitiveProjection reports whether a request action reads a sensitive projection of an object.
func sensitiveProjection(action string) bool {
	if !strings.HasPrefix(action, "GET ") {
		return false
	}
	for _, suffix := range []string{"/statement", "/card", "/audit", "/view"} {
		if strings.HasSuffix(action, suffix) {
			return true
		}
	}
	return false
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
	return ingestInto(&f.events, events)
}

// ingestInto validates every event before storing any of them, rejects duplicate
// sequence numbers, and keeps the store in sequence order. Results therefore do not
// depend on the order events arrive in.
func ingestInto(store *[]Event, events []Event) error {
	seen := make(map[int]bool, len(*store)+len(events))
	for _, e := range *store {
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
	*store = append(*store, events...)
	sort.Slice(*store, func(i, j int) bool { return (*store)[i].Seq < (*store)[j].Seq })
	return nil
}

// Alerts evaluates every rule over the events for one correlation ID. A rule fires
// once, on its Threshold-th matching event. Events under other correlation IDs never
// count.
func (f *ElasticFixture) Alerts(correlationID string) []Alert {
	return evaluate(f.events, ElasticRules, correlationID, SourceElastic)
}

// evaluate applies a rule set to the events for one correlation ID. A rule fires once,
// on its Threshold-th matching event. The rules are vendor-neutral; an adapter supplies
// only its events and its source label.
func evaluate(events []Event, rules []Rule, correlationID, source string) []Alert {
	var out []Alert
	for _, rule := range rules {
		count := 0
		for _, e := range events {
			if e.CorrelationID != correlationID || !rule.Match(e) {
				continue
			}
			count++
			if count == rule.Threshold {
				out = append(out, Alert{
					RuleID: rule.ID, RuleName: rule.Name, Severity: rule.Severity,
					CorrelationID: correlationID, TriggerSeq: e.Seq, Source: source,
				})
			}
		}
	}
	return out
}

// Grade returns "detected" when an alert for the expected rule exists for this
// correlation ID at or above the minimum severity, and "not_detected" otherwise.
func Grade(alerts []Alert, expectRule string, minSeverity Severity, correlationID string) string {
	for _, a := range alerts {
		if a.RuleID == expectRule && a.CorrelationID == correlationID && a.Severity >= minSeverity {
			return Detected
		}
	}
	return NotDetected
}
