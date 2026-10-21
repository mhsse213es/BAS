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
	// NotEvaluated means detection made no claim: the run did not execute, so there was no traffic to judge.
	// It is distinct from NotDetected, which is a judgement on executed traffic.
	NotEvaluated = "not_evaluated"
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
	// ActionClass is the class of the action (see the Class* vocabulary). Empty means the action could not be classified.
	ActionClass string `json:"action_class,omitempty"`
	// Destination is the normalised destination the handler acted on, and DestinationPolicy its verdict (see
	// lab/destination.go). An empty policy means the route records no destination, so REL-012 cannot grade it.
	Destination       string `json:"destination,omitempty"`
	DestinationPolicy string `json:"destination_policy,omitempty"`
	// VerifiedIdentity is the customer a signed token proves. Identity is the claimed identity the verifier accepted.
	// They differ when the server accepted a claim the token does not prove (REL-013).
	VerifiedIdentity string `json:"verified_identity,omitempty"`
	// PageSize is the page size a request asked for (its limit parameter), 0 when the request names none. RequestBytes is
	// the request body size as sent. CacheControl is the Cache-Control value the response carried. Each is recorded by the
	// lab from the request or response the handler produced (see lab/access.go).
	PageSize     int    `json:"page_size,omitempty"`
	RequestBytes int64  `json:"request_bytes,omitempty"`
	CacheControl string `json:"cache_control,omitempty"`
	// Degraded names the controls the lab ran degraded when it served the request (see lab access events).
	Degraded []string `json:"degraded,omitempty"`
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
	// Action, Identity and Owners describe the affected resource from the triggering event (DET-008): the
	// method and path that was requested, the identity that requested it, and the owners it named.
	Action   string
	Identity string
	Owners   []string
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
	// Distinct, when set, counts distinct values of this key among matching events instead of counting events.
	// The rule fires on the event that reaches Threshold distinct values (REL-010 counts identities).
	Distinct func(Event) string
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
		// The lab classes each event. A class-less event is classed from its action, so the rule reads one definition.
		Match: func(e Event) bool { return isPrivilegedClass(e.ActionClass) || privilegedFunction(e.Action) },
	},
	{
		// REL-008 fires on access to a sensitive projection (a statement, card, audit or view) of an object
		// owned by another identity. It is keyed on the projection, not only on the owner.
		ID: "APIBAS-REL-008", Name: "Sensitive projection of another identity's object", Severity: SeverityHigh, Threshold: 1,
		Match: func(e Event) bool {
			return sensitiveProjection(e.Action) && foreignOwned(e)
		},
	},
	{
		// REL-010 fires when two or more distinct identities in one run each reach an object owned by another
		// identity. One identity's foreign access is REL-004; the same pattern from several identities is a
		// correlated campaign across identities (DET-004).
		ID: "APIBAS-REL-010", Name: "Correlated foreign-object access across identities", Severity: SeverityHigh, Threshold: 2,
		Match:    foreignOwned,
		Distinct: func(e Event) string { return e.Identity },
	},
	{
		// REL-011 fires when a request with no identity succeeds on an object that has an owner. It correlates on the
		// request (the run), the target (the owner the request reached) and the behaviour (a 2xx outcome). It does not
		// correlate on source address: the access event carries none, so no source-based anonymous rule exists. A refused
		// anonymous request fires nothing, and an anonymous request that reaches no owned object is not evaluated.
		ID: "APIBAS-REL-011", Name: "Owned object returned to an unauthenticated request", Severity: SeverityHigh, Threshold: 1,
		Match: func(e Event) bool {
			return e.Identity == "anonymous" && e.Status >= 200 && e.Status < 300 && len(e.owners()) > 0
		},
	},
	{
		// REL-014 fires when a request asks for a page larger than the documented maximum. The attempt is the signal,
		// whatever the outcome, as with REL-005.
		ID: "APIBAS-REL-014", Name: "Page size above the documented maximum", Severity: SeverityMedium, Threshold: 1,
		Match: func(e Event) bool { return e.PageSize > MaxPageSize },
	},
	{
		// REL-015 fires when a request body is larger than the documented upload ceiling.
		ID: "APIBAS-REL-015", Name: "Request body above the documented maximum", Severity: SeverityMedium, Threshold: 1,
		Match: func(e Event) bool { return e.RequestBytes > MaxRequestBytes },
	},
	{
		// REL-016 fires when a response that carries an owner's data is marked publicly cacheable, so a shared cache can
		// store it. A private or no-store directive does not fire.
		ID: "APIBAS-REL-016", Name: "Owner data served as publicly cacheable", Severity: SeverityHigh, Threshold: 1,
		Match: func(e Event) bool {
			return e.Status >= 200 && e.Status < 300 && len(e.owners()) > 0 && strings.Contains(e.CacheControl, "public")
		},
	},
	{
		// REL-017 fires when content from an upstream whose certificate does not verify is relayed to the caller (2xx).
		// A refused fetch relays nothing and does not fire.
		ID: "APIBAS-REL-017", Name: "Upstream content relayed without certificate verification", Severity: SeverityHigh, Threshold: 1,
		Match: func(e Event) bool {
			return e.DestinationPolicy == "untrusted_certificate" && e.Status >= 200 && e.Status < 300
		},
	},
	{
		// REL-013 fires when a request is accepted under a customer identity that no signed token proves: an unsigned
		// token's subject, or a caller-supplied customer header. A customer identity with a matching verified identity,
		// or with none (anonymous or unknown), does not fire.
		ID: "APIBAS-REL-013", Name: "Identity not proven by a signed token", Severity: SeverityHigh, Threshold: 1,
		Match: func(e Event) bool {
			claimed := e.Identity != "" && e.Identity != "anonymous" && e.Identity != "unknown"
			return claimed && e.Status >= 200 && e.Status < 300 && e.VerifiedIdentity != e.Identity
		},
	},
	{
		// REL-012 fires when a handler acts on a destination outside its policy: a redirect off this origin, a callback host
		// that is not allowlisted, or an internal address a server-side fetch must not reach (SSRF). Like REL-005 and
		// REL-007, the attempt is the signal, whatever the outcome.
		ID: "APIBAS-REL-012", Name: "Destination outside policy", Severity: SeverityHigh, Threshold: 1,
		Match: func(e Event) bool {
			return e.DestinationPolicy == "outside_allowlist" || e.DestinationPolicy == "internal"
		},
	},
	{
		// REL-009 fires when a payment authorization completes (2xx) while the fraud check is degraded. The fixed
		// build fails closed with 424, so it produces no alert. Elastic-only: the Sentinel record does not carry Degraded.
		ID: "APIBAS-REL-009", Name: "High-risk flow completed while a fraud control is degraded", Severity: SeverityHigh, Threshold: 1,
		Match: func(e Event) bool {
			return e.Status >= 200 && e.Status < 300 && strings.HasSuffix(e.Action, "/authorize-payment") && hasDependency(e.Degraded, "fraud-check")
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
	// SignatureCookie is an attribute injected into a cookie or header value (for example "; Domain=..."). It is matched on
	// the attribute structure, not on the text of any one payload.
	SignatureCookie = "cookie_attribute"
	// SignaturePrototype is a prototype key in a JSON body (__proto__ or constructor.prototype).
	SignaturePrototype = "prototype_key"
)

func hasInjectionSignature(classes []string) bool {
	for _, c := range classes {
		switch c {
		case SignatureSQL, SignatureTraverse, SignatureLDAP, SignatureTemplate, SignatureCookie, SignaturePrototype:
			return true
		}
	}
	return false
}

// privilegedFunction reports whether a request action (METHOD path) names a function the fixture classes
// as privileged: deleting an order, reading its audit trail, rotating a key, or changing a key's status.
func hasDependency(degraded []string, name string) bool {
	for _, d := range degraded {
		if d == name {
			return true
		}
	}
	return false
}

// Documented limits. Each is the ceiling the product's own contract states, not a tuned value.
const (
	// MaxPageSize is the largest page a list request may ask for (the order listing contract).
	MaxPageSize = 100
	// MaxRequestBytes is the largest attachment upload the product accepts (1 MiB).
	MaxRequestBytes = 1 << 20
)

// The action-class vocabulary. Each class names what an action does to the object it targets. Ownership of the object
// never decides the class: the same method and route classify the same way for the owner and for anyone else.
const (
	ClassRead               = "read"                  // a GET that returns an object or a page of objects
	ClassWrite              = "write"                 // a POST, PUT, PATCH or DELETE that changes an object
	ClassSensitiveExport    = "sensitive_export"      // an export of an object, which may carry protected fields
	ClassPrivilegeChange    = "privilege_change"      // an administrative route, or a change to the caller's own role
	ClassFinancialApproval  = "financial_approval"    // approval of a payout, or a refund
	ClassSecurityControlChange = "security_control_change" // rotation, status or audit of a security control
)

// isPrivilegedClass reports whether a class is a privileged operation. REL-007 reads it. The three privileged classes
// are the ones whose effect is administrative, financial or a security control, not ordinary owned-object access.
func isPrivilegedClass(class string) bool {
	switch class {
	case ClassPrivilegeChange, ClassFinancialApproval, ClassSecurityControlChange:
		return true
	}
	return false
}

// ActionClass returns the class of an action given as "METHOD path", or "" when the action cannot be classified.
// The first matching rule wins, so the security and financial classes take precedence over the generic write class.
func ActionClass(action string) string {
	method, path, ok := strings.Cut(action, " ")
	if !ok {
		return ""
	}
	switch {
	case strings.HasPrefix(action, "DELETE /api/authz/orders/"),
		strings.HasPrefix(action, "GET /api/authz/orders/") && strings.HasSuffix(action, "/audit"),
		action == "POST /api/keys/rotate",
		strings.HasPrefix(action, "PATCH /api/keys/orders/") && strings.HasSuffix(action, "/status"):
		return ClassSecurityControlChange
	case strings.HasPrefix(path, "/api/admin/"), action == "PATCH /api/me/role":
		return ClassPrivilegeChange
	case method == "POST" && (strings.HasSuffix(path, "/approve-payout") || strings.HasSuffix(path, "/refund")):
		return ClassFinancialApproval
	case method == "GET" && strings.HasSuffix(path, "/export"):
		return ClassSensitiveExport
	case method == "GET":
		return ClassRead
	case method == "POST" || method == "PUT" || method == "PATCH" || method == "DELETE":
		return ClassWrite
	}
	return ""
}

func privilegedFunction(action string) bool {
	return isPrivilegedClass(ActionClass(action))
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
		seen := map[string]bool{}
		for _, e := range events {
			if e.CorrelationID != correlationID || !rule.Match(e) {
				continue
			}
			if rule.Distinct != nil {
				key := rule.Distinct(e)
				if seen[key] {
					continue
				}
				seen[key] = true
			}
			count++
			if count == rule.Threshold {
				out = append(out, Alert{
					RuleID: rule.ID, RuleName: rule.Name, Severity: rule.Severity,
					CorrelationID: correlationID, TriggerSeq: e.Seq, Source: source,
					Action: e.Action, Identity: e.Identity, Owners: e.owners(),
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
