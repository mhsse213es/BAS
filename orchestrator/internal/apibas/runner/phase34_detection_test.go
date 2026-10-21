package runner_test

import (
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/audspect/bas/internal/apibas/catalog"
	"github.com/audspect/bas/internal/apibas/contract"
	"github.com/audspect/bas/internal/apibas/detect"
	"github.com/audspect/bas/internal/apibas/fixture"
	"github.com/audspect/bas/internal/apibas/lab"
	"github.com/audspect/bas/internal/apibas/runner"
)

// labTelemetryDelay is the hold the lab applies under the telemetry-delayed fault (lab/access.go). The lab
// constant is unexported, so the test states it and TestDET009 checks it against the lab's behaviour.
const labTelemetryDelay = 3 * time.Second

// forgedIdentityHeaders are the request headers the vulnerable build trusts as the caller's identity. The
// access log records the identity the product accepted, so a forged header makes an event look like the
// claimed identity's own access.
var forgedIdentityHeaders = []string{"X-Customer-Id", "X-Gateway-Identity"}

// Phase 34 detection acceptance. Every rule a scenario declares is graded against the fixture's events in
// both builds, with body-identifier extraction off and on. Each result must match an expectation written
// before the run. A scenario is fixture-validated only when every expectation matches on two consecutive
// runs. A mismatch is a finding; the expectation is never edited to match a result.
//
// The expectation for each rule comes from that rule's definition and from the scenario, not from the lab:
//
//   - APIBAS-REL-004 (object owned by another identity): detected when the request names an object owned
//     by someone other than the attacker. The attacker is the identity the product accepted, so a forged
//     identity header counts in the vulnerable build. A body-carried object is seen only with extraction on.
//   - APIBAS-REL-005 (counted-request burst): detected when the run sends at least BurstThreshold requests.
//   - APIBAS-REL-006 (injection-shaped request): detected when a class the rule matches is in the request
//     target, or in the body with extraction on. injectionExpectation states each scenario's payload.
//   - APIBAS-REL-007 (privileged function): detected for the privileged functions the scenarios call.
//   - APIBAS-REL-008 (sensitive projection of another identity's object): detected when the projection
//     names an object owned by someone other than the attacker.

func TestPhase34_DetectionMatchesDeclaredExpectations(t *testing.T) {
	if testing.Short() {
		t.Skip("detection run skipped in -short mode")
	}
	all, err := catalog.All()
	if err != nil {
		t.Fatalf("catalog.All: %v", err)
	}
	var failures []string
	validated, declared := 0, 0
	for _, s := range all {
		if s.Detection == nil || tlsGraded[s.ID] {
			continue
		}
		declared++
		fx := fixtureFor(t, s.Preconditions.Fixture)
		rules := append([]string{s.Detection.ExpectRule}, additionalRules(s)...)
		matched := true
		for pass := 0; pass < 2; pass++ { // repeatability: two consecutive runs must both match
			for _, extract := range []bool{false, true} {
				for _, mode := range []lab.Mode{lab.ModeVulnerable, lab.ModeFixed} {
					e := newEnvWith(t, mode, fx, s.Preconditions.LabFaults, extract)
					rep := e.run(t, s, e.state)
					for i, rule := range rules {
						want := expectedDetection(t, fx, s, rule, mode, extract)
						got := rep.Outcome.Detection
						if i > 0 {
							got = rep.DetectionResults[rule]
						}
						if got != want {
							matched = false
							failures = append(failures, fmt.Sprintf("%s %s %s extract=%t pass=%d: %q, expected %q",
								s.ID, rule, modeName(mode), extract, pass, got, want))
						}
					}
				}
			}
		}
		if matched {
			validated++
		}
	}
	t.Logf("detection: declared=%d validated_repeatable=%d not_matching=%d", declared, validated, declared-validated)
	if declared == 0 {
		t.Fatal("no scenario declares a detection block")
	}
	if len(failures) > 0 {
		t.Fatalf("%d detection results differ from the declared expectations:\n%s", len(failures), strings.Join(failures, "\n"))
	}
}

// additionalRules lists the rule IDs a scenario declares beyond its primary rule.
func additionalRules(s contract.Scenario) []string {
	var out []string
	for _, a := range s.AdditionalDetections {
		out = append(out, a.ExpectRule)
	}
	return out
}

// expectedDetection is the expectation for one rule in one build, with extraction set as given.
func expectedDetection(t *testing.T, fx fixture.Fixture, s contract.Scenario, rule string, mode lab.Mode, extract bool) string {
	t.Helper()
	// Delayed telemetry: the lab holds events for labTelemetryDelay. If that delay exceeds the runner's
	// detection window, the rule cannot see the attack event in time, so the result is inconclusive for every
	// rule. This follows from the two constants, not from observed output.
	if slices.Contains(s.Preconditions.LabFaults, "telemetry-delayed") && labTelemetryDelay > runner.DefaultDetectionWindow {
		return detect.Inconclusive
	}
	switch rule {
	case "APIBAS-REL-004":
		if isCollectionRequest(s) {
			return listDisclosureDetection(t, fx, s, mode)
		}
		return ownershipDetection(t, fx, s, mode, extract)
	case "APIBAS-REL-018":
		// A repayment change by a caller who is not lender staff. The attempt is the signal, in either build.
		attack := s.Steps[len(s.Steps)-1]
		if attack.Method == "PATCH" && strings.HasPrefix(attack.Path, "/api/nbfc/repayments/") && !staffRoleOf(t, fx, attack.Identity) {
			return detect.Detected
		}
		return detect.NotDetected
	case "APIBAS-REL-019":
		// A privileged route called by a caller whose role is not the administrator. The attempt is the signal, in either build.
		attack := s.Steps[len(s.Steps)-1]
		if detect.ActionClass(attack.Method+" "+attack.Path) == detect.ClassPrivilegeChange && roleOf(t, fx, attack.Identity) != "administrator" {
			return detect.Detected
		}
		return detect.NotDetected
	case "APIBAS-REL-001":
		// REL-001 fires on three authentication failures. The scenario's attack repeats a wrong credential
		// and the product refuses each with 401, so three attack requests are enough. The vulnerable build accepts a
		// revoked credential instead of refusing it, so it logs no failure: REL-001 cannot fire there.
		attack := s.Steps[len(s.Steps)-1]
		if mode == lab.ModeVulnerable && attack.Auth == "revoked" {
			return detect.NotDetected
		}
		if attack.Repeat >= 3 {
			return detect.Detected
		}
		return detect.NotDetected
	case "APIBAS-REL-005":
		if requestsInRun(s) >= detect.BurstThreshold {
			return detect.Detected
		}
		return detect.NotDetected
	case "APIBAS-REL-006":
		return injectionExpectation(s.ID, extract)
	case "APIBAS-REL-007":
		return detect.Detected // each scenario that declares it calls a privileged function as a customer
	case "APIBAS-REL-008":
		return projectionDetection(t, fx, s)
	case "APIBAS-REL-010":
		// REL-010 fires when two or more distinct identities in one run each reach a foreign-owned object (DET-004).
		identities := map[string]bool{}
		for _, st := range s.Steps {
			if st.Role == "attack" || st.CoActor {
				identities[st.Identity] = true
			}
		}
		if len(identities) >= 2 {
			return detect.Detected
		}
		return detect.NotDetected
	case "APIBAS-REL-012":
		return destinationDetection(t, s)
	case "APIBAS-REL-014":
		// The page limit the attack asks for, against the documented maximum. The attempt counts whatever the outcome.
		attack := s.Steps[len(s.Steps)-1]
		u, err := url.Parse(attack.Path)
		if err != nil {
			t.Fatalf("%s: attack path %q: %v", s.ID, attack.Path, err)
		}
		if n, err := strconv.Atoi(u.Query().Get("limit")); err == nil && n > detect.MaxPageSize {
			return detect.Detected
		}
		return detect.NotDetected
	case "APIBAS-REL-015":
		// The body the runner sends, with each filler placeholder expanded, against the documented upload ceiling.
		attack := s.Steps[len(s.Steps)-1]
		expanded := fillerPlaceholder.ReplaceAllStringFunc(attack.Body, func(m string) string {
			n, _ := strconv.Atoi(fillerPlaceholder.FindStringSubmatch(m)[1])
			return strings.Repeat("x", n)
		})
		if int64(len(expanded)) > detect.MaxRequestBytes {
			return detect.Detected
		}
		return detect.NotDetected
	case "APIBAS-REL-016":
		// The status route marks its response publicly cacheable only in the vulnerable build.
		attack := s.Steps[len(s.Steps)-1]
		if mode == lab.ModeVulnerable && attack.Method == "GET" && strings.HasSuffix(attack.Path, "/status") {
			return detect.Detected
		}
		return detect.NotDetected
	case "APIBAS-REL-013":
		// The unsigned-token attack is accepted only by the vulnerable build, under the forged subject. Its verified
		// identity is empty, so the claimed identity is not proven by any signed token.
		attack := s.Steps[len(s.Steps)-1]
		if mode == lab.ModeVulnerable && attack.Auth == "alg_none" {
			return detect.Detected
		}
		return detect.NotDetected
	case "APIBAS-REL-011":
		// REL-011 fires when an anonymous request succeeds on an object that has an owner. The vulnerable build serves the
		// anonymous attack; the fixed build refuses it. A scenario whose anonymous attack names no owned object is not
		// declared with this rule, so the expectation here holds only for scenarios that name one.
		return anonymousOwnedDetection(t, fx, s, mode)
	case "APIBAS-REL-009":
		// REL-009 fires when an authorization completes while the fraud check is degraded. Only the vulnerable build
		// completes it under the fault; the fixed build fails closed, so there is nothing to alert on.
		if mode == lab.ModeVulnerable && slices.Contains(s.Preconditions.LabFaults, "fraud-check-down") {
			return detect.Detected
		}
		return detect.NotDetected
	}
	t.Fatalf("%s: no expectation is written for rule %s", s.ID, rule)
	return ""
}

// requestsInRun counts the product requests the scenario sends: each step once, or its repeat count.
func requestsInRun(s contract.Scenario) int {
	n := 0
	for _, st := range s.Steps {
		if st.Repeat > 1 {
			n += st.Repeat
		} else {
			n++
		}
	}
	return n
}

// injectionExpectation states, per scenario, whether REL-006 can see the payload. INJ-001 and INJ-008 carry
// their class in the request target. INJ-003 carries its template in the body, so it is seen only with
// extraction on. INJ-002, INJ-004 and INJ-010 carry a form the classifier does not recognise: a bare
// expression, a bare wildcard, and an internal URL. They are not_detected, with or without extraction.
func injectionExpectation(id string, extract bool) string {
	switch id {
	case "API-BAS-INJ-001", "API-BAS-INJ-008":
		return detect.Detected
	case "API-BAS-INJ-003", "API-BAS-INJ-009", "API-BAS-INJ-011":
		// These carry their payload in the body, which the lab inspects only with body extraction on.
		if extract {
			return detect.Detected
		}
		return detect.NotDetected
	}
	return detect.NotDetected
}

// projectionDetection: REL-008 fires on a sensitive projection of an object owned by another identity.
func projectionDetection(t *testing.T, fx fixture.Fixture, s contract.Scenario) string {
	t.Helper()
	attack := s.Steps[len(s.Steps)-1]
	id, ok := fx.Identity(attack.Identity)
	if !ok {
		t.Fatalf("%s: attack identity %s is not in the fixture", s.ID, attack.Identity)
	}
	target := strings.ReplaceAll(attack.Path, "{object}", s.Preconditions.Object)
	named := namedInRequest(target)
	for _, o := range fx.Objects {
		if named(o.ID) && o.OwnerID != id.CustomerID {
			return detect.Detected
		}
	}
	return detect.NotDetected
}

// ownershipDetection is the REL-004 expectation. The attacker is the identity the product accepted.
func ownershipDetection(t *testing.T, fx fixture.Fixture, s contract.Scenario, mode lab.Mode, extract bool) string {
	t.Helper()
	attack := s.Steps[len(s.Steps)-1]
	attacker := ""
	if attack.Auth != "none" {
		id, ok := fx.Identity(attack.Identity)
		if !ok {
			t.Fatalf("%s: attack identity %s is not in the fixture", s.ID, attack.Identity)
		}
		attacker = id.CustomerID
		if mode == lab.ModeVulnerable {
			for _, h := range forgedIdentityHeaders {
				if claimed, ok := attack.Headers[h]; ok {
					attacker = claimed
				}
			}
		}
	}
	target := strings.ReplaceAll(attack.Path, "{object}", s.Preconditions.Object)
	named := namedInRequest(target)
	for _, o := range fx.Objects {
		inBody := extract && strings.Contains(attack.Body, o.ID)
		if (named(o.ID) || inBody || protectedValueNamed(target, o)) && o.OwnerID != attacker {
			return detect.Detected
		}
	}
	return detect.NotDetected
}

// tlsGraded are the declared scenarios graded on the TLS environment by their own test, not by this table, which has no
// TLS harness.
var tlsGraded = map[string]bool{"API-BAS-GWAY-012": true, "API-BAS-AUTHN-007": true}

// fillerPlaceholder matches a body filler placeholder such as {filler:2097152}, which the runner expands to that many bytes.
var fillerPlaceholder = regexp.MustCompile(`\{filler:(\d+)\}`)

// destinationDetection expects REL-012 from the destination the attack asks the server to act on, graded with the lab's
// policy. The attempt counts whatever its outcome, so the expectation is the same in both builds.
func destinationDetection(t *testing.T, s contract.Scenario) string {
	t.Helper()
	attack := s.Steps[len(s.Steps)-1]
	var kind, value string
	if strings.HasPrefix(attack.Path, "/api/integrations/return") || strings.HasPrefix(attack.Path, "/api/oauth/authorize") {
		u, err := url.Parse(attack.Path)
		if err != nil {
			t.Fatalf("%s: attack path %q: %v", s.ID, attack.Path, err)
		}
		kind, value = lab.DestRedirect, u.Query().Get("next")
		if strings.HasPrefix(attack.Path, "/api/oauth/authorize") {
			kind, value = lab.DestAuthRedirect, u.Query().Get("redirect_uri")
		}
	} else {
		var body struct {
			URL string `json:"url"`
		}
		if err := json.Unmarshal([]byte(attack.Body), &body); err != nil {
			t.Fatalf("%s: attack body %q: %v", s.ID, attack.Body, err)
		}
		// The runner substitutes the lab's own address for {lab_url}, a loopback address, so an SSRF target on the lab is
		// internal. {rogue_url} is an external host in the runner's test setup.
		value = strings.ReplaceAll(body.URL, "{lab_url}", "http://127.0.0.1")
		value = strings.ReplaceAll(value, "{rogue_url}", "https://rogue.example")
		kind = lab.DestWebhook
		if strings.HasPrefix(attack.Path, "/api/integrations/callbacks") {
			kind = lab.DestCallback
		}
	}
	if value == "" {
		return detect.NotDetected
	}
	if lab.DestinationPolicy(kind, value) == lab.PolicyAllowed {
		return detect.NotDetected
	}
	return detect.Detected
}

// anonymousOwnedDetection expects REL-011: in the vulnerable build an anonymous attack that names an owned object is
// served (detected); in the fixed build it is refused (not detected).
func anonymousOwnedDetection(t *testing.T, fx fixture.Fixture, s contract.Scenario, mode lab.Mode) string {
	t.Helper()
	attack := s.Steps[len(s.Steps)-1]
	if attack.Auth != "none" || mode != lab.ModeVulnerable {
		return detect.NotDetected
	}
	target := strings.ReplaceAll(attack.Path, "{object}", s.Preconditions.Object)
	named := namedInRequest(target)
	for _, o := range fx.Objects {
		if named(o.ID) || protectedValueNamed(target, o) {
			return detect.Detected
		}
	}
	return detect.NotDetected
}

// protectedValueNamed reports whether a decoded query value of the request target contains one of the object's
// protected values. It mirrors the lab's attribution of a query that names a protected value.
func protectedValueNamed(target string, o fixture.Object) bool {
	u, err := url.Parse(target)
	if err != nil {
		return false
	}
	for _, vals := range u.Query() {
		for _, v := range vals {
			for _, pv := range o.Protected {
				if pv != "" && strings.Contains(v, pv) {
					return true
				}
			}
		}
	}
	return false
}

// namedInRequest reports whether an object ID appears in the request target's path or in a decoded query
// value. It mirrors the lab's owner attribution.
func namedInRequest(target string) func(id string) bool {
	u, err := url.Parse(target)
	if err != nil {
		return func(string) bool { return false }
	}
	parts := []string{u.Path}
	for _, vals := range u.Query() {
		parts = append(parts, vals...)
	}
	return func(id string) bool {
		for _, p := range parts {
			if strings.Contains(p, id) {
				return true
			}
		}
		return false
	}
}

func modeName(m lab.Mode) string {
	if m == lab.ModeVulnerable {
		return "vulnerable"
	}
	return "fixed"
}

// isCollectionRequest reports whether the attack reads a collection (a list route) rather than naming one object.
func isCollectionRequest(s contract.Scenario) bool {
	attack := s.Steps[len(s.Steps)-1]
	path, _, _ := strings.Cut(attack.Path, "?")
	return strings.HasSuffix(path, "/loans")
}

// listDisclosureDetection is the expectation for a collection read. The list returns the records it discloses, and REL-004
// reads the owners the response names. The vulnerable build's loan list returns every loan, so it names other owners. The
// fixed build returns only the caller's loans.
func listDisclosureDetection(t *testing.T, fx fixture.Fixture, s contract.Scenario, mode lab.Mode) string {
	t.Helper()
	attack := s.Steps[len(s.Steps)-1]
	id, ok := fx.Identity(attack.Identity)
	if !ok {
		t.Fatalf("%s: attack identity %s is not in the fixture", s.ID, attack.Identity)
	}
	if mode != lab.ModeVulnerable {
		return detect.NotDetected
	}
	for _, o := range fx.Objects {
		if o.Kind == "loan" && o.OwnerID != id.CustomerID {
			return detect.Detected
		}
	}
	return detect.NotDetected
}

// roleOf is the fixture role of a named identity, or "customer" for an identity the fixture does not give a role.
func roleOf(t *testing.T, fx fixture.Fixture, name string) string {
	t.Helper()
	id, ok := fx.Identity(name)
	if !ok {
		t.Fatalf("identity %s is not in the fixture", name)
	}
	if id.Role == "" {
		return "customer"
	}
	return id.Role
}

// staffRoleOf reports whether a named identity is lender staff.
func staffRoleOf(t *testing.T, fx fixture.Fixture, name string) bool {
	r := roleOf(t, fx, name)
	return r == "officer" || r == "administrator"
}
