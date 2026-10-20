package reporting

import (
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/audspect/bas/internal/dlpfixture"
	"github.com/audspect/bas/internal/scenario"
)

// DLP Validation Suite — Phase B, the first real consumer of the Outcome
// Validation Framework (Phase A). Registers the "dlp" outcome family's
// comparator and a local-observation verifier that never claims more than an
// OS-level fact proves.
//
// A local script can only observe whether the file operation it attempted
// (USB copy, clipboard write, print, archive, local staging) succeeded or was
// prevented — a primitive fact, not a policy verdict. A Warn-and-continue
// policy produces the identical local symptom as no policy at all (the
// operation succeeds either way), so a local observer that concluded
// "Allow" from a bare success would be claiming evidence it doesn't have.
// dlpComparator keeps that distinction explicit: it compares the DLP outcome
// catalog's richer vocabulary (Allow/Block/Warn/Justify/Audit/Quarantine/
// Encrypt/Redact) against one of three primitive observations, not against
// itself.

// DLPEvidence carries the three evidence-model dimensions Audspect can
// honestly populate today without a vendor connector or new telemetry
// correlation -- see dlp.txt §6 and
// docs/superpowers/plans/2026-10-18-dlpevidence.md. Classification/
// telemetry/response outcomes are deliberately absent, not empty
// placeholders: they require evidence sources that don't exist yet.
type DLPEvidence struct {
	// CollectionMethod names how ObservedOutcome was actually established:
	// "sink-receipt" (destination-side ground truth) or "local-marker" (the
	// step's own self-reported DLP_OBSERVATION line). Empty when neither
	// produced a usable observation (ObservationUnknown, including a skip).
	CollectionMethod string
	// CorrelationID ties this evidence to a specific collection event. Always
	// empty today -- no part of the current pipeline threads a real
	// correlation token (e.g. the sink service's own token value) into
	// StepEvidence yet. Left unavailable rather than inventing one; the field
	// exists so a later, real correlation-ID change populates it without
	// another struct change.
	CorrelationID string
	// FixtureID is the dlpfixture.Fixture.ID this step's synthetic payload
	// actually matches, resolved by exact step-name lookup
	// (dlpfixture.FixtureIDForStep) -- never inferred from the scenario's own
	// ID or description. Empty when the step name doesn't resolve to exactly
	// one catalogued fixture.
	FixtureID string
	// Limitations explains, in words, what Comparison actually proves,
	// contradicts, or leaves unresolved for this specific verdict. Always
	// populated.
	Limitations string
	// TestEventStart is the controlled test-event start the payload recorded
	// with a DLP_EVENT_START marker for this step (see ParseDLPEventStart).
	// Zero when no usable marker exists; TestEventStartReason then says why.
	TestEventStart       time.Time
	TestEventStartReason string

	// Channel names which operation path produced this evidence --
	// "browser" | "native-app" | "sync-client" | "api" | "" (unknown).
	// An open string, not a closed enum, mirroring
	// dlpclassify.ClassificationEvidence.Channel's own discipline.
	Channel string
	// Override carries an observed override/justification record, or
	// nil when no override evidence exists (never a struct of all
	// zero values, which would misrepresent "we have nothing to say"
	// as "an override we know nothing about").
	Override *OverrideEvidence
	// Connectivity carries observed endpoint online/offline and
	// policy-sync state, or nil when unavailable.
	Connectivity *ConnectivityEvidence
}

// OverrideEvidence is what was actually observed about an end user's
// override of a DLP action (e.g. "override and send anyway") --
// never inferred from a bare operation success. This is unrelated to
// this file's own applyOverride/StoredVerification, which is an
// analyst's manual review-workflow override of this tool's own
// verdict, not a DLP end user's override of a policy action.
type OverrideEvidence struct {
	Occurred      bool
	AuthorizedBy  string // user/role/service identity that approved the override; empty if unknown
	Reason        string // the stated justification text, verbatim
	AuditRecordID string // empty when no corresponding audit-trail record was found
}

// ConnectivityEvidence is what was actually observed about the
// endpoint's connectivity and policy currency at the time of the
// enforcement action -- never inferred from the action's outcome
// alone (an endpoint can enforce correctly while offline, using a
// cached policy).
type ConnectivityEvidence struct {
	// Online is nil when connectivity state could not be established
	// (never defaulted to true or false).
	Online                 *bool
	EffectivePolicyVersion string
	LastSyncedAt           time.Time // zero value = unknown, never "now"
}

// Primitive observations a local verifier can honestly report.
const (
	ObservationSucceeded = "OperationSucceeded"
	ObservationBlocked   = "OperationBlocked"
	ObservationUnknown   = "OperationUnknown"
)

// dlpComparator is the "dlp" family's Comparator. The asymmetry is
// deliberate: an observed block is informative regardless of what was
// expected — something clearly intervened, which is real policy drift even
// against a softer expected outcome, not missing evidence. An observed
// success is only conclusive against Allow/Block; every softer expected
// outcome (Warn/Justify/Audit/Quarantine/Encrypt/Redact) stays honestly
// MissingEvidence, since success alone can't confirm which of those fired.
type dlpComparator struct{}

func (dlpComparator) Compare(expected, observed string) ComparisonResult {
	switch observed {
	case ObservationBlocked:
		if expected == "Block" {
			return Match
		}
		return Mismatch
	case ObservationSucceeded:
		switch expected {
		case "Allow":
			return Match
		case "Block":
			return Mismatch
		default:
			return MissingEvidence
		}
	default: // ObservationUnknown, or any unrecognized token
		return MissingEvidence
	}
}

func init() {
	RegisterComparator("dlp", dlpComparator{})
}

var dlpMarkerRe = regexp.MustCompile(`(?m)^DLP_OBSERVATION:\s*(\S+)$`)

// dlpVerifier resolves DLP expectations from a step's self-reported outcome
// marker. The script itself does the post-condition check (did the file land
// on the USB path, does Get-Clipboard now match, etc.) and prints exactly
// one deterministic line; this verifier only parses it. It never re-derives
// observations from vendor-specific error text — that would be exactly the
// fragile heuristic classifySkipReason's own doc comment warns against for
// third-party output. An absent or unrecognized marker always resolves to
// ObservationUnknown — never guessed as a known primitive.
type dlpVerifier struct{}

func (dlpVerifier) Verify(exp scenario.ExpectedDetection, ev StepEvidence) VerificationResult {
	r := baseResult(exp, ev, "automatic")
	r.ExpectedOutcome = scenario.ResolveExpectedOutcome(exp)

	observed := ObservationUnknown
	collectionMethod := ""
	wasSkip := isSkipMarker(ev.RawOutput)
	switch {
	case wasSkip:
		// A step that never ran (client tool absent, technique not
		// applicable, etc.) produced no attempt at all -- SinkTokenObserved
		// being false here is the absence of an attempt, not evidence the
		// attempt was blocked. Checked BEFORE SinkTokenObserved so a skip
		// can never resolve to ObservationBlocked. See
		// docs/superpowers/specs/2026-09-01-sftp-exfiltration-channel-design.md.
		// observed stays ObservationUnknown, collectionMethod stays "".
	case ev.SinkTokenObserved != nil:
		// Sink-primary: destination-side receipt is authoritative ground
		// truth for whether the data actually left, superseding the local
		// marker for this step -- see
		// docs/superpowers/specs/2026-08-19-dlp-exfiltration-sink-service-design.md.
		collectionMethod = "sink-receipt"
		if *ev.SinkTokenObserved {
			observed = ObservationSucceeded
		} else {
			observed = ObservationBlocked
		}
	default:
		if m := dlpMarkerRe.FindStringSubmatch(ev.RawOutput); m != nil {
			switch m[1] {
			case ObservationSucceeded, ObservationBlocked:
				observed = m[1]
				collectionMethod = "local-marker"
			}
			// An unrecognized token is a marker that didn't produce a usable
			// observation -- collectionMethod stays "", observed stays
			// ObservationUnknown, same as no marker at all.
		}
	}

	r.ObservedOutcome = observed
	r.Comparison = comparatorFor("dlp").Compare(r.ExpectedOutcome, r.ObservedOutcome)
	r.Status = collapseToStatus(r.Comparison)
	if wasSkip {
		// collapseToStatus (shared by every verifier in this package) has no
		// concept of "confirmed absent precondition" -- it resolves
		// MissingEvidence to the generic StatusUnknown. Override locally,
		// only for dlp's own recognized skip: path, without touching
		// collapseToStatus itself or any other verifier's behavior.
		// Comparison stays MissingEvidence; only the legacy Status field
		// gains this more specific value.
		r.Status = StatusNotTested
	}

	fixtureID := ""
	if ev.StepName != "" {
		if id, ok := dlpfixture.FixtureIDForStep(ev.StepName); ok {
			fixtureID = id
		}
	}

	var override *OverrideEvidence
	if ev.OverrideOccurred || ev.OverrideAuthorizedBy != "" || ev.OverrideReason != "" || ev.OverrideAuditRecordID != "" {
		override = &OverrideEvidence{
			Occurred:      ev.OverrideOccurred,
			AuthorizedBy:  ev.OverrideAuthorizedBy,
			Reason:        ev.OverrideReason,
			AuditRecordID: ev.OverrideAuditRecordID,
		}
	}
	var connectivity *ConnectivityEvidence
	if ev.ConnectivityOnline != nil || ev.ConnectivityPolicyVersion != "" || !ev.ConnectivityLastSyncedAt.IsZero() {
		connectivity = &ConnectivityEvidence{
			Online:                 ev.ConnectivityOnline,
			EffectivePolicyVersion: ev.ConnectivityPolicyVersion,
			LastSyncedAt:           ev.ConnectivityLastSyncedAt,
		}
	}

	r.DLPEvidence = &DLPEvidence{
		CollectionMethod: collectionMethod,
		FixtureID:        fixtureID,
		Limitations:      limitationsFor(r.ExpectedOutcome, r.ObservedOutcome, r.Comparison, wasSkip, connectivity),
		Channel:          ev.Channel,
		Override:         override,
		Connectivity:     connectivity,
	}
	return r
}

// limitationsFor explains, in plain language, what comparison actually
// establishes for this specific expected/observed pair -- the "confidence
// and limitations" evidence-model dimension. Never implies more than the
// evidence proves: a MissingEvidence verdict is always phrased as
// inconclusive, never as a failure. See
// docs/superpowers/plans/2026-10-18-dlpevidence.md.
func limitationsFor(expected, observed string, comparison ComparisonResult, wasSkip bool, connectivity *ConnectivityEvidence) string {
	base := limitationsForComparison(expected, observed, comparison, wasSkip)
	if connectivity != nil && connectivity.Online != nil && !*connectivity.Online {
		return base + " The endpoint was offline at observation time."
	}
	return base
}

func limitationsForComparison(expected, observed string, comparison ComparisonResult, wasSkip bool) string {
	switch comparison {
	case Match:
		return fmt.Sprintf("Observed outcome %q matches the expected %q outcome.", observed, expected)
	case Mismatch:
		if observed == ObservationBlocked {
			return fmt.Sprintf("The operation was blocked even though %q was expected -- a confirmed policy deviation, not missing evidence.", expected)
		}
		return fmt.Sprintf("The operation succeeded despite an expected %q outcome -- a confirmed enforcement failure for this path.", expected)
	default: // MissingEvidence
		if observed == ObservationUnknown {
			if wasSkip {
				// StatusNotTested: a recognized skip: marker means a required
				// precondition/capability was confirmed absent -- this step
				// did not run at all, a stronger and more specific claim than
				// "no usable observation", never hedged as "may have been
				// skipped" now that Status itself distinguishes the two cases.
				return "This step did not run -- a required precondition or capability (client tool, applicable technique, etc.) was confirmed absent. This is not evidence of either enforcement or a failure; it was never tested."
			}
			return "No usable observation was collected for this step (it produced no recognizable completion marker) -- this is not evidence of either enforcement or a failure."
		}
		// observed == ObservationSucceeded against a softer expected outcome
		// (Warn/Justify/Audit/Quarantine/Encrypt/Redact): the step only
		// confirmed its own completion, which cannot confirm or rule out
		// whether that outcome actually fired.
		return fmt.Sprintf("The step only confirmed that its operation completed; this is not evidence that the expected %q behavior occurred or did not occur -- it remains unverified.", expected)
	}
}

// isSkipMarker reports whether raw's first line matches the "skip:"
// convention internal/scenario/outcome.go's classifyExecution already
// established (case-insensitive, leading whitespace tolerated). This is a
// small local equivalent, not a cross-package call: internal/scenario's
// own firstLine/classifyExecution use the identical convention, but
// firstLine is unexported there and this package deliberately stays a
// pure function throughout (see this file's own top-of-file doc comment).
func isSkipMarker(raw string) bool {
	first, _, _ := strings.Cut(strings.TrimLeft(raw, "\r\n"), "\n")
	first = strings.TrimSpace(first)
	return len(first) >= 5 && strings.EqualFold(first[:5], "skip:")
}
