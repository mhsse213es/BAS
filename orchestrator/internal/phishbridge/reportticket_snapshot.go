package phishbridge

import (
	"fmt"
	"time"

	"github.com/audspect/bas/internal/emailgwefficacy"
	"github.com/audspect/bas/internal/phishval"
)

// ReportTicketSnapshot is one ticket search, retained as evidence. Records are what
// the search returned. Completeness says whether the search covered everything it
// was asked for. Only a Complete search can turn an empty result into a finding.
type ReportTicketSnapshot struct {
	ExecutionID  string
	TargetID     string
	Window       emailgwefficacy.TimeWindow
	CollectedAt  time.Time
	Completeness phishval.CollectionCompleteness
	Records      []ReportTicketEvidence
	Reason       string
}

// ReportTicketSnapshotProvider is the completeness-aware evidence contract. A
// connector implements it to report pagination, limits, and failures, so an absent
// ticket can be told apart from an unread one.
type ReportTicketSnapshotProvider interface {
	SnapshotReportTickets(executionID, targetID string, window emailgwefficacy.TimeWindow) (ReportTicketSnapshot, error)
}

// SnapshotFromLegacy adapts a provider that cannot report completeness. Its results
// are Partial, because nothing says the search was complete. A failed search is
// Failed. Absence from a Partial search can never support a missed-detection verdict.
func SnapshotFromLegacy(p ReportTicketEvidenceProvider) ReportTicketSnapshotProvider {
	return legacyReportTicketSnapshot{p: p}
}

type legacyReportTicketSnapshot struct {
	p ReportTicketEvidenceProvider
}

func (l legacyReportTicketSnapshot) SnapshotReportTickets(executionID, targetID string, window emailgwefficacy.TimeWindow) (ReportTicketSnapshot, error) {
	snap := ReportTicketSnapshot{ExecutionID: executionID, TargetID: targetID, Window: window, CollectedAt: time.Now().UTC()}
	records, err := l.p.ReportTicketEvidenceFor(executionID, targetID, window)
	if err != nil {
		snap.Completeness = phishval.CollectionFailed
		snap.Reason = fmt.Sprintf("collection failed: %v", err)
		return snap, nil
	}
	snap.Records = records
	snap.Completeness = phishval.CollectionPartial
	snap.Reason = "provider reports no completeness; an empty result is not proof of absence"
	return snap, nil
}

// VerifyReportTicketSnapshot grades the expectation against one retained search.
//
// Rules, in order:
//   - A failed search is Inconclusive, whatever it returned.
//   - A matching record is positive evidence and passes, even from a partial search.
//   - A record that contradicts the expectation fails only if the search was complete.
//     Otherwise an unread page could hold the record that changes the answer.
//   - No records: a Complete search that expected a ticket is a missed-ticket finding.
//     A Complete search that expected none passes. Any incomplete search is Inconclusive.
//
// Duplicate records for the same ticket do not change the answer, because the most
// recent record decides.
func VerifyReportTicketSnapshot(exp ReportTicketExpectation, snap ReportTicketSnapshot) emailgwefficacy.VerdictDetail {
	if snap.Completeness == phishval.CollectionFailed {
		return emailgwefficacy.VerdictDetail{Verdict: emailgwefficacy.VerdictInconclusive,
			Reason: "ticketing evidence collection failed: " + snap.Reason}
	}
	if len(snap.Records) > 0 {
		latest := snap.Records[0]
		for _, r := range snap.Records[1:] {
			if r.Timestamp.After(latest.Timestamp) {
				latest = r
			}
		}
		if latest.TicketCreated == exp.ExpectedTicketCreated {
			return emailgwefficacy.VerdictDetail{Verdict: emailgwefficacy.VerdictConfirmedSuccess,
				Reason: fmt.Sprintf("matching ticket record found (%s search)", snap.Completeness)}
		}
		if snap.Completeness != phishval.CollectionComplete {
			return emailgwefficacy.VerdictDetail{Verdict: emailgwefficacy.VerdictInconclusive,
				Reason: fmt.Sprintf("a record contradicts the expectation, but the search was %s, so an unread record could change the answer", snap.Completeness)}
		}
		return emailgwefficacy.VerdictDetail{Verdict: emailgwefficacy.VerdictConfirmedFailure,
			Reason: fmt.Sprintf("complete search: ticket created=%t did not match expected=%t", latest.TicketCreated, exp.ExpectedTicketCreated)}
	}
	if snap.Completeness != phishval.CollectionComplete {
		return emailgwefficacy.VerdictDetail{Verdict: emailgwefficacy.VerdictInconclusive,
			Reason: fmt.Sprintf("no ticketing record found, but the search was %s; absence is not evidence", snap.Completeness)}
	}
	if exp.ExpectedTicketCreated {
		return emailgwefficacy.VerdictDetail{Verdict: emailgwefficacy.VerdictConfirmedFailure,
			Reason: "complete search found no ticket for this report event: a missed triage"}
	}
	return emailgwefficacy.VerdictDetail{Verdict: emailgwefficacy.VerdictConfirmedSuccess,
		Reason: "complete search found no ticket, and none was expected"}
}

// FixtureSnapshotProvider wraps the in-memory fixture with a chosen completeness, so
// tests can model complete, partial, truncated, and failed searches.
type FixtureSnapshotProvider struct {
	inner        *FixtureReportTicketProvider
	completeness phishval.CollectionCompleteness
	fail         error
}

func NewFixtureSnapshotProvider(events []ReportTicketEvidence, completeness phishval.CollectionCompleteness) *FixtureSnapshotProvider {
	return &FixtureSnapshotProvider{inner: NewFixtureReportTicketProvider(events), completeness: completeness}
}

// WithFailure makes every search fail, as a connector outage would.
func (f *FixtureSnapshotProvider) WithFailure(err error) *FixtureSnapshotProvider {
	f.fail = err
	return f
}

func (f *FixtureSnapshotProvider) SnapshotReportTickets(executionID, targetID string, window emailgwefficacy.TimeWindow) (ReportTicketSnapshot, error) {
	snap := ReportTicketSnapshot{ExecutionID: executionID, TargetID: targetID, Window: window, CollectedAt: time.Now().UTC()}
	if f.fail != nil {
		snap.Completeness = phishval.CollectionFailed
		snap.Reason = fmt.Sprintf("collection failed: %v", f.fail)
		return snap, nil
	}
	records, err := f.inner.ReportTicketEvidenceFor(executionID, targetID, window)
	if err != nil {
		return snap, err
	}
	snap.Records = records
	snap.Completeness = f.completeness
	if f.completeness != phishval.CollectionComplete {
		snap.Reason = "fixture search was " + string(f.completeness)
	}
	return snap, nil
}

// ReportTicketEvidenceFor keeps the fixture usable wherever the older interface is
// expected. The completeness contract is read through SnapshotReportTickets.
func (f *FixtureSnapshotProvider) ReportTicketEvidenceFor(executionID, targetID string, window emailgwefficacy.TimeWindow) ([]ReportTicketEvidence, error) {
	if f.fail != nil {
		return nil, f.fail
	}
	return f.inner.ReportTicketEvidenceFor(executionID, targetID, window)
}
