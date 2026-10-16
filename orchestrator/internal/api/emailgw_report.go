package api

// Workstream 2 of the EmailGW mastery roadmap: a unified, JSON-only
// customer-facing report composing every real data source this
// initiative already has (coverage, run history, time-based metrics,
// campaign outcomes, injection-wiring gaps) into one response -- never
// a new computation of its own, and never a confident number where
// the underlying source has none.
//
// Scenario-execution maturity (internal/emailgwefficacy's own
// ScenarioMaturity) is deliberately NOT included here: it requires
// ScenarioExecutionRecords built per-dimension from the real adapter's
// own evidence, and this initiative has never built a safe,
// unambiguous way to derive which dimension a persisted run's own
// evidence belongs to for every scenario (EG-010 in particular jointly
// correlates two). Rather than guess at that mapping and risk a wrong
// or fabricated maturity claim, this report leaves it out and names
// that gap explicitly in MaturityNote -- see internal/reporting's own
// maturity report for the real, already-correct, adapter-execution
// axis instead.
import (
	"net/http"
	"sort"
	"strconv"
	"time"

	"github.com/audspect/bas/internal/db"
	"github.com/audspect/bas/internal/emailgwcampaign"
	"github.com/audspect/bas/internal/emailgwefficacy"
	"github.com/audspect/bas/internal/emailgwrun"
)

// EmailGWCampaignOutcomeCounts is a compute-on-read breakdown of real
// campaigns by status and by template -- same posture as
// EmailGWRunsSummary.ByStatus, never a separately persisted total.
type EmailGWCampaignOutcomeCounts struct {
	Total        int            `json:"total"`
	ByStatus     map[string]int `json:"byStatus"`
	ByTemplateID map[string]int `json:"byTemplateId"`
}

func buildEmailGWCampaignOutcomeCounts(campaigns []*emailgwcampaign.Campaign) EmailGWCampaignOutcomeCounts {
	c := EmailGWCampaignOutcomeCounts{ByStatus: map[string]int{}, ByTemplateID: map[string]int{}}
	for _, camp := range campaigns {
		c.Total++
		c.ByStatus[string(camp.Status)]++
		c.ByTemplateID[camp.TemplateID]++
	}
	return c
}

// emailGWInjectionGaps derives, directly from the same two checks
// ExecuteEmailGWRun/SendOutboundTestMessage themselves enforce
// (exp.EnvelopeFrom == "" for inbound-spoofed scenarios,
// exp.OutboundSenderMailbox == "" for authenticated-outbound ones --
// a scenario is wired if EITHER is set, never both at once by
// construction), exactly which registered expectation IDs are not yet
// wired for real injection -- never a separately hand-maintained list
// that could go stale (this initiative's own Coverage Matrix already
// went stale twice from exactly that pattern, per maturity.go's own
// doc comment). An ID absent from emailgwefficacy.ExpectationByID
// entirely (e.g. EG-007's inbox-rule-based IDs, which are not a
// MailExpectation at all) counts as a gap too.
func emailGWInjectionGaps() []string {
	seen := map[string]bool{}
	var gaps []string
	for _, entry := range emailgwefficacy.EmailGWScenarioRegistry() {
		for _, id := range entry.ExpectationIDs {
			if seen[id] {
				continue
			}
			seen[id] = true
			exp, ok := emailgwefficacy.ExpectationByID(id)
			if !ok || (exp.EnvelopeFrom == "" && exp.OutboundSenderMailbox == "") {
				gaps = append(gaps, id)
			}
		}
	}
	sort.Strings(gaps)
	return gaps
}

func latestStartedAt(runs []*emailgwrun.EmailGWRun) *time.Time {
	var latest time.Time
	found := false
	for _, run := range runs {
		if !found || run.StartedAt.After(latest) {
			latest = run.StartedAt
			found = true
		}
	}
	if !found {
		return nil
	}
	return &latest
}

// EmailGWUnifiedReport is GetEmailGWReport's full response -- every
// section computed fresh, on read, from already-persisted data; no
// section is ever silently omitted when empty, so a caller always
// sees the same shape whether or not there is real history yet.
type EmailGWUnifiedReport struct {
	GeneratedAt     time.Time                    `json:"generatedAt"`
	Coverage        emailGWCoverageResponse      `json:"coverage"`
	RunsSummary     EmailGWRunsSummary           `json:"runsSummary"`
	Metrics         EmailGWMetricsResponse       `json:"metrics"`
	Campaigns       EmailGWCampaignOutcomeCounts `json:"campaigns"`
	InjectionGaps   []string                     `json:"injectionGaps"`
	LastExecutionAt *time.Time                   `json:"lastExecutionAt,omitempty"`
	MaturityNote    string                       `json:"maturityNote"`
}

const emailGWMaturityNote = "Scenario-execution maturity (adapter-proof, not customer-tenant proof) is served separately -- see internal/reporting's EmailGW scenario maturity report. It is not recomputed here: deriving it from persisted run evidence requires knowing which verdict dimension each scenario direction tests, which this report does not assume."

// GetEmailGWReport -- Workstream 2's unified customer-facing report.
// Composes GetEmailGWCoverage's own data, buildEmailGWRunsSummary,
// ComputeEmailGWTimeBasedMetrics, and a campaign outcome breakdown
// into one response. limit/minSampleSize follow GetEmailGWMetrics's
// own bounds.
func (h *Handler) GetEmailGWReport(w http.ResponseWriter, r *http.Request) {
	limit := 5000
	if l, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && l > 0 && l <= 20000 {
		limit = l
	}
	minSampleSize := DefaultEmailGWMinimumSampleSize
	if m, err := strconv.Atoi(r.URL.Query().Get("minSampleSize")); err == nil && m > 0 {
		minSampleSize = m
	}

	coverage, err := emailgwefficacy.AudspectEmailGWCoverageReport()
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	runs, err := db.ListEmailGWRuns(r.Context(), h.db, limit)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	campaigns, err := db.ListEmailGWCampaigns(r.Context(), h.db, limit)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	now := time.Now().UTC()
	respond(w, EmailGWUnifiedReport{
		GeneratedAt: now,
		Coverage:    emailGWCoverageResponse{Summary: coverage.Summary(), Areas: coverage.Areas()},
		RunsSummary: buildEmailGWRunsSummary(runs),
		Metrics: EmailGWMetricsResponse{
			Lab:      ComputeEmailGWTimeBasedMetrics(runs, emailgwrun.EnvironmentLab, minSampleSize, now),
			Customer: ComputeEmailGWTimeBasedMetrics(runs, emailgwrun.EnvironmentCustomer, minSampleSize, now),
		},
		Campaigns:       buildEmailGWCampaignOutcomeCounts(campaigns),
		InjectionGaps:   emailGWInjectionGaps(),
		LastExecutionAt: latestStartedAt(runs),
		MaturityNote:    emailGWMaturityNote,
	})
}
