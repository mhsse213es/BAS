package killchain

import (
	"fmt"
	"time"
)

// PipelineSpec makes a stage a server-side detection-pipeline check instead of an agent
// scenario. It is read-only: it queries a stored connector for a stable identifier inside
// a bounded window. It never injects an event. Credentials are not here; ConnectorID names
// a stored connector that holds them.
type PipelineSpec struct {
	ConnectorID     string `json:"connectorId"`
	Index           string `json:"index"`
	Field           string `json:"field"`
	Identifier      string `json:"identifier"`
	LookbackMinutes int    `json:"lookbackMinutes"`
}

// maxLookbackMinutes bounds the window so a stage cannot scan an unbounded history.
const maxLookbackMinutes = 1440

// Validate checks a pipeline spec. A pipeline stage must be read-only and must name no
// agent scenario.
func (p PipelineSpec) Validate(stageKey string) error {
	switch {
	case p.ConnectorID == "":
		return fmt.Errorf("killchain: stage %s pipeline needs a connectorId", stageKey)
	case p.Index == "" || p.Field == "" || p.Identifier == "":
		return fmt.Errorf("killchain: stage %s pipeline needs index, field and identifier", stageKey)
	case p.LookbackMinutes < 1 || p.LookbackMinutes > maxLookbackMinutes:
		return fmt.Errorf("killchain: stage %s pipeline lookbackMinutes must be 1 to %d", stageKey, maxLookbackMinutes)
	}
	return nil
}

// PipelineStageResult is one pipeline stage's outcome, kept with its evidence. Status is
// VERIFIED, INCONCLUSIVE, ERROR or NOT_TESTED. Stage names the capability it covers.
type PipelineStageResult struct {
	Stage      string    `json:"stage"`
	Status     string    `json:"status"`
	Reason     string    `json:"reason"`
	Connector  string    `json:"connector,omitempty"`
	Target     string    `json:"target,omitempty"`
	Identifier string    `json:"identifier,omitempty"`
	WindowFrom time.Time `json:"windowFrom,omitempty"`
	WindowTo   time.Time `json:"windowTo,omitempty"`
	MatchCount int64     `json:"matchCount"`
	EventIDs   []string  `json:"eventIds,omitempty"`
	HTTPStatus int       `json:"httpStatus,omitempty"`
	CheckedAt  time.Time `json:"checkedAt"`
}

// PipelineVerdict derives the stage verdict from its per-stage results. It never produces
// an attack verdict. A pipeline stage cannot say a control blocked or detected anything.
//
//   - Any ERROR result: ERROR, with every failing stage named. A failure is never hidden by
//     a success in another stage.
//   - Otherwise any evidence (VERIFIED or INCONCLUSIVE): INCONCLUSIVE. Ingestion can be
//     verified, but it cannot establish normalisation, correlation or the rest.
//   - Otherwise: NOT_TESTED.
func PipelineVerdict(results []PipelineStageResult) (Verdict, []string) {
	if len(results) == 0 {
		return VerdictNotTested, []string{"no pipeline stage was checked"}
	}
	var errs, reasons []string
	evidence := false
	for _, r := range results {
		switch r.Status {
		case "ERROR":
			errs = append(errs, fmt.Sprintf("%s: %s", r.Stage, r.Reason))
		case "VERIFIED", "INCONCLUSIVE":
			evidence = true
			reasons = append(reasons, fmt.Sprintf("%s %s: %s", r.Stage, r.Status, r.Reason))
		default:
			reasons = append(reasons, fmt.Sprintf("%s NOT_TESTED: %s", r.Stage, r.Reason))
		}
	}
	if len(errs) > 0 {
		return VerdictError, append(errs, reasons...)
	}
	if evidence {
		return VerdictInconclusive, reasons
	}
	return VerdictNotTested, reasons
}
