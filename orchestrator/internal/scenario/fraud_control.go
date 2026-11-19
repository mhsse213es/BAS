package scenario

import (
	"encoding/json"
	"strings"

	"github.com/audspect/bas/internal/models"
)

const fraudMarkerPrefix = "BAS-FRAUD-CONTROL "

// fraudMarker is the structured line a fraud step prints after calling the ledger.
type fraudMarker struct {
	Step            string `json:"step"`
	ExpectedControl string `json:"expected_control"`
	LedgerCalled    bool   `json:"ledger_called"`
	LedgerDecision  string `json:"ledger_decision"`
	RuleFired       string `json:"rule_fired"`
	AlertPresent    bool   `json:"alert_present"`
	AuditIntact     bool   `json:"audit_intact"`
	AuditHash       string `json:"audit_hash"`
}

// ParseFraudControl finds the BAS-FRAUD-CONTROL marker in step output and returns
// the scored fraud-control record. It returns false when there is no marker or it
// is not valid JSON.
func ParseFraudControl(output string) (*models.FraudControl, bool) {
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, fraudMarkerPrefix) {
			continue
		}
		var m fraudMarker
		if err := json.Unmarshal([]byte(strings.TrimPrefix(line, fraudMarkerPrefix)), &m); err != nil {
			return nil, false
		}
		rec := models.FraudControl{
			Step:            m.Step,
			ExpectedControl: m.ExpectedControl,
			LedgerCalled:    m.LedgerCalled,
			LedgerDecision:  m.LedgerDecision,
			RuleFired:       m.RuleFired,
			AlertPresent:    m.AlertPresent,
			AuditIntact:     m.AuditIntact,
			AuditHash:       m.AuditHash,
		}
		rec.Verdict, rec.Reason = FraudVerdict(rec)
		return &rec, true
	}
	return nil, false
}

// FraudVerdict scores one fraud-control record. It returns PASS, FAIL, or SKIPPED
// and a short reason.
//   - ledger not called: SKIPPED (the control was never tested)
//   - prevent: PASS when the ledger rejected the action
//   - detect: PASS when the ledger flagged the action or an alert fired
//   - verify: PASS when the audit chain is intact
func FraudVerdict(rec models.FraudControl) (string, string) {
	if !rec.LedgerCalled {
		return "SKIPPED", "ledger not called"
	}
	switch rec.ExpectedControl {
	case "evidence":
		return "SKIPPED", "evidence only, not a control test"
	case "prevent":
		if rec.LedgerDecision == "rejected" {
			return "PASS", ""
		}
		return "FAIL", "ledger decision was " + rec.LedgerDecision + ", expected rejected"
	case "detect":
		if rec.LedgerDecision == "flagged" || rec.AlertPresent {
			return "PASS", ""
		}
		return "FAIL", "no flag or alert from the fraud controls"
	case "verify":
		if rec.AuditIntact {
			return "PASS", ""
		}
		return "FAIL", "audit chain did not verify"
	default:
		return "FAIL", "unknown expected_control " + rec.ExpectedControl
	}
}

// CombinedVerdict is the overall step verdict from the endpoint and fraud-control
// verdicts. It is PASS only when both are PASS. Any FAIL makes it FAIL. Otherwise
// it is SKIPPED, so an endpoint block with no ledger call is never an overall PASS.
func CombinedVerdict(endpoint, fraud string) string {
	return models.CombinedVerdict(endpoint, fraud)
}

func fraudControlFromOutput(out string) *models.FraudControl {
	rec, ok := ParseFraudControl(out)
	if !ok {
		return nil
	}
	return rec
}
