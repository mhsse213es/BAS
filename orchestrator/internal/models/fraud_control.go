package models

// FraudControl records whether the banking application detected or prevented an
// unauthorized transaction. It is scored independently of the endpoint verdict.
type FraudControl struct {
	Step            string `json:"step"`
	ExpectedControl string `json:"expectedControl"` // prevent | detect | verify
	LedgerCalled    bool   `json:"ledgerCalled"`
	LedgerDecision  string `json:"ledgerDecision,omitempty"` // approved | rejected | flagged
	RuleFired       string `json:"ruleFired,omitempty"`
	AlertPresent    bool   `json:"alertPresent,omitempty"`
	AuditIntact     bool   `json:"auditIntact,omitempty"`
	AuditHash       string `json:"auditHash,omitempty"`
	Verdict         string `json:"verdict"` // PASS | FAIL | SKIPPED
	Reason          string `json:"reason,omitempty"`
}
