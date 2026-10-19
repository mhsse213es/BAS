package phishbridge

import (
	"testing"

	"github.com/audspect/bas/internal/emailgwefficacy"
)

// EG-014 is the email-gateway expectation PH-AUTH-007's read-back grades. Its
// known-good form (the gateway quarantines the spoofed internal sender) is the
// one PH-AUTH-007 maps to.
func TestInternalSenderSpoof_ExpectationInDispatchTable(t *testing.T) {
	exp, ok := emailgwefficacy.ExpectationByID("EG-014.internal-sender-spoof.known-good")
	if !ok {
		t.Fatal("EG-014.internal-sender-spoof.known-good must be in the dispatch table")
	}
	if exp.ExpectedAction != emailgwefficacy.ExpectedQuarantine {
		t.Errorf("ExpectedAction = %q, want %q", exp.ExpectedAction, emailgwefficacy.ExpectedQuarantine)
	}
	if exp.MessageClass != "internal-sender-helo-spoof" {
		t.Errorf("MessageClass = %q, want %q", exp.MessageClass, "internal-sender-helo-spoof")
	}
}

// The registered test content must be the spoofed IT-support message, so the
// gateway is graded on the actual lure.
func TestInternalSenderSpoof_TestContentRegistered(t *testing.T) {
	exp, _ := emailgwefficacy.ExpectationByID("EG-014.internal-sender-spoof.known-good")
	content, ok := emailgwefficacy.ScenarioTestContent(exp)
	if !ok {
		t.Fatal("no test content registered for internal-sender-helo-spoof")
	}
	if content.Subject != internalSenderSpoofContent.Subject {
		t.Errorf("Subject = %q, want %q", content.Subject, internalSenderSpoofContent.Subject)
	}
}
