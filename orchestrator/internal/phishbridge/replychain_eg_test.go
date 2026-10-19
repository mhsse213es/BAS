package phishbridge

import (
	"testing"

	"github.com/audspect/bas/internal/emailgwefficacy"
)

// EG-015 is the email-gateway expectation PH-BEC-006's read-back grades. Its
// known-good form (the gateway quarantines the reply-chain message) is the one
// PH-BEC-006 maps to.
func TestReplyChainHijack_ExpectationInDispatchTable(t *testing.T) {
	exp, ok := emailgwefficacy.ExpectationByID("EG-015.reply-chain-hijack.known-good")
	if !ok {
		t.Fatal("EG-015.reply-chain-hijack.known-good must be in the dispatch table")
	}
	if exp.ExpectedAction != emailgwefficacy.ExpectedQuarantine {
		t.Errorf("ExpectedAction = %q, want %q", exp.ExpectedAction, emailgwefficacy.ExpectedQuarantine)
	}
	if exp.MessageClass != "reply-chain-hijack" {
		t.Errorf("MessageClass = %q, want %q", exp.MessageClass, "reply-chain-hijack")
	}
}

// The registered test content must be the reply-chain message itself.
func TestReplyChainHijack_TestContentRegistered(t *testing.T) {
	exp, _ := emailgwefficacy.ExpectationByID("EG-015.reply-chain-hijack.known-good")
	content, ok := emailgwefficacy.ScenarioTestContent(exp)
	if !ok {
		t.Fatal("no test content registered for reply-chain-hijack")
	}
	if content.Subject != replyChainHijackContent.Subject {
		t.Errorf("Subject = %q, want %q", content.Subject, replyChainHijackContent.Subject)
	}
}
