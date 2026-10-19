package emailgwefficacy

import (
	"testing"

	"github.com/snykk/qr-generator/qrgen"
)

// EG-011 is the email-gateway expectation PH-CHN-005's read-back grades. It
// must exist in the dispatch table, with a quarantine action (the control catches it, as in EG-002.known-good).
func TestQRCodeLure_ExpectationInDispatchTable(t *testing.T) {
	exp, ok := ExpectationByID("EG-011.qr-code-lure.known-good")
	if !ok {
		t.Fatal("EG-011.qr-code-lure.known-good must be in the dispatch table")
	}
	if exp.ExpectedAction != ExpectedQuarantine {
		t.Errorf("ExpectedAction = %q, want %q", exp.ExpectedAction, ExpectedQuarantine)
	}
	if exp.MessageClass != "qr-code-lure" {
		t.Errorf("MessageClass = %q, want %q", exp.MessageClass, "qr-code-lure")
	}
	if exp.EnvelopeFrom == "" {
		t.Error("EnvelopeFrom must be set so the inbound SMTP injector can send it")
	}
}

// The test content must carry a QR attachment that decodes back to the URI,
// so the gateway is graded on the real lure, not on text alone.
func TestQRCodeLure_TestContentDecodesToLureURI(t *testing.T) {
	exp, _ := ExpectationByID("EG-011.qr-code-lure.known-good")
	content, ok := ScenarioTestContent(exp)
	if !ok {
		t.Fatal("no test content registered for qr-code-lure")
	}
	if content.Attachment == nil || len(content.Attachment.Content) == 0 {
		t.Fatal("test content has no QR attachment")
	}
	decoded, err := qrgen.DecodeBytes(content.Attachment.Content)
	if err != nil {
		t.Fatalf("qrgen.DecodeBytes: %v", err)
	}
	if decoded != QRCodeLureURI {
		t.Errorf("decoded = %q, want %q", decoded, QRCodeLureURI)
	}
}
