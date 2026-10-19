package phishbridge

import (
	"bytes"
	"testing"

	"github.com/audspect/bas/internal/emailgwefficacy"
)

// EG-012 is the email-gateway expectation PH-ATT-002's read-back grades. Its
// known-good form (the gateway quarantines the PDF) is the one PH-ATT-002 maps to.
func TestPDFEmbeddedLink_ExpectationInDispatchTable(t *testing.T) {
	exp, ok := emailgwefficacy.ExpectationByID("EG-012.pdf-embedded-link.known-good")
	if !ok {
		t.Fatal("EG-012.pdf-embedded-link.known-good must be in the dispatch table")
	}
	if exp.ExpectedAction != emailgwefficacy.ExpectedQuarantine {
		t.Errorf("ExpectedAction = %q, want %q", exp.ExpectedAction, emailgwefficacy.ExpectedQuarantine)
	}
	if exp.MessageClass != "pdf-embedded-link" {
		t.Errorf("MessageClass = %q, want %q", exp.MessageClass, "pdf-embedded-link")
	}
}

// The registered test content must carry a real PDF whose link annotation
// targets the lure URI, so the gateway is graded on the actual lure.
func TestPDFEmbeddedLink_TestContentIsPDFWithLureLink(t *testing.T) {
	exp, _ := emailgwefficacy.ExpectationByID("EG-012.pdf-embedded-link.known-good")
	content, ok := emailgwefficacy.ScenarioTestContent(exp)
	if !ok {
		t.Fatal("no test content registered for pdf-embedded-link")
	}
	if content.Attachment == nil {
		t.Fatal("test content has no PDF attachment")
	}
	pdf := content.Attachment.Content
	if !bytes.HasPrefix(pdf, []byte("%PDF-")) {
		t.Fatal("attachment is not a PDF")
	}
	if !bytes.Contains(pdf, []byte(pdfEmbeddedLinkURI)) {
		t.Errorf("PDF does not contain the lure URI %q", pdfEmbeddedLinkURI)
	}
}
