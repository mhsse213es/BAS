package emailgwefficacy

// PDFEmbeddedLinkExpectation builds the PDF-with-embedded-link MailExpectation
// (PH-ATT-002's email leg). The PDF is a real, valid minimal document with a
// /Link annotation to a synthetic lab URL. caught=true is the known-good case
// (the gateway quarantines the attachment); caught=false is the known-bad case.
func PDFEmbeddedLinkExpectation(caught bool) MailExpectation {
	exp := MailExpectation{
		SenderProfile:  "pdf-embedded-link",
		Recipient:      "finance-test@example-lab.test",
		MessageClass:   "pdf-embedded-link",
		ControlProduct: "m365-defender-o365",
		Note:           "real, valid, minimal PDF attachment carrying a /Link annotation to a synthetic lab URL -- tests content/URL inspection reaching inside a PDF attachment, distinct from EICARAttachmentExpectation's generic malicious-MIME-content test",
		EnvelopeFrom:   "billing@pdf-attachment-lab.test",
	}
	if caught {
		exp.ExpectedAction = ExpectedQuarantine
	} else {
		exp.ExpectedAction = ExpectedDeliver
	}
	return exp
}
