package emailgwefficacy

// OfficeExternalLinkExpectation builds the Office-document-with-external-link
// MailExpectation (PH-ATT-003's email leg): a real, valid, minimal OOXML Word
// document carrying an external hyperlink relationship to a synthetic lab URL.
// caught=true is the known-good case (the gateway quarantines the document);
// caught=false is the known-bad case.
func OfficeExternalLinkExpectation(caught bool) MailExpectation {
	exp := MailExpectation{
		SenderProfile:  "office-external-link",
		Recipient:      "finance-test@example-lab.test",
		MessageClass:   "office-external-link",
		ControlProduct: "m365-defender-o365",
		Note:           "real, valid, minimal OOXML Word document attachment carrying an external hyperlink relationship to a synthetic lab URL -- tests content/URL inspection reaching inside an Office document's own relationship part, distinct from EICARAttachmentExpectation's generic malicious-MIME-content test",
		EnvelopeFrom:   "documents@office-attachment-lab.test",
	}
	if caught {
		exp.ExpectedAction = ExpectedQuarantine
	} else {
		exp.ExpectedAction = ExpectedDeliver
	}
	return exp
}
