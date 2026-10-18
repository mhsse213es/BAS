package phishbridge

import (
	"archive/zip"
	"bytes"
	"context"
	"fmt"

	"github.com/audspect/bas/internal/emailgwefficacy"
	"github.com/audspect/bas/internal/exercise"
)

// pdfEmbeddedLinkURI and officeExternalLinkURI are the synthetic,
// non-functional lab URIs embedded in the generated test artifacts --
// never a real, working endpoint, matching every other lab URL in
// this package (e.g. lookalike-login-lab.test).
const (
	pdfEmbeddedLinkURI    = "http://lookalike-login-lab.test/pdf-click"
	officeExternalLinkURI = "http://lookalike-login-lab.test/docx-click"
)

// buildMinimalPDFWithLink returns a complete, valid, minimal PDF
// (catalog -> pages -> one page carrying a /Link annotation whose
// action is a /URI pointing at uri) with a byte-accurate xref table --
// not a fixture string with an embedded link substring, an actual
// parseable PDF a real reader can open. Reproducible: calling this
// twice with the same uri produces byte-identical output.
func buildMinimalPDFWithLink(uri string) []byte {
	var buf bytes.Buffer
	buf.WriteString("%PDF-1.4\n")

	var offsets [5]int
	writeObj := func(n int, body string) {
		offsets[n] = buf.Len()
		fmt.Fprintf(&buf, "%d 0 obj\n%s\nendobj\n", n, body)
	}

	writeObj(1, "<< /Type /Catalog /Pages 2 0 R >>")
	writeObj(2, "<< /Type /Pages /Kids [3 0 R] /Count 1 >>")
	writeObj(3, "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] /Annots [4 0 R] >>")
	writeObj(4, fmt.Sprintf("<< /Type /Annot /Subtype /Link /Rect [10 10 190 30] /Border [0 0 0] /A << /Type /Action /S /URI /URI (%s) >> >>", uri))

	xrefOffset := buf.Len()
	buf.WriteString("xref\n0 5\n")
	buf.WriteString("0000000000 65535 f \n")
	for n := 1; n <= 4; n++ {
		fmt.Fprintf(&buf, "%010d 00000 n \n", offsets[n])
	}
	fmt.Fprintf(&buf, "trailer\n<< /Size 5 /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF", xrefOffset)

	return buf.Bytes()
}

// buildMinimalDOCXWithExternalLink returns a complete, valid, minimal
// OOXML Word document (a real ZIP archive: [Content_Types].xml,
// package relationships, word/document.xml, and word/_rels/
// document.xml.rels declaring an EXTERNAL hyperlink relationship to
// uri) -- an actual document.xml + relationship-id reference a real
// reader resolves to uri, not just uri appearing somewhere in the
// bytes. Reproducible: calling this twice with the same uri produces
// byte-identical output (archive/zip writes in insertion order with
// no timestamps set here).
func buildMinimalDOCXWithExternalLink(uri string) ([]byte, error) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)

	files := []struct{ name, body string }{
		{"[Content_Types].xml", `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
<Default Extension="xml" ContentType="application/xml"/>
<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>
</Types>`},
		{"_rels/.rels", `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>
</Relationships>`},
		{"word/document.xml", `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">
<w:body>
<w:p><w:hyperlink r:id="rId1"><w:r><w:t>Click here</w:t></w:r></w:hyperlink></w:p>
</w:body>
</w:document>`},
		{"word/_rels/document.xml.rels", fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/hyperlink" Target="%s" TargetMode="External"/>
</Relationships>`, uri)},
	}

	for _, f := range files {
		w, err := zw.Create(f.name)
		if err != nil {
			return nil, fmt.Errorf("buildMinimalDOCXWithExternalLink: create %s: %w", f.name, err)
		}
		if _, err := w.Write([]byte(f.body)); err != nil {
			return nil, fmt.Errorf("buildMinimalDOCXWithExternalLink: write %s: %w", f.name, err)
		}
	}
	if err := zw.Close(); err != nil {
		return nil, fmt.Errorf("buildMinimalDOCXWithExternalLink: close: %w", err)
	}
	return buf.Bytes(), nil
}

// PDFEmbeddedLinkExpectation builds PH-ATT-002's MailExpectation: a
// real, valid, minimal PDF attachment carrying a /Link annotation to
// a synthetic lab URL. caught=true is the known-good case (content/
// URL inspection catches the embedded link); caught=false is the
// known-bad case (the same attachment delivered uninspected).
func PDFEmbeddedLinkExpectation(caught bool) emailgwefficacy.MailExpectation {
	exp := emailgwefficacy.MailExpectation{
		SenderProfile:  "pdf-embedded-link",
		Recipient:      "finance-test@example-lab.test",
		MessageClass:   "pdf-embedded-link",
		ControlProduct: "m365-defender-o365",
		Note:           "real, valid, minimal PDF attachment carrying a /Link annotation to a synthetic lab URL -- tests content/URL inspection reaching inside a PDF attachment, distinct from EICARAttachmentExpectation's generic malicious-MIME-content test",
		EnvelopeFrom:   "billing@pdf-attachment-lab.test",
	}
	if caught {
		exp.ExpectedAction = emailgwefficacy.ExpectedQuarantine
	} else {
		exp.ExpectedAction = emailgwefficacy.ExpectedDeliver
	}
	return exp
}

// OfficeExternalLinkExpectation builds PH-ATT-003's MailExpectation:
// a real, valid, minimal OOXML Word document attachment carrying an
// external hyperlink relationship to a synthetic lab URL. caught=true
// is the known-good case; caught=false is the known-bad case.
func OfficeExternalLinkExpectation(caught bool) emailgwefficacy.MailExpectation {
	exp := emailgwefficacy.MailExpectation{
		SenderProfile:  "office-external-link",
		Recipient:      "finance-test@example-lab.test",
		MessageClass:   "office-external-link",
		ControlProduct: "m365-defender-o365",
		Note:           "real, valid, minimal OOXML Word document attachment carrying an external hyperlink relationship to a synthetic lab URL -- tests content/URL inspection reaching inside an Office document's own relationship part, distinct from EICARAttachmentExpectation's generic malicious-MIME-content test",
		EnvelopeFrom:   "documents@office-attachment-lab.test",
	}
	if caught {
		exp.ExpectedAction = emailgwefficacy.ExpectedQuarantine
	} else {
		exp.ExpectedAction = emailgwefficacy.ExpectedDeliver
	}
	return exp
}

// DispatchPDFEmbeddedLink sends PH-ATT-002's real test message, PDF
// attachment included, via emailgwefficacy.InjectScenarioMessage.
func DispatchPDFEmbeddedLink(ctx context.Context, target emailgwefficacy.InjectionTarget, exp emailgwefficacy.MailExpectation) (emailgwefficacy.OriginDeliveryObservation, error) {
	content := emailgwefficacy.InjectableMessage{
		Subject:  "Q3 invoice attached",
		BodyHTML: "<p>Please see the attached invoice.</p>",
		Attachment: &exercise.TestAttachment{
			Filename:    "invoice.pdf",
			ContentType: "application/pdf",
			Content:     buildMinimalPDFWithLink(pdfEmbeddedLinkURI),
		},
	}
	return emailgwefficacy.InjectScenarioMessage(ctx, target, exp, content)
}

// DispatchOfficeExternalLink sends PH-ATT-003's real test message,
// Office document attachment included, via
// emailgwefficacy.InjectScenarioMessage.
func DispatchOfficeExternalLink(ctx context.Context, target emailgwefficacy.InjectionTarget, exp emailgwefficacy.MailExpectation) (emailgwefficacy.OriginDeliveryObservation, error) {
	docx, err := buildMinimalDOCXWithExternalLink(officeExternalLinkURI)
	if err != nil {
		return emailgwefficacy.OriginDeliveryObservation{}, fmt.Errorf("DispatchOfficeExternalLink: %w", err)
	}
	content := emailgwefficacy.InjectableMessage{
		Subject:  "Updated vendor agreement attached",
		BodyHTML: "<p>Please review the attached document.</p>",
		Attachment: &exercise.TestAttachment{
			Filename:    "agreement.docx",
			ContentType: "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
			Content:     docx,
		},
	}
	return emailgwefficacy.InjectScenarioMessage(ctx, target, exp, content)
}
