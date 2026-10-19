package phishbridge

import (
	"archive/zip"
	"bytes"
	"io"
	"strings"
	"testing"

	"github.com/audspect/bas/internal/emailgwefficacy"
)

// EG-013 is the email-gateway expectation PH-ATT-003's read-back grades. Its
// known-good form (the gateway quarantines the document) is the one PH-ATT-003 maps to.
func TestOfficeExternalLink_ExpectationInDispatchTable(t *testing.T) {
	exp, ok := emailgwefficacy.ExpectationByID("EG-013.office-external-link.known-good")
	if !ok {
		t.Fatal("EG-013.office-external-link.known-good must be in the dispatch table")
	}
	if exp.ExpectedAction != emailgwefficacy.ExpectedQuarantine {
		t.Errorf("ExpectedAction = %q, want %q", exp.ExpectedAction, emailgwefficacy.ExpectedQuarantine)
	}
	if exp.MessageClass != "office-external-link" {
		t.Errorf("MessageClass = %q, want %q", exp.MessageClass, "office-external-link")
	}
}

// The registered test content must carry a real DOCX whose relationship part
// targets the lure URI. The DOCX is deflate-compressed, so the test opens the
// archive and reads its relationship XML, rather than searching raw bytes.
func TestOfficeExternalLink_TestContentIsDOCXWithLureRelationship(t *testing.T) {
	exp, _ := emailgwefficacy.ExpectationByID("EG-013.office-external-link.known-good")
	content, ok := emailgwefficacy.ScenarioTestContent(exp)
	if !ok {
		t.Fatal("no test content registered for office-external-link")
	}
	if content.Attachment == nil {
		t.Fatal("test content has no DOCX attachment")
	}
	zr, err := zip.NewReader(bytes.NewReader(content.Attachment.Content), int64(len(content.Attachment.Content)))
	if err != nil {
		t.Fatalf("attachment is not a ZIP/DOCX: %v", err)
	}
	found := false
	for _, f := range zr.File {
		if !strings.HasSuffix(f.Name, ".rels") {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			t.Fatalf("open %s: %v", f.Name, err)
		}
		body, _ := io.ReadAll(rc)
		rc.Close()
		if strings.Contains(string(body), officeExternalLinkURI) {
			found = true
		}
	}
	if !found {
		t.Errorf("no relationship part in the DOCX targets %q", officeExternalLinkURI)
	}
}
