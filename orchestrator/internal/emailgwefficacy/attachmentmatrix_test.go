package emailgwefficacy

import (
	"strings"
	"testing"
)

// checkAttachmentScenario asserts the common contract every scenario in
// this matrix must meet: present in the dispatch table with the right
// action, a MessageClass matching knownGoodID's own suffix, EnvelopeFrom
// set (so the injector can actually send it), and real registered test
// content carrying an attachment.
func checkAttachmentScenario(t *testing.T, knownGoodID, knownBadID, wantMessageClass string) InjectableMessage {
	t.Helper()
	good, ok := ExpectationByID(knownGoodID)
	if !ok {
		t.Fatalf("%s must be in the dispatch table", knownGoodID)
	}
	if good.ExpectedAction != ExpectedQuarantine {
		t.Errorf("%s ExpectedAction = %q, want %q", knownGoodID, good.ExpectedAction, ExpectedQuarantine)
	}
	if good.MessageClass != wantMessageClass {
		t.Errorf("%s MessageClass = %q, want %q", knownGoodID, good.MessageClass, wantMessageClass)
	}
	if good.EnvelopeFrom == "" {
		t.Errorf("%s EnvelopeFrom must be set so the inbound SMTP injector can send it", knownGoodID)
	}

	bad, ok := ExpectationByID(knownBadID)
	if !ok {
		t.Fatalf("%s must be in the dispatch table", knownBadID)
	}
	if bad.ExpectedAction != ExpectedDeliver {
		t.Errorf("%s ExpectedAction = %q, want %q", knownBadID, bad.ExpectedAction, ExpectedDeliver)
	}

	content, ok := ScenarioTestContent(good)
	if !ok {
		t.Fatalf("no test content registered for message class %q", wantMessageClass)
	}
	if content.Attachment == nil || len(content.Attachment.Content) == 0 {
		t.Fatalf("message class %q has no attachment content", wantMessageClass)
	}
	return content
}

func TestMalwareCategoryAttachment_WiredAndDistinctFromEG004(t *testing.T) {
	content := checkAttachmentScenario(t, "EG-017.malware-category-script.known-good", "EG-017.malware-category-script.known-bad", "malware-category-script")
	if content.Attachment.Filename != "setup.js" {
		t.Errorf("Filename = %q, want setup.js", content.Attachment.Filename)
	}
	if content.Attachment.ContentType == "application/octet-stream" {
		t.Error("ContentType must differ from EG-004's own container, not just the filename")
	}
	if string(content.Attachment.Content) != eicarTestString {
		t.Error("content must be the industry-standard EICAR test string")
	}
}

func TestRansomwareStandIn_DoubleExtensionDisguise(t *testing.T) {
	content := checkAttachmentScenario(t, "EG-018.ransomware-stand-in.known-good", "EG-018.ransomware-stand-in.known-bad", "ransomware-stand-in")
	if content.Attachment.Filename != "invoice.pdf.exe" {
		t.Errorf("Filename = %q, want the double-extension invoice.pdf.exe", content.Attachment.Filename)
	}
	if !strings.HasSuffix(content.Attachment.Filename, ".exe") {
		t.Error("the real extension must be the executable one, the whole point of the disguise")
	}
	if string(content.Attachment.Content) != eicarTestString {
		t.Error("content must be the industry-standard EICAR test string, never real ransomware code")
	}
}

func TestFileTypeSpoofing_DeclaredTypeDoesNotMatchContent(t *testing.T) {
	content := checkAttachmentScenario(t, "EG-019.file-type-spoofing.known-good", "EG-019.file-type-spoofing.known-bad", "file-type-spoofing")
	if content.Attachment.Filename != "contract.docx" {
		t.Errorf("Filename = %q, want contract.docx", content.Attachment.Filename)
	}
	if content.Attachment.ContentType != "application/vnd.openxmlformats-officedocument.wordprocessingml.document" {
		t.Errorf("ContentType = %q, want the Word-document MIME type it falsely claims", content.Attachment.ContentType)
	}
	// A real OOXML document is a ZIP container and starts with the "PK"
	// magic bytes. This attachment's declared type claims that format
	// while its actual content does not -- that mismatch is the scenario.
	if strings.HasPrefix(string(content.Attachment.Content), "PK") {
		t.Fatal("content must NOT be a real OOXML document -- the declared-type/actual-content mismatch is the entire point of this scenario")
	}
}

func TestBlockedExtensionPolicy_IsolatedFromContentScanning(t *testing.T) {
	content := checkAttachmentScenario(t, "EG-020.blocked-extension-policy.known-good", "EG-020.blocked-extension-policy.known-bad", "blocked-extension-policy")
	if content.Attachment.Filename != "backup.vbs" {
		t.Errorf("Filename = %q, want backup.vbs", content.Attachment.Filename)
	}
	if strings.Contains(string(content.Attachment.Content), "EICAR") {
		t.Fatal("this scenario must carry no EICAR content -- it tests pure extension-policy enforcement, isolated from content scanning, unlike every other scenario in this matrix")
	}
}

// Every scenario in this matrix must send the EICAR test string only when
// its own Note says it does -- the three malware/ransomware/spoofing
// scenarios do, the extension-policy one deliberately does not.
func TestAttachmentMatrix_OnlyThreeOfFourCarryEICAR(t *testing.T) {
	cases := map[string]bool{
		"malware-category-script":  true,
		"ransomware-stand-in":      true,
		"file-type-spoofing":       true,
		"blocked-extension-policy": false,
	}
	for messageClass, wantEICAR := range cases {
		exp := MailExpectation{MessageClass: messageClass}
		content, ok := ScenarioTestContent(exp)
		if !ok {
			t.Fatalf("no content registered for %q", messageClass)
		}
		gotEICAR := string(content.Attachment.Content) == eicarTestString
		if gotEICAR != wantEICAR {
			t.Errorf("%s: content is EICAR = %v, want %v", messageClass, gotEICAR, wantEICAR)
		}
	}
}
