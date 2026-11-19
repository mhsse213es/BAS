package emailgwefficacy

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"strings"
	"testing"
)

// Second container matrix: formats the Go standard library cannot write (7z, CAB, a password-protected ZIP) and the
// macro-enabled Office types. The files are small, generated once offline (each round-tripped with a real tool at
// generation time) and embedded from testdata/, with their SHA-256 pinned here so a change is always deliberate.

var pinnedSHA256 = map[string]string{
	"eicar.7z":            "cdf2d2b9cd92ad85299ef5c61dfbb96b70c850abb7ef36f981ea0c567906c4d5",
	"eicar.cab":           "bcd2444d07edb2a9db762574acf79b0532253633d3e8921fc93cba05d5cbb46f",
	"eicar-protected.zip": "8f8ecfee149ce45fb783ab6c81a6dda77ecdf2e7349b627a2432a36de06b3cde",
	"carrier-macro.docm":  "e8e002c44270db3fca6ebe0918894dd4da25d8158dc7ac2a40f30f0f895d28c3",
	"carrier-macro.xlsm":  "b47dc2d96c575f867c2ce8524b299262d3b10b323911ff5d4233dcc249284858",
	"carrier-macro.pptm":  "cff7daebbb3007daa929ca06af2e545e3332b37944d1218c4fa3ed7f16c675d5",
}

func embeddedFiles() map[string][]byte {
	return map[string][]byte{
		"eicar.7z": eicar7z, "eicar.cab": eicarCab, "eicar-protected.zip": eicarProtectedZip,
		"carrier-macro.docm": macroDocm, "carrier-macro.xlsm": macroXlsm, "carrier-macro.pptm": macroPptm,
	}
}

func TestContainerMatrix2_EmbeddedFilesAreExactlyTheOnesGenerated(t *testing.T) {
	for name, data := range embeddedFiles() {
		sum := sha256.Sum256(data)
		if got := hex.EncodeToString(sum[:]); got != pinnedSHA256[name] {
			t.Errorf("%s: sha256 = %s, want %s (regenerate deliberately and update the pin)", name, got, pinnedSHA256[name])
		}
	}
}

func TestContainerMatrix2_7zHasTheRealSignature(t *testing.T) {
	content := checkAttachmentScenario(t, "EG-026.archive-7z.known-good", "EG-026.archive-7z.known-bad", "archive-7z")
	if !bytes.HasPrefix(content.Attachment.Content, []byte{'7', 'z', 0xBC, 0xAF, 0x27, 0x1C}) {
		t.Error("attachment does not start with the 7z signature")
	}
	if content.Attachment.Filename != "documents.7z" || content.Attachment.ContentType != "application/x-7z-compressed" {
		t.Errorf("attachment = %q / %q", content.Attachment.Filename, content.Attachment.ContentType)
	}
}

func TestContainerMatrix2_CabIsAStoredCabinetHoldingEICAR(t *testing.T) {
	content := checkAttachmentScenario(t, "EG-027.archive-cab.known-good", "EG-027.archive-cab.known-bad", "archive-cab")
	data := content.Attachment.Content
	if !bytes.HasPrefix(data, []byte("MSCF")) {
		t.Error("attachment does not start with the cabinet signature MSCF")
	}
	if !bytes.Contains(data, []byte(eicarTestString)) {
		t.Error("the cabinet (stored, not compressed) must hold the EICAR test string")
	}
	if content.Attachment.ContentType != "application/vnd.ms-cab-compressed" {
		t.Errorf("ContentType = %q", content.Attachment.ContentType)
	}
}

func TestContainerMatrix2_ProtectedZipIsEncryptedAndTheBodyGivesThePassword(t *testing.T) {
	content := checkAttachmentScenario(t, "EG-028.archive-protected-zip.known-good", "EG-028.archive-protected-zip.known-bad", "archive-protected-zip")
	data := content.Attachment.Content
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatalf("not a valid zip: %v", err)
	}
	if len(zr.File) != 1 {
		t.Fatalf("entries = %d, want 1", len(zr.File))
	}
	f := zr.File[0]
	if f.Flags&0x1 == 0 {
		t.Error("the entry is not marked encrypted")
	}
	if f.Method != 99 {
		t.Errorf("method = %d, want 99 (AES)", f.Method)
	}
	if rc, err := f.Open(); err == nil {
		b, _ := io.ReadAll(rc)
		if bytes.Contains(b, []byte(eicarTestString)) {
			t.Error("the EICAR string is readable without the password")
		}
	}
	if !strings.Contains(content.BodyHTML, "infected") {
		t.Error("the message body must give the password, as a real sender would")
	}
	if bytes.Contains(data, []byte(eicarTestString)) {
		t.Error("EICAR is visible in the encrypted archive's bytes")
	}
}

func TestContainerMatrix2_MacroEnabledTypesCarryTheTypeButNoMacro(t *testing.T) {
	want := map[string]struct{ file, ctype, content string }{
		"docm": {"notice.docm", "application/vnd.ms-word.document.macroEnabled.12", "macroEnabled.main+xml"},
		"xlsm": {"notice.xlsm", "application/vnd.ms-excel.sheet.macroEnabled.12", "macroEnabled.main+xml"},
		"pptm": {"notice.pptm", "application/vnd.ms-powerpoint.presentation.macroEnabled.12", "macroEnabled.main+xml"},
	}
	if strings.Join(macroExtensionSet, ",") != "docm,xlsm,pptm" {
		t.Fatalf("macroExtensionSet = %v", macroExtensionSet)
	}
	for ext, w := range want {
		id := "EG-029.macro-enabled-" + ext
		content := checkAttachmentScenario(t, id+".known-good", id+".known-bad", "macro-enabled-"+ext)
		if content.Attachment.Filename != w.file || content.Attachment.ContentType != w.ctype {
			t.Errorf("%s: attachment = %q / %q", ext, content.Attachment.Filename, content.Attachment.ContentType)
		}
		data := content.Attachment.Content
		zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
		if err != nil {
			t.Fatalf("%s: not a valid package: %v", ext, err)
		}
		var types string
		for _, f := range zr.File {
			if strings.Contains(strings.ToLower(f.Name), "vba") {
				t.Errorf("%s: contains a macro part %q; this scenario tests the file type only", ext, f.Name)
			}
			if f.Name == "[Content_Types].xml" {
				rc, _ := f.Open()
				b, _ := io.ReadAll(rc)
				rc.Close()
				types = string(b)
			}
		}
		if !strings.Contains(types, w.content) {
			t.Errorf("%s: [Content_Types].xml does not declare the macro-enabled main part", ext)
		}
	}
}
