package emailgwefficacy

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"io"
	"mime"
	"mime/multipart"
	"net/mail"
	"strings"
	"testing"
)

// Container matrix: the same EICAR / benign content as the attachment matrix, wrapped in archive and message
// containers. Each test unwraps the container the way a scanning gateway has to and checks what is inside.

func unzipOnly(t *testing.T, data []byte) (string, []byte) {
	t.Helper()
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatalf("not a valid zip: %v", err)
	}
	if len(zr.File) != 1 {
		t.Fatalf("zip has %d entries, want exactly 1", len(zr.File))
	}
	rc, err := zr.File[0].Open()
	if err != nil {
		t.Fatal(err)
	}
	defer rc.Close()
	b, _ := io.ReadAll(rc)
	return zr.File[0].Name, b
}

func TestArchiveZip_OneLevelHoldsEICAR(t *testing.T) {
	content := checkAttachmentScenario(t, "EG-021.archive-zip.known-good", "EG-021.archive-zip.known-bad", "archive-zip")
	if content.Attachment.Filename != "documents.zip" || content.Attachment.ContentType != "application/zip" {
		t.Errorf("attachment = %q / %q", content.Attachment.Filename, content.Attachment.ContentType)
	}
	_, inner := unzipOnly(t, content.Attachment.Content)
	if string(inner) != eicarTestString {
		t.Error("the file inside the zip must be the EICAR test string")
	}
}

func TestNestedArchive_ThreeZipLevelsDeep(t *testing.T) {
	content := checkAttachmentScenario(t, "EG-022.nested-archive.known-good", "EG-022.nested-archive.known-bad", "nested-archive")
	data := content.Attachment.Content
	levels := 0
	for len(data) > 2 && data[0] == 'P' && data[1] == 'K' {
		_, data = unzipOnly(t, data)
		levels++
	}
	if levels != 3 {
		t.Errorf("zip depth = %d, want 3", levels)
	}
	if string(data) != eicarTestString {
		t.Error("the innermost file must be the EICAR test string")
	}
}

func TestArchiveTarGz_HoldsEICAR(t *testing.T) {
	content := checkAttachmentScenario(t, "EG-023.archive-targz.known-good", "EG-023.archive-targz.known-bad", "archive-targz")
	if content.Attachment.Filename != "backup.tar.gz" {
		t.Errorf("Filename = %q", content.Attachment.Filename)
	}
	gz, err := gzip.NewReader(bytes.NewReader(content.Attachment.Content))
	if err != nil {
		t.Fatalf("not gzip: %v", err)
	}
	tr := tar.NewReader(gz)
	hdr, err := tr.Next()
	if err != nil {
		t.Fatalf("no tar entry: %v", err)
	}
	b, _ := io.ReadAll(tr)
	if hdr.Name == "" || string(b) != eicarTestString {
		t.Errorf("tar entry %q holds %q, want the EICAR test string", hdr.Name, b)
	}
	if _, err := tr.Next(); err != io.EOF {
		t.Error("the tarball must hold exactly one file")
	}
}

func TestAttachedMessage_InnerEmailCarriesEICAR(t *testing.T) {
	content := checkAttachmentScenario(t, "EG-024.attached-message.known-good", "EG-024.attached-message.known-bad", "attached-message")
	if content.Attachment.Filename != "forwarded.eml" || content.Attachment.ContentType != "message/rfc822" {
		t.Errorf("attachment = %q / %q", content.Attachment.Filename, content.Attachment.ContentType)
	}
	msg, err := mail.ReadMessage(bytes.NewReader(content.Attachment.Content))
	if err != nil {
		t.Fatalf("the attached message does not parse: %v", err)
	}
	mt, params, err := mime.ParseMediaType(msg.Header.Get("Content-Type"))
	if err != nil || !strings.HasPrefix(mt, "multipart/") {
		t.Fatalf("inner message Content-Type = %q (%v), want multipart", mt, err)
	}
	mr := multipart.NewReader(msg.Body, params["boundary"])
	found := false
	for {
		p, err := mr.NextPart()
		if err != nil {
			break
		}
		b, _ := io.ReadAll(p)
		if p.FileName() != "" {
			found = true
			// the inner attachment is base64: decode it the way a scanner would
			dec, derr := decodeBase64Lines(string(b))
			if derr != nil || string(dec) != eicarTestString {
				t.Errorf("inner attachment %q decodes to %q (%v), want the EICAR test string", p.FileName(), dec, derr)
			}
		}
	}
	if !found {
		t.Error("the inner message has no attachment")
	}
}

func TestScriptExtensionSet_OneScenarioPerExtensionBenignContent(t *testing.T) {
	want := []string{"bat", "scr", "pif", "wsf", "jse", "vbe", "com", "cmd"}
	if got := scriptExtensionSet; strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("scriptExtensionSet = %v, want %v", got, want)
	}
	for _, ext := range want {
		id := "EG-025.script-extension-" + ext
		content := checkAttachmentScenario(t, id+".known-good", id+".known-bad", "script-extension-"+ext)
		if !strings.HasSuffix(content.Attachment.Filename, "."+ext) {
			t.Errorf("%s: filename %q must end in .%s", ext, content.Attachment.Filename, ext)
		}
		if string(content.Attachment.Content) != attachmentPolicyPlaceholderText {
			t.Errorf("%s: content must be the benign placeholder, so only the extension policy is tested", ext)
		}
	}
}

// Content discipline for the whole matrix: after unwrapping every container, the only payloads are the EICAR test
// string and the benign placeholder. Nothing else is ever sent.
func TestContainerMatrix_OnlyEICARAndPlaceholderEverReachTheWire(t *testing.T) {
	for _, id := range []string{
		"EG-021.archive-zip.known-good", "EG-022.nested-archive.known-good", "EG-023.archive-targz.known-good",
		"EG-024.attached-message.known-good", "EG-025.script-extension-bat.known-good",
	} {
		exp, ok := ExpectationByID(id)
		if !ok {
			t.Fatalf("%s missing", id)
		}
		content, ok := ScenarioTestContent(exp)
		if !ok || content.Attachment == nil {
			t.Fatalf("%s has no attachment", id)
		}
		for _, banned := range []string{"MZ", "#!/", "powershell", "cmd.exe /c", "<script"} {
			if bytes.Contains(content.Attachment.Content, []byte(banned)) && !bytes.Contains(content.Attachment.Content, []byte(eicarTestString)) {
				t.Errorf("%s contains %q, which is not EICAR or placeholder content", id, banned)
			}
		}
	}
}

// decodeBase64Lines decodes a base64 MIME body (CRLF-wrapped lines) the way a scanner would.
func decodeBase64Lines(s string) ([]byte, error) {
	clean := strings.Map(func(r rune) rune {
		if r == 13 || r == 10 { // CR, LF
			return -1
		}
		return r
	}, s)
	return base64.StdEncoding.DecodeString(clean)
}
