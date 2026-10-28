package emailgwefficacy

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"mime/multipart"
	"net/textproto"
	"time"

	"github.com/audspect/bas/internal/exercise"
)

// Container matrix: the attachment matrix (EG-017..020) sends its content bare. Real mail rarely arrives that way, and
// gateways differ most in how deep they look, so this file wraps the same two payloads in archive and message
// containers:
//
//   - EG-021 archive-zip:        EICAR inside a ZIP (one level).
//   - EG-022 nested-archive:     EICAR inside a ZIP inside a ZIP inside a ZIP (three levels).
//   - EG-023 archive-targz:      EICAR inside a gzip-compressed tarball.
//   - EG-024 attached-message:   EICAR attached to an email that is itself attached (message/rfc822).
//   - EG-025 script-extension-*: one scenario per script or executable extension, each a benign placeholder, so only the
//     extension policy is tested (EG-020 does this for .vbs; this covers the rest of the set that real gateways are
//     expected to block).
//
// Content discipline, as everywhere in this package: the only payloads are the EICAR test string (eicarTestString) and
// the benign placeholder (attachmentPolicyPlaceholderText). The containers are built from the Go standard library, so
// no tool, template or binary sample is involved. Formats the standard library cannot write (RAR, 7z, CAB, ARJ,
// password-protected ZIP, macro-enabled Office files) are not covered here.

// scriptExtensionSet is the extension set EG-025 covers, one scenario each.
var scriptExtensionSet = []string{"bat", "scr", "pif", "wsf", "jse", "vbe", "com", "cmd"}

// containerModTime is a fixed time stamped into every archive entry so the same input always produces the same bytes.
var containerModTime = time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC)

// containerExpectation is the shared shape of the container scenarios: quarantined when caught, delivered otherwise.
func containerExpectation(messageClass, senderDomain, note string, caught bool) MailExpectation {
	exp := MailExpectation{
		SenderProfile:  "known-bad-malware-attachment",
		Recipient:      "helpdesk-test@example-lab.test",
		MessageClass:   messageClass,
		ControlProduct: "m365-defender-o365",
		Note:           note,
		EnvelopeFrom:   messageClass + "-test-sender@" + senderDomain,
	}
	if caught {
		exp.ExpectedAction = ExpectedQuarantine
	} else {
		exp.ExpectedAction = ExpectedDeliver
	}
	return exp
}

// ArchiveZipExpectation builds EG-021. caught=true is the known-good case (quarantined).
func ArchiveZipExpectation(caught bool) MailExpectation {
	return containerExpectation("archive-zip", "archive-container-lab.test",
		"the EICAR test string inside a ZIP archive (one level) -- tests whether the gateway opens an archive and scans what is in it", caught)
}

// NestedArchiveExpectation builds EG-022. caught=true is the known-good case (quarantined).
func NestedArchiveExpectation(caught bool) MailExpectation {
	return containerExpectation("nested-archive", "nested-archive-lab.test",
		"the EICAR test string inside a ZIP inside a ZIP inside a ZIP (three levels) -- tests how deep the gateway unpacks before it stops looking", caught)
}

// ArchiveTarGzExpectation builds EG-023. caught=true is the known-good case (quarantined).
func ArchiveTarGzExpectation(caught bool) MailExpectation {
	return containerExpectation("archive-targz", "tarball-container-lab.test",
		"the EICAR test string inside a gzip-compressed tarball -- tests a second archive family, since ZIP support does not imply tar.gz support", caught)
}

// AttachedMessageExpectation builds EG-024. caught=true is the known-good case (quarantined).
func AttachedMessageExpectation(caught bool) MailExpectation {
	return containerExpectation("attached-message", "forwarded-message-lab.test",
		"the EICAR test string attached to an email that is itself attached (message/rfc822) -- tests whether the gateway looks inside a forwarded message", caught)
}

// ScriptExtensionExpectation builds one EG-025 scenario for ext (one of scriptExtensionSet). The content is the benign
// placeholder, so a quarantine can only be the extension policy, never content scanning.
func ScriptExtensionExpectation(ext string, caught bool) MailExpectation {
	return containerExpectation("script-extension-"+ext, "extension-set-lab.test",
		"a ."+ext+" attachment with wholly benign content -- isolates extension-based blocking for the script and executable extensions beyond .vbs (EG-020)", caught)
}

// buildZipArchive returns a ZIP holding one file.
func buildZipArchive(name string, content []byte) []byte {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, _ := zw.CreateHeader(&zip.FileHeader{Name: name, Method: zip.Deflate, Modified: containerModTime})
	_, _ = w.Write(content)
	_ = zw.Close()
	return buf.Bytes()
}

// buildNestedZip wraps content in `levels` ZIPs; every ZIP above the innermost holds one file named inner.zip.
func buildNestedZip(levels int, innerName string, content []byte) []byte {
	data := buildZipArchive(innerName, content)
	for i := 2; i <= levels; i++ {
		data = buildZipArchive("inner.zip", data)
	}
	return data
}

// buildTarGz returns a gzip-compressed tarball holding one file.
func buildTarGz(name string, content []byte) []byte {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	gz.ModTime = containerModTime
	tw := tar.NewWriter(gz)
	_ = tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(content)), ModTime: containerModTime, Typeflag: tar.TypeReg})
	_, _ = tw.Write(content)
	_ = tw.Close()
	_ = gz.Close()
	return buf.Bytes()
}

// buildAttachedMessage returns a complete RFC 822 message (multipart/mixed) carrying one base64 attachment.
func buildAttachedMessage(innerFilename, innerContentType string, content []byte) []byte {
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	_ = mw.SetBoundary("audspect-container-boundary")
	text, _ := mw.CreatePart(textproto.MIMEHeader{"Content-Type": {"text/plain; charset=UTF-8"}})
	_, _ = text.Write([]byte("Forwarded for your review."))
	att, _ := mw.CreatePart(textproto.MIMEHeader{
		"Content-Type":              {innerContentType},
		"Content-Transfer-Encoding": {"base64"},
		"Content-Disposition":       {"attachment; filename=\"" + innerFilename + "\""},
	})
	enc := base64.StdEncoding.EncodeToString(content)
	for i := 0; i < len(enc); i += 76 {
		end := i + 76
		if end > len(enc) {
			end = len(enc)
		}
		_, _ = att.Write([]byte(enc[i:end] + "\r\n"))
	}
	_ = mw.Close()

	var msg bytes.Buffer
	msg.WriteString("MIME-Version: 1.0\r\n")
	msg.WriteString("From: forwarding-test-sender@forwarded-message-lab.test\r\n")
	msg.WriteString("To: helpdesk-test@example-lab.test\r\n")
	msg.WriteString("Subject: Forwarded notice\r\n")
	msg.WriteString("Content-Type: multipart/mixed; boundary=audspect-container-boundary\r\n")
	msg.WriteString("\r\n")
	msg.Write(body.Bytes())
	return msg.Bytes()
}

func init() {
	for id, exp := range map[string][2]MailExpectation{
		"EG-021.archive-zip":      {ArchiveZipExpectation(true), ArchiveZipExpectation(false)},
		"EG-022.nested-archive":   {NestedArchiveExpectation(true), NestedArchiveExpectation(false)},
		"EG-023.archive-targz":    {ArchiveTarGzExpectation(true), ArchiveTarGzExpectation(false)},
		"EG-024.attached-message": {AttachedMessageExpectation(true), AttachedMessageExpectation(false)},
	} {
		expectationByID[id+".known-good"] = exp[0]
		expectationByID[id+".known-bad"] = exp[1]
	}
	for _, ext := range scriptExtensionSet {
		id := "EG-025.script-extension-" + ext
		expectationByID[id+".known-good"] = ScriptExtensionExpectation(ext, true)
		expectationByID[id+".known-bad"] = ScriptExtensionExpectation(ext, false)
		RegisterScenarioTestContent("script-extension-"+ext, InjectableMessage{
			Subject:  "Notice attached",
			BodyHTML: "<p>Please find the attached notice for your review.</p>",
			Attachment: &exercise.TestAttachment{
				Filename:    "notice." + ext,
				ContentType: "application/octet-stream",
				Content:     []byte(attachmentPolicyPlaceholderText),
			},
		})
	}

	RegisterScenarioTestContent("archive-zip", InjectableMessage{
		Subject:  "Documents attached",
		BodyHTML: "<p>The requested documents are attached as a zip archive.</p>",
		Attachment: &exercise.TestAttachment{
			Filename: "documents.zip", ContentType: "application/zip",
			Content: buildZipArchive("readme.txt", []byte(eicarTestString)),
		},
	})
	RegisterScenarioTestContent("nested-archive", InjectableMessage{
		Subject:  "Package attached",
		BodyHTML: "<p>The package is attached.</p>",
		Attachment: &exercise.TestAttachment{
			Filename: "package.zip", ContentType: "application/zip",
			Content: buildNestedZip(3, "readme.txt", []byte(eicarTestString)),
		},
	})
	RegisterScenarioTestContent("archive-targz", InjectableMessage{
		Subject:  "Backup attached",
		BodyHTML: "<p>The latest backup is attached.</p>",
		Attachment: &exercise.TestAttachment{
			Filename: "backup.tar.gz", ContentType: "application/gzip",
			Content: buildTarGz("readme.txt", []byte(eicarTestString)),
		},
	})
	RegisterScenarioTestContent("attached-message", InjectableMessage{
		Subject:  "Fwd: notice",
		BodyHTML: "<p>Forwarding the original message below as an attachment.</p>",
		Attachment: &exercise.TestAttachment{
			Filename: "forwarded.eml", ContentType: "message/rfc822",
			Content: buildAttachedMessage("eicar.txt", "text/plain", []byte(eicarTestString)),
		},
	})
}
