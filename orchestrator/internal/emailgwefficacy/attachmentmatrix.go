package emailgwefficacy

import "github.com/audspect/bas/internal/exercise"

// Attachment matrix: four scenarios distinct from EG-004
// (EICARAttachmentExpectation), each isolating one specific attachment-
// handling question a gateway's inspection can get wrong independently of
// the others. Every byte of content sent here is either the existing
// eicarTestString (the industry-standard, universally-recognized AV test
// string, never real malware) or plain benign placeholder text -- this
// package sends no other kind of attachment content, for either reason.
//
//   - MalwareCategoryAttachmentExpectation: the same EICAR content inside a
//     script-type container (.js), not EG-004's plain-text container --
//     proves content-scanning reaches a different attachment MIME/extension
//     than the one EG-004 already covers.
//   - RansomwareStandInExpectation: a double-extension attachment
//     ("invoice.pdf.exe") disguising an executable as a document, the
//     classic ransomware-delivery disguise technique -- tests whether the
//     gateway looks past a benign-looking first extension.
//   - FileTypeSpoofingExpectation: a declared Content-Type/filename
//     claiming a Word document while the actual bytes are not a valid
//     OOXML document at all -- tests whether inspection catches a
//     declared-type mismatch, independent of (and orthogonal to) the
//     double-extension disguise above.
//   - BlockedExtensionPolicyExpectation: a disallowed script extension
//     (.vbs) carrying wholly benign, non-EICAR content -- deliberately
//     isolates "is this extension blocked by policy at all" from content
//     scanning, which the other three scenarios would otherwise conflate
//     it with.
//
// Each is wired for real injection via EnvelopeFrom, the same mechanism as
// EICARAttachmentExpectation (Workstream 5).

// attachmentPolicyPlaceholderText is wholly benign, non-EICAR content for
// BlockedExtensionPolicyExpectation: that scenario tests extension-based
// policy enforcement specifically, and using EICAR there would conflate
// "the extension is blocked" with "the content was scanned and caught",
// two different control behaviors this matrix keeps separate on purpose.
const attachmentPolicyPlaceholderText = "This is a benign placeholder file used to test attachment-extension policy enforcement. It contains no executable code and is not malware."

// MalwareCategoryAttachmentExpectation builds a malware-category attachment
// scenario distinct from EG-004: the same EICAR string, delivered inside a
// script-type (.js) container rather than EG-004's plain-text one.
// caught=true is the known-good case (quarantined); caught=false is the
// known-bad case (delivered).
func MalwareCategoryAttachmentExpectation(caught bool) MailExpectation {
	exp := MailExpectation{
		SenderProfile:  "known-bad-malware-attachment",
		Recipient:      "helpdesk-test@example-lab.test",
		MessageClass:   "malware-category-script",
		ControlProduct: "m365-defender-o365",
		Note:           "industry-standard EICAR test string delivered inside a script-type (.js) attachment container, distinct from EG-004's plain-text container -- proves content-scanning reaches a second attachment MIME/extension, not only the first one already covered",
		EnvelopeFrom:   "malware-script-test-sender@malware-category-lab.test",
	}
	if caught {
		exp.ExpectedAction = ExpectedQuarantine
	} else {
		exp.ExpectedAction = ExpectedDeliver
	}
	return exp
}

// RansomwareStandInExpectation builds a double-extension attachment
// scenario: a filename ("invoice.pdf.exe") disguising an executable as a
// document, the classic ransomware-delivery disguise, carrying the EICAR
// test string as its content -- never real ransomware code.
// caught=true is the known-good case (quarantined); caught=false is the
// known-bad case (delivered).
func RansomwareStandInExpectation(caught bool) MailExpectation {
	exp := MailExpectation{
		SenderProfile:  "known-bad-malware-attachment",
		Recipient:      "helpdesk-test@example-lab.test",
		MessageClass:   "ransomware-stand-in",
		ControlProduct: "m365-defender-o365",
		Note:           "double-extension attachment (invoice.pdf.exe) disguising an executable as a document -- the classic ransomware-delivery disguise technique. Content is the industry-standard EICAR test string, never real ransomware code; this scenario tests the disguise, not a payload",
		EnvelopeFrom:   "invoice-notice-test-sender@ransomware-standin-lab.test",
	}
	if caught {
		exp.ExpectedAction = ExpectedQuarantine
	} else {
		exp.ExpectedAction = ExpectedDeliver
	}
	return exp
}

// FileTypeSpoofingExpectation builds a declared-type-mismatch scenario: an
// attachment whose filename and declared Content-Type claim a Word
// document, while the actual bytes are the EICAR test string -- not a
// valid OOXML document at all. Distinct from RansomwareStandInExpectation's
// double-extension disguise: this tests whether inspection catches a
// declared-type/actual-content mismatch, not an extension trick.
// caught=true is the known-good case (quarantined); caught=false is the
// known-bad case (delivered).
func FileTypeSpoofingExpectation(caught bool) MailExpectation {
	exp := MailExpectation{
		SenderProfile:  "known-bad-malware-attachment",
		Recipient:      "helpdesk-test@example-lab.test",
		MessageClass:   "file-type-spoofing",
		ControlProduct: "m365-defender-o365",
		Note:           "attachment declares a Word-document filename and Content-Type, but its actual bytes (the EICAR test string) are not a valid OOXML document at all -- tests whether inspection looks past the declared type to the real content, independent of the double-extension disguise in RansomwareStandInExpectation",
		EnvelopeFrom:   "contract-test-sender@filetype-spoofing-lab.test",
	}
	if caught {
		exp.ExpectedAction = ExpectedQuarantine
	} else {
		exp.ExpectedAction = ExpectedDeliver
	}
	return exp
}

// BlockedExtensionPolicyExpectation builds a pure file-extension-policy
// scenario: a disallowed script extension (.vbs) carrying wholly benign,
// non-EICAR placeholder content. This deliberately isolates "is this
// extension blocked by policy at all" from content scanning -- the other
// three scenarios in this file all use EICAR content, which would
// conflate an extension-policy pass with a content-scanning catch.
// caught=true is the known-good case (quarantined by extension policy
// alone); caught=false is the known-bad case (delivered).
func BlockedExtensionPolicyExpectation(caught bool) MailExpectation {
	exp := MailExpectation{
		SenderProfile:  "known-bad-malware-attachment",
		Recipient:      "helpdesk-test@example-lab.test",
		MessageClass:   "blocked-extension-policy",
		ControlProduct: "m365-defender-o365",
		Note:           "a disallowed script extension (.vbs) carrying wholly benign, non-EICAR content -- isolates pure extension-policy enforcement from content scanning, which every other scenario in this matrix exercises instead",
		EnvelopeFrom:   "backup-notice-test-sender@extension-policy-lab.test",
	}
	if caught {
		exp.ExpectedAction = ExpectedQuarantine
	} else {
		exp.ExpectedAction = ExpectedDeliver
	}
	return exp
}

func init() {
	RegisterScenarioTestContent("malware-category-script", InjectableMessage{
		Subject:  "Please run the attached setup script",
		BodyHTML: "<p>Please run the attached setup script to complete your account configuration.</p>",
		Attachment: &exercise.TestAttachment{
			Filename:    "setup.js",
			ContentType: "text/javascript",
			Content:     []byte(eicarTestString),
		},
	})
	RegisterScenarioTestContent("ransomware-stand-in", InjectableMessage{
		Subject:  "Overdue invoice attached",
		BodyHTML: "<p>Please find the overdue invoice attached and remit payment at your earliest convenience.</p>",
		Attachment: &exercise.TestAttachment{
			Filename:    "invoice.pdf.exe",
			ContentType: "application/x-msdownload",
			Content:     []byte(eicarTestString),
		},
	})
	RegisterScenarioTestContent("file-type-spoofing", InjectableMessage{
		Subject:  "Signed contract attached",
		BodyHTML: "<p>Please find the signed contract attached for your records.</p>",
		Attachment: &exercise.TestAttachment{
			Filename:    "contract.docx",
			ContentType: "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
			Content:     []byte(eicarTestString),
		},
	})
	RegisterScenarioTestContent("blocked-extension-policy", InjectableMessage{
		Subject:  "Backup script attached",
		BodyHTML: "<p>Please find the backup script attached for your review.</p>",
		Attachment: &exercise.TestAttachment{
			Filename:    "backup.vbs",
			ContentType: "text/vbscript",
			Content:     []byte(attachmentPolicyPlaceholderText),
		},
	})
}
