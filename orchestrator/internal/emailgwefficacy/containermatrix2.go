package emailgwefficacy

import (
	_ "embed"

	"github.com/audspect/bas/internal/exercise"
)

// Second container matrix, continuing EG-026..EG-029 after the first (containermatrix.go):
//
//   - EG-026 archive-7z:            EICAR inside a 7z archive.
//   - EG-027 archive-cab:           EICAR inside a Windows cabinet (stored, not compressed).
//   - EG-028 archive-protected-zip: EICAR inside an AES-256 password-protected ZIP, with the password in the message body,
//     the way real malware mail does it. A gateway cannot scan inside without the password, so this tests its policy for
//     content it cannot inspect.
//   - EG-029 macro-enabled-*:       one scenario each for .docm, .xlsm and .pptm. The files are the fabricated carrier
//     documents with the main part's content type switched to the macro-enabled type. They contain no macro and no
//     vbaProject part: the scenario tests type-based policy only, never macro detection.
//
// Go's standard library cannot write 7z, CAB or AES-encrypted ZIP, so these files were generated once offline and
// embedded. Each was round-tripped with a real extractor at generation time, and containermatrix2_test.go pins their
// SHA-256 so any change is deliberate. RAR and ARJ are not covered: no free writer exists for them.

//go:embed testdata/eicar.7z
var eicar7z []byte

//go:embed testdata/eicar.cab
var eicarCab []byte

//go:embed testdata/eicar-protected.zip
var eicarProtectedZip []byte

//go:embed testdata/carrier-macro.docm
var macroDocm []byte

//go:embed testdata/carrier-macro.xlsm
var macroXlsm []byte

//go:embed testdata/carrier-macro.pptm
var macroPptm []byte

// macroExtensionSet is the macro-enabled Office types EG-029 covers, one scenario each.
var macroExtensionSet = []string{"docm", "xlsm", "pptm"}

func init() {
	for id, exp := range map[string][2]MailExpectation{
		"EG-026.archive-7z": {
			containerExpectation("archive-7z", "sevenzip-container-lab.test", "the EICAR test string inside a 7z archive -- tests a third archive family, since ZIP and tar.gz support do not imply 7z support", true),
			containerExpectation("archive-7z", "sevenzip-container-lab.test", "the EICAR test string inside a 7z archive -- tests a third archive family, since ZIP and tar.gz support do not imply 7z support", false)},
		"EG-027.archive-cab": {
			containerExpectation("archive-cab", "cabinet-container-lab.test", "the EICAR test string inside a Windows cabinet file -- tests an archive format common in Windows delivery chains", true),
			containerExpectation("archive-cab", "cabinet-container-lab.test", "the EICAR test string inside a Windows cabinet file -- tests an archive format common in Windows delivery chains", false)},
		"EG-028.archive-protected-zip": {
			containerExpectation("archive-protected-zip", "protected-archive-lab.test", "the EICAR test string inside a password-protected ZIP with the password in the message body -- tests the gateway's policy for content it cannot scan", true),
			containerExpectation("archive-protected-zip", "protected-archive-lab.test", "the EICAR test string inside a password-protected ZIP with the password in the message body -- tests the gateway's policy for content it cannot scan", false)},
	} {
		expectationByID[id+".known-good"] = exp[0]
		expectationByID[id+".known-bad"] = exp[1]
	}
	for _, ext := range macroExtensionSet {
		id := "EG-029.macro-enabled-" + ext
		note := "a ." + ext + " file with the macro-enabled content type but no macro inside -- tests type-based policy for macro-enabled Office files, not macro detection"
		expectationByID[id+".known-good"] = containerExpectation("macro-enabled-"+ext, "macro-type-lab.test", note, true)
		expectationByID[id+".known-bad"] = containerExpectation("macro-enabled-"+ext, "macro-type-lab.test", note, false)
	}

	RegisterScenarioTestContent("archive-7z", InjectableMessage{
		Subject:  "Documents attached",
		BodyHTML: "<p>The requested documents are attached as a 7z archive.</p>",
		Attachment: &exercise.TestAttachment{
			Filename: "documents.7z", ContentType: "application/x-7z-compressed", Content: eicar7z,
		},
	})
	RegisterScenarioTestContent("archive-cab", InjectableMessage{
		Subject:  "Update package attached",
		BodyHTML: "<p>The update package is attached.</p>",
		Attachment: &exercise.TestAttachment{
			Filename: "update.cab", ContentType: "application/vnd.ms-cab-compressed", Content: eicarCab,
		},
	})
	RegisterScenarioTestContent("archive-protected-zip", InjectableMessage{
		Subject:  "Protected documents attached",
		BodyHTML: "<p>The documents are attached in a protected archive. The password is: infected</p>",
		Attachment: &exercise.TestAttachment{
			Filename: "documents.zip", ContentType: "application/zip", Content: eicarProtectedZip,
		},
	})
	macro := map[string]struct {
		data  []byte
		ctype string
	}{
		"docm": {macroDocm, "application/vnd.ms-word.document.macroEnabled.12"},
		"xlsm": {macroXlsm, "application/vnd.ms-excel.sheet.macroEnabled.12"},
		"pptm": {macroPptm, "application/vnd.ms-powerpoint.presentation.macroEnabled.12"},
	}
	for _, ext := range macroExtensionSet {
		RegisterScenarioTestContent("macro-enabled-"+ext, InjectableMessage{
			Subject:  "Notice attached",
			BodyHTML: "<p>Please find the attached notice for your review.</p>",
			Attachment: &exercise.TestAttachment{
				Filename: "notice." + ext, ContentType: macro[ext].ctype, Content: macro[ext].data,
			},
		})
	}
}
