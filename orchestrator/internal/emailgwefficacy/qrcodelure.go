package emailgwefficacy

import (
	"github.com/snykk/qr-generator/qrgen"

	"github.com/audspect/bas/internal/exercise"
)

// QRCodeLureURI is the synthetic lookalike-login URL the QR lure encodes.
// "mobile-camera transition" itself is unprovable in an automated BAS test;
// what is provable is that the generated code is a real, spec-conformant QR
// symbol that decodes back to exactly this URI.
const QRCodeLureURI = "http://lookalike-login-lab.test/qr-scan"

// BuildQRCodeLureImage generates a real PNG-encoded QR code for uri using
// github.com/snykk/qr-generator/qrgen, an ISO/IEC 18004:2015 encoder with no
// dependencies beyond the Go standard library.
func BuildQRCodeLureImage(uri string) ([]byte, error) {
	return qrgen.Encode(uri, qrgen.WithECLevel(qrgen.ECLevelM))
}

// QRCodeLureExpectation builds the QR-lure MailExpectation (PH-CHN-005's
// email leg). caught=true is the known-good case: the attachment is
// quarantined before any scan can happen. caught=false is the known-bad case.
func QRCodeLureExpectation(caught bool) MailExpectation {
	exp := MailExpectation{
		SenderProfile:  "qr-code-lure",
		Recipient:      "mobile-user-test@example-lab.test",
		MessageClass:   "qr-code-lure",
		ControlProduct: "m365-defender-o365",
		Note:           "attachment is a real, spec-conformant QR code image encoding a lookalike-login URL; proves QR generation/decode genuineness, not the mobile-camera scan itself or the post-scan browser leg (see PH-URL-001/PH-URL-005 for that)",
		EnvelopeFrom:   "notices@qr-code-lure-lab.test",
	}
	if caught {
		exp.ExpectedAction = ExpectedQuarantine
	} else {
		exp.ExpectedAction = ExpectedDeliver
	}
	return exp
}

// QRCodeLureText is the QR lure's message text. The attachment is added per
// message, from the QR image built for QRCodeLureURI.
var QRCodeLureText = InjectableMessage{
	Subject:  "Scan to verify your account",
	BodyHTML: "<p>Please scan the attached QR code with your phone camera to verify your account before it is suspended.</p>",
}

// The EmailGW executor reads test content by message class. Registration
// happens only when the QR image builds, so a failure leaves the scenario
// with no test content, and the executor reports that instead of sending.
func init() {
	png, err := BuildQRCodeLureImage(QRCodeLureURI)
	if err != nil {
		return
	}
	msg := QRCodeLureText
	msg.Attachment = &exercise.TestAttachment{
		Filename: "account-verification.png", ContentType: "image/png", Content: png,
	}
	scenarioTestContent["qr-code-lure"] = msg
}
