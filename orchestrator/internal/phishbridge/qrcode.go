package phishbridge

import (
	"context"

	"github.com/snykk/qr-generator/qrgen"

	"github.com/audspect/bas/internal/emailgwefficacy"
	"github.com/audspect/bas/internal/exercise"
)

// qrCodeLureURI is the synthetic lookalike-login URL this scenario's
// QR code encodes. "mobile-camera transition" itself -- a human
// physically pointing a phone camera at this code -- is unprovable in
// an automated BAS test; what this package can and does prove is that
// the generated code is a real, spec-conformant QR symbol that
// decodes back to exactly this URI, the same genuineness bar
// buildMinimalPDFWithLink/buildMinimalDOCXWithExternalLink hold
// themselves to for PH-ATT-002/003.
const qrCodeLureURI = "http://lookalike-login-lab.test/qr-scan"

// buildQRCodeLureImage generates a real PNG-encoded QR code for uri
// using github.com/snykk/qr-generator/qrgen -- a from-scratch,
// ISO/IEC 18004:2015-conformant encoder with no dependencies beyond
// the Go standard library (not hand-rolled here: QR's Reed-Solomon
// error correction and mask-pattern selection make that
// disproportionate for one BAS stimulus, unlike the simpler PDF/ZIP
// formats PH-ATT-002/003 construct directly).
func buildQRCodeLureImage(uri string) ([]byte, error) {
	return qrgen.Encode(uri, qrgen.WithECLevel(qrgen.ECLevelM))
}

// QRCodeLureExpectation builds PH-CHN-005's MailExpectation: an
// email whose attachment is a real QR code encoding a lookalike-login
// URL, the mobile-QR-to-browser attack's own first leg. The browser
// leg after a (real or simulated) scan is deliberately NOT re-proven
// here -- that's PH-URL-001/PH-URL-005's own evidence, per this
// scenario's existing partial-overlap note; this expectation and its
// dispatch close only the QR-generation half that previously had no
// adapter at all. caught=true is the known-good case (the attachment
// itself gets quarantined/flagged before any scan can happen);
// caught=false is the known-bad case.
func QRCodeLureExpectation(caught bool) emailgwefficacy.MailExpectation {
	exp := emailgwefficacy.MailExpectation{
		SenderProfile:  "qr-code-lure",
		Recipient:      "mobile-user-test@example-lab.test",
		MessageClass:   "qr-code-lure",
		ControlProduct: "m365-defender-o365",
		Note:           "attachment is a real, spec-conformant QR code image encoding a lookalike-login URL; proves QR generation/decode genuineness, not the mobile-camera scan itself or the post-scan browser leg (see PH-URL-001/PH-URL-005 for that)",
		EnvelopeFrom:   "notices@qr-code-lure-lab.test",
	}
	if caught {
		exp.ExpectedAction = emailgwefficacy.ExpectedQuarantine
	} else {
		exp.ExpectedAction = emailgwefficacy.ExpectedDeliver
	}
	return exp
}

var qrCodeLureContent = emailgwefficacy.InjectableMessage{
	Subject:  "Scan to verify your account",
	BodyHTML: "<p>Please scan the attached QR code with your phone camera to verify your account before it is suspended.</p>",
}

// DispatchQRCodeLure generates a fresh real QR code encoding
// qrCodeLureURI, attaches it, and sends PH-CHN-005's real test message
// via emailgwefficacy.InjectScenarioMessage.
func DispatchQRCodeLure(ctx context.Context, target emailgwefficacy.InjectionTarget, exp emailgwefficacy.MailExpectation) (emailgwefficacy.OriginDeliveryObservation, error) {
	png, err := buildQRCodeLureImage(qrCodeLureURI)
	if err != nil {
		return emailgwefficacy.OriginDeliveryObservation{}, err
	}
	content := qrCodeLureContent
	content.Attachment = &exercise.TestAttachment{
		Filename: "account-verification.png", ContentType: "image/png", Content: png,
	}
	return emailgwefficacy.InjectScenarioMessage(ctx, target, exp, content)
}
