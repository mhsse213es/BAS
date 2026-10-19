package phishbridge

import (
	"context"

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
const qrCodeLureURI = emailgwefficacy.QRCodeLureURI

// buildQRCodeLureImage generates a real PNG-encoded QR code for uri
// using github.com/snykk/qr-generator/qrgen -- a from-scratch,
// ISO/IEC 18004:2015-conformant encoder with no dependencies beyond
// the Go standard library (not hand-rolled here: QR's Reed-Solomon
// error correction and mask-pattern selection make that
// disproportionate for one BAS stimulus, unlike the simpler PDF/ZIP
// formats PH-ATT-002/003 construct directly).
func buildQRCodeLureImage(uri string) ([]byte, error) {
	return emailgwefficacy.BuildQRCodeLureImage(uri)
}

// QRCodeLureExpectation is PH-CHN-005's MailExpectation. The definition lives in
// emailgwefficacy, so the EmailGW dispatch table and this bridge share one
// expectation. See emailgwefficacy.QRCodeLureExpectation for its contract.
func QRCodeLureExpectation(caught bool) emailgwefficacy.MailExpectation {
	return emailgwefficacy.QRCodeLureExpectation(caught)
}

// qrCodeLureContent is the QR lure's message text; DispatchQRCodeLure attaches
// the generated QR image to it.
var qrCodeLureContent = emailgwefficacy.QRCodeLureText

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
