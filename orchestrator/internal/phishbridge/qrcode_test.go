package phishbridge

import (
	"context"
	"encoding/base64"
	"io"
	"mime"
	"mime/multipart"
	"net/mail"
	"strings"
	"testing"
	"time"

	"github.com/snykk/qr-generator/qrgen"

	"github.com/audspect/bas/internal/emailgwefficacy"
	"github.com/audspect/bas/internal/phishval"
)

func TestBuildQRCodeLureImage_IsValidAndDecodesToTheExpectedURI(t *testing.T) {
	png, err := buildQRCodeLureImage(qrCodeLureURI)
	if err != nil {
		t.Fatalf("buildQRCodeLureImage: %v", err)
	}
	if len(png) == 0 {
		t.Fatal("buildQRCodeLureImage returned no bytes")
	}

	// Independent round trip: decode with the SAME library's own
	// decoder, not just trust the encoder blindly -- the same
	// genuineness discipline buildMinimalPDFWithLink/
	// buildMinimalDOCXWithExternalLink hold themselves to by being
	// re-parsed with a real parser.
	decoded, err := qrgen.DecodeBytes(png)
	if err != nil {
		t.Fatalf("qrgen.DecodeBytes: %v", err)
	}
	if decoded != qrCodeLureURI {
		t.Errorf("decoded = %q, want %q", decoded, qrCodeLureURI)
	}
}

func TestPHCHN005_EndToEnd_KnownGood_QRAttachmentQuarantined(t *testing.T) {
	exp := QRCodeLureExpectation(true)
	now := time.Now()
	provider := emailgwefficacy.NewFixtureMailEvidenceProvider(
		[]emailgwefficacy.EnforcementEvidence{{
			Message: exp.Ref(), Action: "quarantine", ControlProduct: exp.ControlProduct,
			Timestamp: now, Source: emailgwefficacy.SourceFixture,
			Provenance: emailgwefficacy.Provenance{Kind: emailgwefficacy.ProvenanceObserved, Confidence: emailgwefficacy.ConfidenceHigh},
		}},
		[]emailgwefficacy.DetectionEvidence{{
			Message: exp.Ref(), AlertGenerated: true, Product: exp.ControlProduct,
			Timestamp: now, Source: emailgwefficacy.SourceFixture,
			Provenance: emailgwefficacy.Provenance{Kind: emailgwefficacy.ProvenanceObserved, Confidence: emailgwefficacy.ConfidenceHigh},
		}},
	)

	result := emailgwefficacy.VerifyMailExpectation(exp, emailgwefficacy.OriginDeliveryObservation{}, provider, scenarioWindow())
	obs := FromEmailGWEfficacyResult(result)
	outcome := phishval.Evaluate("run-ph-chn-005", "known-good", catalogExpectation(t, "PH-CHN-005"), obs)

	for name, dim := range map[string]phishval.DimensionResult{"Delivery": outcome.Delivery, "Enforcement": outcome.Enforcement} {
		if dim.Verdict != phishval.VerdictPass {
			t.Errorf("%s.Verdict = %q (%s), want %q", name, dim.Verdict, dim.Reason, phishval.VerdictPass)
		}
	}
}

func TestPHCHN005_EndToEnd_KnownBad_QRAttachmentDelivered(t *testing.T) {
	exp := QRCodeLureExpectation(true)
	now := time.Now()
	provider := emailgwefficacy.NewFixtureMailEvidenceProvider(
		[]emailgwefficacy.EnforcementEvidence{{
			Message: exp.Ref(), Action: "deliver", ControlProduct: exp.ControlProduct,
			Timestamp: now, Source: emailgwefficacy.SourceFixture,
			Provenance: emailgwefficacy.Provenance{Kind: emailgwefficacy.ProvenanceObserved, Confidence: emailgwefficacy.ConfidenceHigh},
		}},
		nil,
	)

	result := emailgwefficacy.VerifyMailExpectation(exp, emailgwefficacy.OriginDeliveryObservation{}, provider, scenarioWindow())
	obs := FromEmailGWEfficacyResult(result)
	outcome := phishval.Evaluate("run-ph-chn-005", "known-bad", catalogExpectation(t, "PH-CHN-005"), obs)

	if outcome.Enforcement.Verdict != phishval.VerdictFail {
		t.Errorf("Enforcement.Verdict = %q, want %q", outcome.Enforcement.Verdict, phishval.VerdictFail)
	}
}

// --- real dispatch proof: the attached PNG that actually crosses the
// wire decodes to the expected URI, mirroring attachmentdepth_test.go's
// own real-SMTP-server + real-decode pattern. ---

func TestDispatchQRCodeLure_RealSMTPServer_AttachmentDecodesToTheExpectedURI(t *testing.T) {
	// Reuses attachmentdepth_test.go's own real-SMTP-server double --
	// the same local server, no scenario-specific fixture needed.
	backend, addr := startAttachmentDepthTestServer(t)
	exp := QRCodeLureExpectation(true)

	_, err := DispatchQRCodeLure(context.Background(), emailgwefficacy.InjectionTarget{TargetMX: addr}, exp)
	if err != nil {
		t.Fatalf("DispatchQRCodeLure: %v", err)
	}

	backend.mu.Lock()
	defer backend.mu.Unlock()
	if len(backend.received) != 1 {
		t.Fatalf("server received %d messages, want 1", len(backend.received))
	}
	png := decodeAttachmentFromRawMIME(t, backend.received[0].Data, "image/png")

	decoded, err := qrgen.DecodeBytes(png)
	if err != nil {
		t.Fatalf("qrgen.DecodeBytes on the attachment that crossed the wire: %v", err)
	}
	if decoded != qrCodeLureURI {
		t.Errorf("decoded = %q, want %q", decoded, qrCodeLureURI)
	}
}

// decodeAttachmentFromRawMIME extracts and base64-decodes the first
// attachment part whose Content-Type matches wantContentType from a
// raw MIME message -- shared decode logic the attachmentdepth_test.go
// dispatch tests already perform inline; factored out here so this
// test doesn't duplicate that parsing by hand.
func decodeAttachmentFromRawMIME(t *testing.T, raw []byte, wantContentType string) []byte {
	t.Helper()
	msg, err := mail.ReadMessage(strings.NewReader(string(raw)))
	if err != nil {
		t.Fatalf("mail.ReadMessage: %v", err)
	}
	mediaType, params, err := mime.ParseMediaType(msg.Header.Get("Content-Type"))
	if err != nil {
		t.Fatalf("mime.ParseMediaType: %v", err)
	}
	if !strings.HasPrefix(mediaType, "multipart/") {
		t.Fatalf("Content-Type = %q, want multipart/*", mediaType)
	}
	mr := multipart.NewReader(msg.Body, params["boundary"])
	for {
		part, err := mr.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("multipart.NextPart: %v", err)
		}
		if strings.HasPrefix(part.Header.Get("Content-Type"), wantContentType) {
			data, err := io.ReadAll(part)
			if err != nil {
				t.Fatalf("reading part: %v", err)
			}
			decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(data)))
			if err != nil {
				t.Fatalf("base64 decode: %v", err)
			}
			return decoded
		}
	}
	t.Fatalf("no part with Content-Type %q found", wantContentType)
	return nil
}
