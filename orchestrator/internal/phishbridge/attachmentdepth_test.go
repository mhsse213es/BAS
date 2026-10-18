package phishbridge

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/base64"
	"io"
	"mime"
	"mime/multipart"
	"net"
	"net/mail"
	"strings"
	"sync"
	"testing"
	"time"

	gosmtp "github.com/emersion/go-smtp"

	"github.com/audspect/bas/internal/emailgwefficacy"
	"github.com/audspect/bas/internal/phishval"
)

// --- unit proofs: the generated artifacts are genuinely valid,
// parseable, reproducible files, not fixture strings with a
// substring embedded. ---

func TestBuildMinimalPDFWithLink_IsValidAndReproducible(t *testing.T) {
	pdf := buildMinimalPDFWithLink(pdfEmbeddedLinkURI)
	if !bytes.HasPrefix(pdf, []byte("%PDF-1.4")) {
		t.Error("PDF does not start with %PDF-1.4 header")
	}
	if !bytes.Contains(pdf, []byte("/URI ("+pdfEmbeddedLinkURI+")")) {
		t.Errorf("PDF does not contain a /URI action for %q", pdfEmbeddedLinkURI)
	}
	if !bytes.HasSuffix(pdf, []byte("%%EOF")) {
		t.Error("PDF does not end with the EOF marker")
	}
	if !bytes.Equal(pdf, buildMinimalPDFWithLink(pdfEmbeddedLinkURI)) {
		t.Error("buildMinimalPDFWithLink is not reproducible: two calls with the same uri produced different bytes")
	}
}

func TestBuildMinimalDOCXWithExternalLink_IsValidZipWithExternalRelationship(t *testing.T) {
	docx, err := buildMinimalDOCXWithExternalLink(officeExternalLinkURI)
	if err != nil {
		t.Fatalf("buildMinimalDOCXWithExternalLink: %v", err)
	}
	zr, err := zip.NewReader(bytes.NewReader(docx), int64(len(docx)))
	if err != nil {
		t.Fatalf("docx is not a valid zip archive: %v", err)
	}
	f, err := zr.Open("word/_rels/document.xml.rels")
	if err != nil {
		t.Fatalf("docx has no word/_rels/document.xml.rels: %v", err)
	}
	defer f.Close()
	relsXML, err := io.ReadAll(f)
	if err != nil {
		t.Fatalf("read document.xml.rels: %v", err)
	}
	if !strings.Contains(string(relsXML), officeExternalLinkURI) {
		t.Errorf("document.xml.rels does not contain %q", officeExternalLinkURI)
	}
	if !strings.Contains(string(relsXML), `TargetMode="External"`) {
		t.Error(`document.xml.rels does not declare TargetMode="External" -- a real reader would treat this as an internal part reference, not a hyperlink`)
	}

	docx2, err := buildMinimalDOCXWithExternalLink(officeExternalLinkURI)
	if err != nil {
		t.Fatalf("buildMinimalDOCXWithExternalLink (second call): %v", err)
	}
	if !bytes.Equal(docx, docx2) {
		t.Error("buildMinimalDOCXWithExternalLink is not reproducible: two calls with the same uri produced different bytes")
	}
}

// --- fixture-based evaluation proofs, mirroring the established
// known-good/known-bad end-to-end pattern. ---

func TestPHATT002_EndToEnd_KnownGood_PDFLinkQuarantined(t *testing.T) {
	exp := PDFEmbeddedLinkExpectation(true)
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
	outcome := phishval.Evaluate("run-ph-att-002", "known-good", catalogExpectation(t, "PH-ATT-002"), obs)

	for name, dim := range map[string]phishval.DimensionResult{"Delivery": outcome.Delivery, "Enforcement": outcome.Enforcement} {
		if dim.Verdict != phishval.VerdictPass {
			t.Errorf("%s.Verdict = %q (%s), want %q", name, dim.Verdict, dim.Reason, phishval.VerdictPass)
		}
	}
}

func TestPHATT002_EndToEnd_KnownBad_PDFLinkDelivered(t *testing.T) {
	exp := PDFEmbeddedLinkExpectation(true)
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
	outcome := phishval.Evaluate("run-ph-att-002", "known-bad", catalogExpectation(t, "PH-ATT-002"), obs)

	if outcome.Enforcement.Verdict != phishval.VerdictFail {
		t.Errorf("Enforcement.Verdict = %q, want %q", outcome.Enforcement.Verdict, phishval.VerdictFail)
	}
}

func TestPHATT003_EndToEnd_KnownGood_OfficeLinkQuarantined(t *testing.T) {
	exp := OfficeExternalLinkExpectation(true)
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
	outcome := phishval.Evaluate("run-ph-att-003", "known-good", catalogExpectation(t, "PH-ATT-003"), obs)

	for name, dim := range map[string]phishval.DimensionResult{"Delivery": outcome.Delivery, "Enforcement": outcome.Enforcement} {
		if dim.Verdict != phishval.VerdictPass {
			t.Errorf("%s.Verdict = %q (%s), want %q", name, dim.Verdict, dim.Reason, phishval.VerdictPass)
		}
	}
}

func TestPHATT003_EndToEnd_KnownBad_OfficeLinkDelivered(t *testing.T) {
	exp := OfficeExternalLinkExpectation(true)
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
	outcome := phishval.Evaluate("run-ph-att-003", "known-bad", catalogExpectation(t, "PH-ATT-003"), obs)

	if outcome.Enforcement.Verdict != phishval.VerdictFail {
		t.Errorf("Enforcement.Verdict = %q, want %q", outcome.Enforcement.Verdict, phishval.VerdictFail)
	}
}

// --- real dispatch proof: the attachment actually reaching the wire
// decodes back into a valid PDF/DOCX carrying the expected link, not
// just a filename string in the raw MIME. ---

type attachmentDepthReceipt struct {
	From string
	To   string
	Data []byte
}

type attachmentDepthBackend struct {
	mu       sync.Mutex
	received []attachmentDepthReceipt
}

func (b *attachmentDepthBackend) NewSession(c *gosmtp.Conn) (gosmtp.Session, error) {
	return &attachmentDepthSession{backend: b}, nil
}

type attachmentDepthSession struct {
	backend *attachmentDepthBackend
	from    string
	to      string
}

func (s *attachmentDepthSession) Mail(from string, opts *gosmtp.MailOptions) error {
	s.from = from
	return nil
}
func (s *attachmentDepthSession) Rcpt(to string, opts *gosmtp.RcptOptions) error {
	s.to = to
	return nil
}
func (s *attachmentDepthSession) Data(r io.Reader) error {
	data, err := io.ReadAll(r)
	if err != nil {
		return err
	}
	s.backend.mu.Lock()
	s.backend.received = append(s.backend.received, attachmentDepthReceipt{From: s.from, To: s.to, Data: data})
	s.backend.mu.Unlock()
	return nil
}
func (s *attachmentDepthSession) Reset()        {}
func (s *attachmentDepthSession) Logout() error { return nil }

func startAttachmentDepthTestServer(t *testing.T) (*attachmentDepthBackend, string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	backend := &attachmentDepthBackend{}
	srv := gosmtp.NewServer(backend)
	srv.Domain = "phishbridge-attachmentdepth-test.local"
	srv.ReadTimeout = 10 * time.Second
	srv.WriteTimeout = 10 * time.Second
	srv.MaxRecipients = 1
	srv.AllowInsecureAuth = true

	t.Cleanup(func() { ln.Close() })
	go srv.Serve(ln)

	return backend, ln.Addr().String()
}

// decodeAttachmentFromRawMessage parses raw (a real RFC 5322/MIME
// message as received over the wire) and returns the first
// attachment part's decoded (base64) bytes.
func decodeAttachmentFromRawMessage(t *testing.T, raw []byte) []byte {
	t.Helper()
	msg, err := mail.ReadMessage(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("mail.ReadMessage: %v", err)
	}
	mediaType, params, err := mime.ParseMediaType(msg.Header.Get("Content-Type"))
	if err != nil {
		t.Fatalf("mime.ParseMediaType: %v", err)
	}
	if !strings.HasPrefix(mediaType, "multipart/") {
		t.Fatalf("message Content-Type %q is not multipart", mediaType)
	}
	mr := multipart.NewReader(msg.Body, params["boundary"])
	for {
		part, err := mr.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("multipart NextPart: %v", err)
		}
		if part.Header.Get("Content-Transfer-Encoding") != "base64" {
			continue
		}
		encoded, err := io.ReadAll(part)
		if err != nil {
			t.Fatalf("read attachment part: %v", err)
		}
		decoded, err := base64.StdEncoding.DecodeString(strings.ReplaceAll(string(encoded), "\r\n", ""))
		if err != nil {
			t.Fatalf("base64 decode attachment: %v", err)
		}
		return decoded
	}
	t.Fatal("no base64-encoded attachment part found in message")
	return nil
}

func TestDispatchPDFEmbeddedLink_RealSMTPServer_AttachmentDecodesToValidPDFWithLink(t *testing.T) {
	backend, addr := startAttachmentDepthTestServer(t)
	exp := PDFEmbeddedLinkExpectation(true)

	_, err := DispatchPDFEmbeddedLink(context.Background(), emailgwefficacy.InjectionTarget{TargetMX: addr}, exp)
	if err != nil {
		t.Fatalf("DispatchPDFEmbeddedLink: %v", err)
	}

	backend.mu.Lock()
	defer backend.mu.Unlock()
	if len(backend.received) != 1 {
		t.Fatalf("server received %d messages, want 1", len(backend.received))
	}
	decoded := decodeAttachmentFromRawMessage(t, backend.received[0].Data)
	if !bytes.HasPrefix(decoded, []byte("%PDF-1.4")) {
		t.Error("decoded attachment does not start with %PDF-1.4 -- not a valid PDF as received")
	}
	if !bytes.Contains(decoded, []byte(pdfEmbeddedLinkURI)) {
		t.Errorf("decoded PDF does not contain the embedded link %q", pdfEmbeddedLinkURI)
	}
}

func TestDispatchOfficeExternalLink_RealSMTPServer_AttachmentDecodesToValidDOCXWithExternalLink(t *testing.T) {
	backend, addr := startAttachmentDepthTestServer(t)
	exp := OfficeExternalLinkExpectation(true)

	_, err := DispatchOfficeExternalLink(context.Background(), emailgwefficacy.InjectionTarget{TargetMX: addr}, exp)
	if err != nil {
		t.Fatalf("DispatchOfficeExternalLink: %v", err)
	}

	backend.mu.Lock()
	defer backend.mu.Unlock()
	if len(backend.received) != 1 {
		t.Fatalf("server received %d messages, want 1", len(backend.received))
	}
	decoded := decodeAttachmentFromRawMessage(t, backend.received[0].Data)
	zr, err := zip.NewReader(bytes.NewReader(decoded), int64(len(decoded)))
	if err != nil {
		t.Fatalf("decoded attachment is not a valid zip/docx as received: %v", err)
	}
	f, err := zr.Open("word/_rels/document.xml.rels")
	if err != nil {
		t.Fatalf("decoded docx has no word/_rels/document.xml.rels: %v", err)
	}
	defer f.Close()
	relsXML, err := io.ReadAll(f)
	if err != nil {
		t.Fatalf("read document.xml.rels: %v", err)
	}
	if !strings.Contains(string(relsXML), officeExternalLinkURI) {
		t.Errorf("decoded docx's document.xml.rels does not contain the external link %q", officeExternalLinkURI)
	}
}
