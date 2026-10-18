package phishbridge

import (
	"context"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	gosmtp "github.com/emersion/go-smtp"

	"github.com/audspect/bas/internal/emailgwefficacy"
	"github.com/audspect/bas/internal/phishval"
)

func TestPHAUTH007_EndToEnd_KnownGood_SpoofedHELOQuarantined(t *testing.T) {
	exp := InternalSenderSpoofExpectation(true)
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
	outcome := phishval.Evaluate("run-ph-auth-007", "known-good", catalogExpectation(t, "PH-AUTH-007"), obs)

	for name, dim := range map[string]phishval.DimensionResult{"Delivery": outcome.Delivery, "Enforcement": outcome.Enforcement, "Detection": outcome.Detection} {
		if dim.Verdict != phishval.VerdictPass {
			t.Errorf("%s.Verdict = %q (%s), want %q", name, dim.Verdict, dim.Reason, phishval.VerdictPass)
		}
	}
}

func TestPHAUTH007_EndToEnd_KnownBad_SpoofedHELODelivered(t *testing.T) {
	exp := InternalSenderSpoofExpectation(true) // known-good expectation; bad outcome contradicts it
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
	outcome := phishval.Evaluate("run-ph-auth-007", "known-bad", catalogExpectation(t, "PH-AUTH-007"), obs)

	if outcome.Enforcement.Verdict != phishval.VerdictFail {
		t.Errorf("Enforcement.Verdict = %q, want %q", outcome.Enforcement.Verdict, phishval.VerdictFail)
	}
}

// --- real dispatch proof, mirroring emailgwefficacy's own
// injection_test.go local-SMTP-server pattern exactly, to prove
// DispatchInternalSenderSpoof actually reaches the wire with the
// spoofed HELO identity and the internal-looking envelope-from -- not
// just that the fixture-based evaluation above is correct. ---

type internalSpoofReceipt struct {
	HeloHost string
	From     string
	To       string
	Data     []byte
}

type internalSpoofBackend struct {
	mu       sync.Mutex
	received []internalSpoofReceipt
}

func (b *internalSpoofBackend) NewSession(c *gosmtp.Conn) (gosmtp.Session, error) {
	return &internalSpoofSession{backend: b, helo: c.Hostname()}, nil
}

type internalSpoofSession struct {
	backend *internalSpoofBackend
	helo    string
	from    string
	to      string
}

func (s *internalSpoofSession) Mail(from string, opts *gosmtp.MailOptions) error {
	s.from = from
	return nil
}
func (s *internalSpoofSession) Rcpt(to string, opts *gosmtp.RcptOptions) error { s.to = to; return nil }
func (s *internalSpoofSession) Data(r io.Reader) error {
	data, err := io.ReadAll(r)
	if err != nil {
		return err
	}
	s.backend.mu.Lock()
	s.backend.received = append(s.backend.received, internalSpoofReceipt{HeloHost: s.helo, From: s.from, To: s.to, Data: data})
	s.backend.mu.Unlock()
	return nil
}
func (s *internalSpoofSession) Reset()        {}
func (s *internalSpoofSession) Logout() error { return nil }

func startInternalSpoofTestServer(t *testing.T) (*internalSpoofBackend, string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	backend := &internalSpoofBackend{}
	srv := gosmtp.NewServer(backend)
	srv.Domain = "phishbridge-internalspoof-test.local"
	srv.ReadTimeout = 10 * time.Second
	srv.WriteTimeout = 10 * time.Second
	srv.MaxRecipients = 1
	srv.AllowInsecureAuth = true

	t.Cleanup(func() { ln.Close() })
	go srv.Serve(ln)

	return backend, ln.Addr().String()
}

func TestDispatchInternalSenderSpoof_RealSMTPServer_SendsSpoofedHELOAndInternalEnvelope(t *testing.T) {
	backend, addr := startInternalSpoofTestServer(t)
	exp := InternalSenderSpoofExpectation(true)
	target := emailgwefficacy.InjectionTarget{TargetMX: addr, HELODomain: "mail.internal-corp-lab.test"}

	obs, err := DispatchInternalSenderSpoof(context.Background(), target, exp)
	if err != nil {
		t.Fatalf("DispatchInternalSenderSpoof: %v", err)
	}
	if obs.SenderPayloadHash == "" {
		t.Error("SenderPayloadHash is empty, want a hash of the sent payload")
	}

	backend.mu.Lock()
	defer backend.mu.Unlock()
	if len(backend.received) != 1 {
		t.Fatalf("server received %d messages, want 1", len(backend.received))
	}
	got := backend.received[0]
	if got.HeloHost != target.HELODomain {
		t.Errorf("HELO = %q, want %q (the spoofed internal-looking identity)", got.HeloHost, target.HELODomain)
	}
	if got.From != exp.EnvelopeFrom {
		t.Errorf("MAIL FROM = %q, want %q", got.From, exp.EnvelopeFrom)
	}
	if !strings.Contains(string(got.Data), internalSenderSpoofContent.Subject) {
		t.Errorf("message body does not contain Subject %q", internalSenderSpoofContent.Subject)
	}
}
