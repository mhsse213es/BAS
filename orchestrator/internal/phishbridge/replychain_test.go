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

func TestPHBEC006_EndToEnd_KnownGood_ReplyChainQuarantined(t *testing.T) {
	exp := ReplyChainHijackExpectation(true)
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
	outcome := phishval.Evaluate("run-ph-bec-006", "known-good", catalogExpectation(t, "PH-BEC-006"), obs)

	for name, dim := range map[string]phishval.DimensionResult{"Delivery": outcome.Delivery, "Enforcement": outcome.Enforcement} {
		if dim.Verdict != phishval.VerdictPass {
			t.Errorf("%s.Verdict = %q (%s), want %q", name, dim.Verdict, dim.Reason, phishval.VerdictPass)
		}
	}
}

func TestPHBEC006_EndToEnd_KnownBad_ReplyChainDelivered(t *testing.T) {
	exp := ReplyChainHijackExpectation(true)
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
	outcome := phishval.Evaluate("run-ph-bec-006", "known-bad", catalogExpectation(t, "PH-BEC-006"), obs)

	if outcome.Enforcement.Verdict != phishval.VerdictFail {
		t.Errorf("Enforcement.Verdict = %q, want %q", outcome.Enforcement.Verdict, phishval.VerdictFail)
	}
}

// --- real dispatch proof, mirroring the established local-SMTP-
// server pattern: the reply-framed Subject and quoted body actually
// reach the wire. ---

type replyChainReceipt struct {
	From string
	To   string
	Data []byte
}

type replyChainBackend struct {
	mu       sync.Mutex
	received []replyChainReceipt
}

func (b *replyChainBackend) NewSession(c *gosmtp.Conn) (gosmtp.Session, error) {
	return &replyChainSession{backend: b}, nil
}

type replyChainSession struct {
	backend *replyChainBackend
	from    string
	to      string
}

func (s *replyChainSession) Mail(from string, opts *gosmtp.MailOptions) error {
	s.from = from
	return nil
}
func (s *replyChainSession) Rcpt(to string, opts *gosmtp.RcptOptions) error { s.to = to; return nil }
func (s *replyChainSession) Data(r io.Reader) error {
	data, err := io.ReadAll(r)
	if err != nil {
		return err
	}
	s.backend.mu.Lock()
	s.backend.received = append(s.backend.received, replyChainReceipt{From: s.from, To: s.to, Data: data})
	s.backend.mu.Unlock()
	return nil
}
func (s *replyChainSession) Reset()        {}
func (s *replyChainSession) Logout() error { return nil }

func startReplyChainTestServer(t *testing.T) (*replyChainBackend, string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	backend := &replyChainBackend{}
	srv := gosmtp.NewServer(backend)
	srv.Domain = "phishbridge-replychain-test.local"
	srv.ReadTimeout = 10 * time.Second
	srv.WriteTimeout = 10 * time.Second
	srv.MaxRecipients = 1
	srv.AllowInsecureAuth = true

	t.Cleanup(func() { ln.Close() })
	go srv.Serve(ln)

	return backend, ln.Addr().String()
}

func TestDispatchReplyChainHijack_RealSMTPServer_SendsReplyFramedMessage(t *testing.T) {
	backend, addr := startReplyChainTestServer(t)
	exp := ReplyChainHijackExpectation(true)

	obs, err := DispatchReplyChainHijack(context.Background(), emailgwefficacy.InjectionTarget{TargetMX: addr}, exp)
	if err != nil {
		t.Fatalf("DispatchReplyChainHijack: %v", err)
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
	if got.From != exp.EnvelopeFrom {
		t.Errorf("MAIL FROM = %q, want %q", got.From, exp.EnvelopeFrom)
	}
	raw := string(got.Data)
	if !strings.Contains(raw, "Subject: "+replyChainHijackContent.Subject) {
		t.Errorf("message does not contain the reply-framed Subject %q", replyChainHijackContent.Subject)
	}
	if !strings.HasPrefix(replyChainHijackContent.Subject, "Re:") {
		t.Fatalf("precondition: replyChainHijackContent.Subject = %q, want it to start with \"Re:\"", replyChainHijackContent.Subject)
	}
	if !strings.Contains(raw, "blockquote") {
		t.Error("message does not contain the quoted prior-thread content")
	}
}
