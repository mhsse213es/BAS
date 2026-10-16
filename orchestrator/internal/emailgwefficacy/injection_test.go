package emailgwefficacy

import (
	"context"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	gosmtp "github.com/emersion/go-smtp"
)

// injectionTestReceipt is one accepted message, as a minimal local
// test SMTP server observed it -- a test listener only, never this
// package's own production delivery path (that's
// exercise.SpoofableSMTPInjector, which this file proves is actually
// wired into InjectScenarioMessage).
type injectionTestReceipt struct {
	HeloHost string
	From     string
	To       string
	Data     []byte
}

type injectionTestBackend struct {
	mu       sync.Mutex
	received []injectionTestReceipt
}

func (b *injectionTestBackend) NewSession(c *gosmtp.Conn) (gosmtp.Session, error) {
	return &injectionTestSession{backend: b, helo: c.Hostname()}, nil
}

type injectionTestSession struct {
	backend *injectionTestBackend
	helo    string
	from    string
	to      string
}

func (s *injectionTestSession) Mail(from string, opts *gosmtp.MailOptions) error {
	s.from = from
	return nil
}
func (s *injectionTestSession) Rcpt(to string, opts *gosmtp.RcptOptions) error { s.to = to; return nil }

func (s *injectionTestSession) Data(r io.Reader) error {
	data, err := io.ReadAll(r)
	if err != nil {
		return err
	}
	s.backend.mu.Lock()
	s.backend.received = append(s.backend.received, injectionTestReceipt{HeloHost: s.helo, From: s.from, To: s.to, Data: data})
	s.backend.mu.Unlock()
	return nil
}

func (s *injectionTestSession) Reset()        {}
func (s *injectionTestSession) Logout() error { return nil }

func startInjectionTestServer(t *testing.T) (*injectionTestBackend, string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	backend := &injectionTestBackend{}
	srv := gosmtp.NewServer(backend)
	srv.Domain = "emailgw-injection-test.local"
	srv.ReadTimeout = 10 * time.Second
	srv.WriteTimeout = 10 * time.Second
	srv.MaxRecipients = 1
	srv.AllowInsecureAuth = true

	t.Cleanup(func() { ln.Close() })
	go srv.Serve(ln)

	return backend, ln.Addr().String()
}

func TestInjectScenarioMessage_WiredScenario_SendsRealMessageAndReturnsObservation(t *testing.T) {
	backend, addr := startInjectionTestServer(t)
	exp := SPFAlignmentExpectation(false) // known-bad: EnvelopeFrom is wired
	content, ok := ScenarioTestContent(exp)
	if !ok {
		t.Fatalf("ScenarioTestContent(%q): no content, want content for a wired scenario", exp.MessageClass)
	}

	obs, err := InjectScenarioMessage(context.Background(), InjectionTarget{TargetMX: addr}, exp, content)
	if err != nil {
		t.Fatalf("InjectScenarioMessage: %v", err)
	}
	if obs.SenderPayloadHash == "" {
		t.Error("SenderPayloadHash is empty, want a hash of the sent payload")
	}
	if obs.Timestamp.IsZero() {
		t.Error("Timestamp is zero, want the send time")
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
	if got.To != exp.Recipient {
		t.Errorf("RCPT TO = %q, want %q", got.To, exp.Recipient)
	}
	if !strings.Contains(string(got.Data), exp.HeaderFrom) {
		t.Errorf("message body does not contain From header %q", exp.HeaderFrom)
	}
	if !strings.Contains(string(got.Data), content.Subject) {
		t.Errorf("message body does not contain Subject %q", content.Subject)
	}
}

// TestInjectScenarioMessage_NotWiredScenario_ReturnsErrorNeverSends
// proves the empty-EnvelopeFrom signal is actually checked -- a
// scenario this package can't genuinely inject yet must never send
// anything, silently or otherwise.
func TestInjectScenarioMessage_NotWiredScenario_ReturnsErrorNeverSends(t *testing.T) {
	backend, addr := startInjectionTestServer(t)
	exp := SPFAlignmentExpectation(true) // known-good: NOT wired (needs real lab DNS)
	if exp.EnvelopeFrom != "" {
		t.Fatalf("SPFAlignmentExpectation(true).EnvelopeFrom = %q, want empty for this test's premise to hold", exp.EnvelopeFrom)
	}

	_, err := InjectScenarioMessage(context.Background(), InjectionTarget{TargetMX: addr}, exp, InjectableMessage{})
	if err == nil {
		t.Fatal("expected an error for an expectation with no EnvelopeFrom, got nil")
	}

	backend.mu.Lock()
	defer backend.mu.Unlock()
	if len(backend.received) != 0 {
		t.Fatalf("server received %d messages, want 0 -- an unwired scenario must never reach the wire", len(backend.received))
	}
}

func TestScenarioTestContent_UnknownMessageClass_ReturnsFalse(t *testing.T) {
	_, ok := ScenarioTestContent(MailExpectation{MessageClass: "no-such-scenario"})
	if ok {
		t.Error("ok = true for an unknown MessageClass, want false -- never invent content for a scenario this function doesn't know")
	}
}

// TestEveryWiredScenario_HasMatchingContent is the cross-check this
// package's own injection wiring needs: every scenario whose
// EnvelopeFrom is set (a real injection attempt is possible) must
// also have content registered in scenarioTestContent -- an identity
// with nothing to say would be silently sent with empty content
// otherwise.
func TestEveryWiredScenario_HasMatchingContent(t *testing.T) {
	wired := []MailExpectation{
		SPFAlignmentExpectation(false),
		DKIMAlignmentExpectation(false),
		DMARCPolicyExpectation(false),
		URLRewriteExpectation(true), URLRewriteExpectation(false),
		CredentialHarvestingURLExpectation(true), CredentialHarvestingURLExpectation(false),
		ExecutiveImpersonationExpectation(true), ExecutiveImpersonationExpectation(false),
		SupplierPaymentDiversionExpectation(true), SupplierPaymentDiversionExpectation(false),
		AuthenticationExceptionScopeExpectation(false),
		PostDeliveryThreatResponseExpectation(),
	}
	for _, exp := range wired {
		if exp.EnvelopeFrom == "" {
			t.Errorf("%s: EnvelopeFrom is empty, want this list to contain only wired scenarios", exp.MessageClass)
			continue
		}
		if _, ok := ScenarioTestContent(exp); !ok {
			t.Errorf("%s: EnvelopeFrom is set but ScenarioTestContent has no entry for it", exp.MessageClass)
		}
	}
}

// TestNotWiredScenarios_HaveEmptyEnvelopeFrom documents, as a
// checked fact rather than prose alone, exactly which scenario
// directions remain unwired and why -- each one's own Note explains
// the specific capability gap.
func TestNotWiredScenarios_HaveEmptyEnvelopeFrom(t *testing.T) {
	notWired := []MailExpectation{
		SPFAlignmentExpectation(true),
		DKIMAlignmentExpectation(true),
		DMARCPolicyExpectation(true),
		EICARAttachmentExpectation(true), EICARAttachmentExpectation(false),
		OutboundDLPExpectation(true), OutboundDLPExpectation(false),
		AuthenticationExceptionScopeExpectation(true),
	}
	for _, exp := range notWired {
		if exp.EnvelopeFrom != "" {
			t.Errorf("%s: EnvelopeFrom = %q, want empty -- this scenario direction is documented as not yet wired for real injection", exp.MessageClass, exp.EnvelopeFrom)
		}
		if exp.Note == "" {
			t.Errorf("%s: Note is empty, want it to explain why this direction isn't wired", exp.MessageClass)
		}
	}
}
