package exercise

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

// spoofTestReceipt is one accepted message, as a minimal test SMTP
// server observed it -- mirroring internal/smtpsink's own
// go-smtp-backed test-fixture shape, used here only as a test
// listener, never this phase's production delivery path.
type spoofTestReceipt struct {
	HeloHost string
	From     string
	To       string
	Data     []byte
}

type spoofTestBackend struct {
	mu       sync.Mutex
	received []spoofTestReceipt
}

func (b *spoofTestBackend) NewSession(c *gosmtp.Conn) (gosmtp.Session, error) {
	return &spoofTestSession{backend: b, helo: c.Hostname()}, nil
}

type spoofTestSession struct {
	backend *spoofTestBackend
	helo    string
	from    string
	to      string
}

func (s *spoofTestSession) Mail(from string, opts *gosmtp.MailOptions) error {
	s.from = from
	return nil
}
func (s *spoofTestSession) Rcpt(to string, opts *gosmtp.RcptOptions) error { s.to = to; return nil }

func (s *spoofTestSession) Data(r io.Reader) error {
	data, err := io.ReadAll(r)
	if err != nil {
		return err
	}
	s.backend.mu.Lock()
	s.backend.received = append(s.backend.received, spoofTestReceipt{HeloHost: s.helo, From: s.from, To: s.to, Data: data})
	s.backend.mu.Unlock()
	return nil
}

func (s *spoofTestSession) Reset()        {}
func (s *spoofTestSession) Logout() error { return nil }

// startSpoofTestServer binds an ephemeral local port and serves SMTP
// until the test ends, returning the backend (to inspect what was
// received) and the server's address (to use as TargetMX).
func startSpoofTestServer(t *testing.T) (*spoofTestBackend, string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	backend := &spoofTestBackend{}
	srv := gosmtp.NewServer(backend)
	srv.Domain = "spooftest.local"
	srv.ReadTimeout = 10 * time.Second
	srv.WriteTimeout = 10 * time.Second
	srv.MaxRecipients = 1
	srv.AllowInsecureAuth = true

	t.Cleanup(func() { ln.Close() })
	go srv.Serve(ln)

	return backend, ln.Addr().String()
}

func TestSpoofableSMTPInjector_SendTestMessage_DeliversWithControlledIdentity(t *testing.T) {
	backend, addr := startSpoofTestServer(t)

	injector := &SpoofableSMTPInjector{
		EnvelopeFrom: "ceo@spoofed-lookalike.test",
		HeaderFrom:   "CEO <ceo@spoofed-lookalike.test>",
		HELODomain:   "attacker-helo.test",
		TargetMX:     addr,
	}
	msg := TestMessage{To: "finance-test@example-lab.test", Subject: "Urgent wire request", BodyHTML: "<p>test</p>"}

	leg, err := injector.SendTestMessage(context.Background(), msg)
	if err != nil {
		t.Fatalf("SendTestMessage: %v", err)
	}
	if leg.SenderPayloadHash == "" {
		t.Error("SenderPayloadHash is empty, want a hash of the sent payload")
	}
	if leg.Timestamp.IsZero() {
		t.Error("Timestamp is zero, want the send time")
	}

	backend.mu.Lock()
	defer backend.mu.Unlock()
	if len(backend.received) != 1 {
		t.Fatalf("server received %d messages, want 1", len(backend.received))
	}
	got := backend.received[0]
	if got.From != injector.EnvelopeFrom {
		t.Errorf("MAIL FROM = %q, want %q", got.From, injector.EnvelopeFrom)
	}
	if got.To != msg.To {
		t.Errorf("RCPT TO = %q, want %q", got.To, msg.To)
	}
	if got.HeloHost != injector.HELODomain {
		t.Errorf("HELO host = %q, want %q", got.HeloHost, injector.HELODomain)
	}
	if !strings.Contains(string(got.Data), injector.HeaderFrom) {
		t.Errorf("message body does not contain From header %q", injector.HeaderFrom)
	}
}

func TestSpoofableSMTPInjector_HeaderFromDefaultsToEnvelopeFrom(t *testing.T) {
	_, addr := startSpoofTestServer(t)

	injector := &SpoofableSMTPInjector{
		EnvelopeFrom: "ceo@spoofed-lookalike.test",
		TargetMX:     addr,
	}
	_, err := injector.SendTestMessage(context.Background(), TestMessage{To: "finance-test@example-lab.test", Subject: "s", BodyHTML: "b"})
	if err != nil {
		t.Fatalf("SendTestMessage: %v", err)
	}
}

func TestSpoofableSMTPInjector_NeitherTargetNorRelaySet_ReturnsError(t *testing.T) {
	injector := &SpoofableSMTPInjector{EnvelopeFrom: "ceo@spoofed-lookalike.test"}
	_, err := injector.SendTestMessage(context.Background(), TestMessage{To: "finance-test@example-lab.test"})
	if err == nil {
		t.Fatal("expected an error when neither TargetMX nor RelayHost is set")
	}
}

func TestSpoofableSMTPInjector_HeaderFromWithCRLF_RejectedBeforeSend(t *testing.T) {
	backend, addr := startSpoofTestServer(t)

	injector := &SpoofableSMTPInjector{
		EnvelopeFrom: "ceo@spoofed-lookalike.test",
		HeaderFrom:   "ceo@spoofed-lookalike.test\r\nBcc: attacker@evil.test",
		TargetMX:     addr,
	}
	_, err := injector.SendTestMessage(context.Background(), TestMessage{To: "finance-test@example-lab.test", Subject: "s", BodyHTML: "b"})
	if err == nil {
		t.Fatal("expected an error for a CRLF-injecting HeaderFrom, got nil")
	}

	backend.mu.Lock()
	defer backend.mu.Unlock()
	if len(backend.received) != 0 {
		t.Fatalf("server received %d messages, want 0 -- a header-injection attempt must never reach the wire", len(backend.received))
	}
}

func TestSpoofableSMTPInjector_SubjectWithCRLF_RejectedBeforeSend(t *testing.T) {
	backend, addr := startSpoofTestServer(t)

	injector := &SpoofableSMTPInjector{
		EnvelopeFrom: "ceo@spoofed-lookalike.test",
		TargetMX:     addr,
	}
	_, err := injector.SendTestMessage(context.Background(), TestMessage{
		To:       "finance-test@example-lab.test",
		Subject:  "Urgent\r\nBcc: attacker@evil.test",
		BodyHTML: "b",
	})
	if err == nil {
		t.Fatal("expected an error for a CRLF-injecting Subject, got nil")
	}

	backend.mu.Lock()
	defer backend.mu.Unlock()
	if len(backend.received) != 0 {
		t.Fatalf("server received %d messages, want 0 -- a header-injection attempt must never reach the wire", len(backend.received))
	}
}

func TestSpoofableSMTPInjector_RelayHostUsedWhenTargetMXEmpty(t *testing.T) {
	backend, addr := startSpoofTestServer(t)

	injector := &SpoofableSMTPInjector{
		EnvelopeFrom: "ceo@spoofed-lookalike.test",
		RelayHost:    addr,
	}
	_, err := injector.SendTestMessage(context.Background(), TestMessage{To: "finance-test@example-lab.test", Subject: "s", BodyHTML: "b"})
	if err != nil {
		t.Fatalf("SendTestMessage: %v", err)
	}

	backend.mu.Lock()
	defer backend.mu.Unlock()
	if len(backend.received) != 1 {
		t.Fatalf("server received %d messages, want 1 -- RelayHost must be used when TargetMX is empty", len(backend.received))
	}
}
