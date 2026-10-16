package exercise

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"net/smtp"
	"strings"
	"time"
)

// SpoofableSMTPInjector sends one authorized test message with
// explicit control over envelope-from, HELO domain, and destination
// (direct-to-MX or via a configured relay) -- control SMTPInjector
// deliberately doesn't expose, because its own job (deliver a
// realistic phishing-simulation email through whatever relay the
// customer's exercise already uses) never needed to construct a
// deliberately SPF-failing or DKIM-misaligned message. EmailGW
// Mastery's sender-identity scenarios need exactly that control, so
// this is a new, small type rather than a change to SMTPInjector's
// existing fields or call sites -- per
// docs/superpowers/specs/2026-10-15-emailgw-mastery-phase3-first-real-vertical-design.md
// §2.
type SpoofableSMTPInjector struct {
	// EnvelopeFrom is the SMTP MAIL FROM address -- what SPF actually
	// evaluates. A fabricated, synthetic address only; never a real
	// customer, partner, or brand domain.
	EnvelopeFrom string
	// HeaderFrom is the message's From: header -- what DMARC
	// alignment compares the authenticated domain against. Defaults
	// to EnvelopeFrom when empty, so a caller testing SPF/DKIM
	// alignment alone doesn't have to set it separately.
	HeaderFrom string
	// HELODomain is the SMTP HELO/EHLO identity. Empty uses the local
	// hostname, matching net/smtp's own default.
	HELODomain string
	// TargetMX is the gateway-under-test's inbound mail host:port --
	// direct delivery, bypassing any relay. Takes precedence over
	// RelayHost when both are set.
	TargetMX string
	// RelayHost is a configured relay's host:port, used when
	// TargetMX is empty.
	RelayHost string
}

// TestMessage is one message to send -- intentionally minimal; the
// scenario layer (internal/emailgwefficacy) owns what message class
// each one represents, this type only carries what SMTP needs.
type TestMessage struct {
	To       string
	Subject  string
	BodyHTML string
}

// OriginLeg is the sender-side half of
// emailgwefficacy.OriginDeliveryObservation (observation-model item
// 3's first leg: what the authorized test sender actually
// transmitted). The receiving-side leg is a separate evidence
// provider's job, never this type's.
type OriginLeg struct {
	SenderPayloadHash string
	Timestamp         time.Time
}

// dialAddr resolves which host:port to connect to, per TargetMX's
// precedence over RelayHost documented on the struct.
func (s *SpoofableSMTPInjector) dialAddr() (string, error) {
	if s.TargetMX != "" {
		return s.TargetMX, nil
	}
	if s.RelayHost != "" {
		return s.RelayHost, nil
	}
	return "", fmt.Errorf("SpoofableSMTPInjector: neither TargetMX nor RelayHost is set")
}

// SendTestMessage delivers msg and returns the sender-side
// OriginLeg. It never inspects or infers the receiving system's
// outcome -- that is strictly a MailEvidenceProvider's job, per the
// observation model's own two-independent-legs discipline.
func (s *SpoofableSMTPInjector) SendTestMessage(ctx context.Context, msg TestMessage) (OriginLeg, error) {
	addr, err := s.dialAddr()
	if err != nil {
		return OriginLeg{}, err
	}
	headerFrom := s.HeaderFrom
	if headerFrom == "" {
		headerFrom = s.EnvelopeFrom
	}
	// EnvelopeFrom/HELODomain/msg.To are each validated against CRLF
	// injection by the stdlib itself (client.Mail/Hello/Rcpt below).
	// headerFrom and msg.Subject never pass through any smtp.Client
	// method -- they're written directly into the raw header block --
	// so this package must reject an embedded CR or LF itself, or a
	// caller could smuggle an extra header (e.g. a hidden Bcc) past
	// every other safeguard here.
	if err := rejectHeaderInjection("From", headerFrom); err != nil {
		return OriginLeg{}, err
	}
	if err := rejectHeaderInjection("Subject", msg.Subject); err != nil {
		return OriginLeg{}, err
	}
	raw := []byte(buildSpoofableMIME(headerFrom, msg.To, msg.Subject, msg.BodyHTML))

	dialer := &net.Dialer{}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return OriginLeg{}, fmt.Errorf("SpoofableSMTPInjector: dial %s: %w", addr, err)
	}

	heloHost, _, splitErr := net.SplitHostPort(addr)
	if splitErr != nil {
		heloHost = addr
	}
	client, err := smtp.NewClient(conn, heloHost)
	if err != nil {
		conn.Close()
		return OriginLeg{}, fmt.Errorf("SpoofableSMTPInjector: smtp client: %w", err)
	}
	defer client.Close()

	if s.HELODomain != "" {
		if err := client.Hello(s.HELODomain); err != nil {
			return OriginLeg{}, fmt.Errorf("SpoofableSMTPInjector: HELO %s: %w", s.HELODomain, err)
		}
	}
	if err := client.Mail(s.EnvelopeFrom); err != nil {
		return OriginLeg{}, fmt.Errorf("SpoofableSMTPInjector: MAIL FROM %s: %w", s.EnvelopeFrom, err)
	}
	if err := client.Rcpt(msg.To); err != nil {
		return OriginLeg{}, fmt.Errorf("SpoofableSMTPInjector: RCPT TO %s: %w", msg.To, err)
	}
	w, err := client.Data()
	if err != nil {
		return OriginLeg{}, fmt.Errorf("SpoofableSMTPInjector: DATA: %w", err)
	}
	if _, err := w.Write(raw); err != nil {
		return OriginLeg{}, fmt.Errorf("SpoofableSMTPInjector: write message: %w", err)
	}
	if err := w.Close(); err != nil {
		return OriginLeg{}, fmt.Errorf("SpoofableSMTPInjector: close DATA: %w", err)
	}

	sum := sha256.Sum256(raw)
	return OriginLeg{SenderPayloadHash: hex.EncodeToString(sum[:]), Timestamp: time.Now()}, nil
}

// rejectHeaderInjection errors if value contains a CR or LF -- either
// would let a caller terminate the named header early and inject
// arbitrary additional header lines (e.g. a hidden Bcc) into the raw
// MIME block buildSpoofableMIME writes directly to the wire.
func rejectHeaderInjection(headerName, value string) error {
	if strings.ContainsAny(value, "\r\n") {
		return fmt.Errorf("SpoofableSMTPInjector: %s contains a CR or LF, which would inject an extra header line", headerName)
	}
	return nil
}

func buildSpoofableMIME(headerFrom, to, subject, bodyHTML string) string {
	return "MIME-Version: 1.0\r\n" +
		"Content-Type: text/html; charset=UTF-8\r\n" +
		"From: " + headerFrom + "\r\n" +
		"To: " + to + "\r\n" +
		"Subject: " + subject + "\r\n" +
		"\r\n" +
		bodyHTML
}
