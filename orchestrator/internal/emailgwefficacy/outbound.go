package emailgwefficacy

// Workstream 6 of the EmailGW mastery roadmap: outbound DLP testing
// needs mail sent AS an authenticated internal mailbox, not spoofed
// inbound mail -- exercise.SpoofableSMTPInjector's whole model is an
// arbitrary external envelope-from, which is the wrong tool here (see
// injection.go's own package comment). This file is the new, separate
// sender abstraction for that: Microsoft Graph's sendMail action,
// under the Mail.Send application permission, via
// internal/vendors/defender.Client.SendMail.
import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/audspect/bas/internal/vendors/defender"
)

// OutboundSender is the authenticated-outbound-sending counterpart to
// InjectionTarget/exercise.SpoofableSMTPInjector -- deliberately a
// different interface, never a variant of InjectionTarget, because
// "send as this mailbox via Graph" and "spoof this envelope-from via
// SMTP" are not the same capability and must never be silently
// interchangeable.
type OutboundSender interface {
	// SendOutboundMessage sends msg as fromMailbox to recipient, and
	// returns the real send timestamp plus a hash of the sent content
	// (the same SenderPayloadHash role exercise.SpoofableSMTPInjector's
	// own OriginLeg plays -- informational/audit only, never used for
	// evidence matching, which is keyed by MessageRef).
	SendOutboundMessage(ctx context.Context, fromMailbox, recipient string, msg OutboundMessage) (sentAt time.Time, payloadHash string, err error)
}

// OutboundMessage is the content an outbound scenario's test message
// needs -- mirrors InjectableMessage's own minimal shape, without the
// Attachment field (no outbound scenario in this package sends one).
type OutboundMessage struct {
	Subject  string
	BodyHTML string
}

// GraphOutboundSender implements OutboundSender via Microsoft Graph's
// sendMail action. IdempotencyKeyFunc is overridable so a test can
// supply a deterministic key; defaults to a timestamp-derived one.
type GraphOutboundSender struct {
	Client             *defender.Client
	IdempotencyKeyFunc func() string
}

// NewGraphOutboundSender wraps client, defaulting IdempotencyKeyFunc
// to a real-clock-derived key.
func NewGraphOutboundSender(client *defender.Client) *GraphOutboundSender {
	return &GraphOutboundSender{
		Client:             client,
		IdempotencyKeyFunc: func() string { return fmt.Sprintf("emailgw-outbound-%d", time.Now().UnixNano()) },
	}
}

func (s *GraphOutboundSender) SendOutboundMessage(ctx context.Context, fromMailbox, recipient string, msg OutboundMessage) (time.Time, string, error) {
	key := ""
	if s.IdempotencyKeyFunc != nil {
		key = s.IdempotencyKeyFunc()
	}
	err := s.Client.SendMail(ctx, fromMailbox, defender.SendMailMessage{
		ToRecipients:   []string{recipient},
		Subject:        msg.Subject,
		BodyHTML:       msg.BodyHTML,
		IdempotencyKey: key,
	})
	if err != nil {
		return time.Time{}, "", fmt.Errorf("GraphOutboundSender: %w", err)
	}
	sum := sha256.Sum256([]byte(fromMailbox + "|" + recipient + "|" + msg.Subject + "|" + msg.BodyHTML))
	return time.Now(), hex.EncodeToString(sum[:]), nil
}

// outboundScenarioTestContent is the generic, synthetic content for
// every outbound MessageClass this package has OutboundSenderMailbox
// wired for -- the outbound counterpart to injection.go's own
// scenarioTestContent map. The sensitive-marker body uses two
// well-known, industry-standard, never-real test values, same
// "universally-recognized, deliberately harmless marker" discipline
// as injection.go's own eicarTestString:
//   - "4111111111111111": Visa's own officially published test card
//     number (used throughout the payments industry for exactly this
//     purpose), never a real, chargeable card.
//   - "000-00-0000": the NNN-NN-NNNN shape a DLP sensitive-info-type
//     detector pattern-matches on, with an area number (000) the SSA
//     has never issued -- structurally guaranteed to never be a real
//     person's SSN.
var outboundScenarioTestContent = map[string]OutboundMessage{
	"outbound-dlp-sensitive-marker": {
		Subject:  "Customer payment details for file update",
		BodyHTML: "<p>Please update our records with the customer's card number 4111111111111111 and SSN 000-00-0000.</p>",
	},
	"outbound-ordinary-mail": {
		Subject:  "Team meeting notes",
		BodyHTML: "<p>Attaching this week's team meeting notes, nothing sensitive here.</p>",
	},
}

// OutboundScenarioTestContent returns the OutboundMessage content for
// exp's own MessageClass, and whether one exists -- a lookup, not a
// fallback, same discipline as ScenarioTestContent.
func OutboundScenarioTestContent(exp MailExpectation) (OutboundMessage, bool) {
	content, ok := outboundScenarioTestContent[exp.MessageClass]
	return content, ok
}

// SendOutboundTestMessage sends exp's own outbound test message for
// real via sender, and returns the sender-side half of
// OriginDeliveryObservation -- the outbound-sending counterpart to
// InjectScenarioMessage. Returns an error, never a silent no-op, when
// exp.OutboundSenderMailbox is empty -- same deliberate, checked
// "not wired for real injection" signal EnvelopeFrom's own doc
// comment describes, kept as a SEPARATE field because the two sending
// mechanisms are not interchangeable (see this file's own package
// comment).
func SendOutboundTestMessage(ctx context.Context, sender OutboundSender, exp MailExpectation, content OutboundMessage) (OriginDeliveryObservation, error) {
	if exp.OutboundSenderMailbox == "" {
		return OriginDeliveryObservation{}, fmt.Errorf("SendOutboundTestMessage: %s has no OutboundSenderMailbox set -- not wired for real outbound sending, see %s's own Note", exp.MessageClass, exp.MessageClass)
	}
	sentAt, hash, err := sender.SendOutboundMessage(ctx, exp.OutboundSenderMailbox, exp.Recipient, content)
	if err != nil {
		return OriginDeliveryObservation{}, fmt.Errorf("SendOutboundTestMessage: %w", err)
	}
	return OriginDeliveryObservation{SenderPayloadHash: hash, Timestamp: sentAt}, nil
}
