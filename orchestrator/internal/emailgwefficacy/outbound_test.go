package emailgwefficacy

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/audspect/bas/internal/vendors/defender"
)

type fakeOutboundSender struct {
	calledFrom, calledTo string
	calledMsg            OutboundMessage
	returnErr            error
}

func (f *fakeOutboundSender) SendOutboundMessage(ctx context.Context, fromMailbox, recipient string, msg OutboundMessage) (time.Time, string, error) {
	f.calledFrom, f.calledTo, f.calledMsg = fromMailbox, recipient, msg
	if f.returnErr != nil {
		return time.Time{}, "", f.returnErr
	}
	return time.Now(), "fake-hash", nil
}

func TestSendOutboundTestMessage_UnwiredExpectation_ReturnsErrorNeverCallsSender(t *testing.T) {
	exp := MailExpectation{MessageClass: "not-wired-for-outbound"}
	sender := &fakeOutboundSender{}
	_, err := SendOutboundTestMessage(context.Background(), sender, exp, OutboundMessage{})
	if err == nil {
		t.Fatal("expected an error for an expectation with no OutboundSenderMailbox")
	}
	if sender.calledFrom != "" {
		t.Errorf("sender was called (calledFrom=%q), want it never invoked for an unwired expectation", sender.calledFrom)
	}
}

func TestSendOutboundTestMessage_Wired_CallsSenderWithExpectationFields(t *testing.T) {
	exp := OutboundDLPExpectation(true)
	content, ok := OutboundScenarioTestContent(exp)
	if !ok {
		t.Fatalf("OutboundScenarioTestContent: no content registered for %q", exp.MessageClass)
	}
	sender := &fakeOutboundSender{}
	obs, err := SendOutboundTestMessage(context.Background(), sender, exp, content)
	if err != nil {
		t.Fatalf("SendOutboundTestMessage: %v", err)
	}
	if sender.calledFrom != exp.OutboundSenderMailbox {
		t.Errorf("calledFrom = %q, want %q", sender.calledFrom, exp.OutboundSenderMailbox)
	}
	if sender.calledTo != exp.Recipient {
		t.Errorf("calledTo = %q, want %q", sender.calledTo, exp.Recipient)
	}
	if sender.calledMsg.Subject != content.Subject {
		t.Errorf("calledMsg.Subject = %q, want %q", sender.calledMsg.Subject, content.Subject)
	}
	if obs.SenderPayloadHash != "fake-hash" {
		t.Errorf("SenderPayloadHash = %q, want %q", obs.SenderPayloadHash, "fake-hash")
	}
	if obs.Timestamp.IsZero() {
		t.Error("Timestamp is zero, want the sender's real send time")
	}
}

func TestSendOutboundTestMessage_SenderError_PropagatesWrapped(t *testing.T) {
	exp := OutboundDLPExpectation(false)
	sender := &fakeOutboundSender{returnErr: context.DeadlineExceeded}
	_, err := SendOutboundTestMessage(context.Background(), sender, exp, OutboundMessage{})
	if err == nil {
		t.Fatal("expected the sender's error to propagate")
	}
}

func TestOutboundDLPExpectation_BothDirections_AreWiredViaOutboundSenderMailbox(t *testing.T) {
	for _, sensitive := range []bool{true, false} {
		exp := OutboundDLPExpectation(sensitive)
		if exp.OutboundSenderMailbox == "" {
			t.Errorf("sensitive=%v: OutboundSenderMailbox is empty, want it wired", sensitive)
		}
		if exp.EnvelopeFrom != "" {
			t.Errorf("sensitive=%v: EnvelopeFrom = %q, want empty -- this scenario is wired via OutboundSenderMailbox, not SpoofableSMTPInjector", sensitive, exp.EnvelopeFrom)
		}
		if _, ok := OutboundScenarioTestContent(exp); !ok {
			t.Errorf("sensitive=%v: no OutboundScenarioTestContent registered for MessageClass %q", sensitive, exp.MessageClass)
		}
	}
}

func TestGraphOutboundSender_SendsViaRealGraphSendMailAndReturnsStableHash(t *testing.T) {
	tokenSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"access_token": "tok", "expires_in": 3600})
	}))
	defer tokenSrv.Close()

	var gotPath string
	graphSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.WriteHeader(http.StatusAccepted)
	}))
	defer graphSrv.Close()

	client := defender.New(defender.Config{TenantID: "t1", ClientID: "c1", ClientSecret: "s1"})
	*client.TokenURL() = tokenSrv.URL
	client.BaseURL = graphSrv.URL

	sender := NewGraphOutboundSender(client)
	sentAt, hash1, err := sender.SendOutboundMessage(context.Background(), "finance-user@example-lab.test", "external-partner-test@external-lab.test", OutboundMessage{Subject: "s", BodyHTML: "b"})
	if err != nil {
		t.Fatalf("SendOutboundMessage: %v", err)
	}
	if gotPath != "/users/finance-user@example-lab.test/sendMail" {
		t.Fatalf("path = %q, want the real Graph sendMail endpoint for the given mailbox", gotPath)
	}
	if sentAt.IsZero() {
		t.Error("sentAt is zero, want a real send timestamp")
	}

	_, hash2, err := sender.SendOutboundMessage(context.Background(), "finance-user@example-lab.test", "external-partner-test@external-lab.test", OutboundMessage{Subject: "s", BodyHTML: "b"})
	if err != nil {
		t.Fatalf("second SendOutboundMessage: %v", err)
	}
	if hash1 != hash2 {
		t.Errorf("hash1=%q hash2=%q, want the same hash for identical content", hash1, hash2)
	}
}

func TestGraphOutboundSender_PermissionDenied_PropagatesError(t *testing.T) {
	tokenSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"access_token": "tok", "expires_in": 3600})
	}))
	defer tokenSrv.Close()
	graphSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer graphSrv.Close()

	client := defender.New(defender.Config{TenantID: "t1", ClientID: "c1", ClientSecret: "s1"})
	*client.TokenURL() = tokenSrv.URL
	client.BaseURL = graphSrv.URL

	sender := NewGraphOutboundSender(client)
	_, _, err := sender.SendOutboundMessage(context.Background(), "finance-user@example-lab.test", "x@y.test", OutboundMessage{})
	if err == nil {
		t.Fatal("expected a permission error to propagate")
	}
}
