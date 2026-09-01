package smtpsink

import (
	"strings"
	"testing"
	"time"
)

const sampleMessage = "From: dlptest@sink.audspect.local\r\n" +
	"To: dlptest@sink.audspect.local\r\n" +
	"Subject: abcd1234ef567890abcd1234ef567890abcd1234ef567890abcd1234ef5678\r\n" +
	"Content-Type: text/plain\r\n" +
	"\r\n" +
	"abcd1234ef567890abcd1234ef567890abcd1234ef567890abcd1234ef5678\r\n" +
	"[BAS-SIM-DLP] CustomerID,PAN,Aadhaar,SWIFT,UPI,CreditCard\r\n" +
	"BAS-SIM-SINK,ABCDE1234F,123456789012,SBININBBXXX,fake.user@upi,4111111111111111\r\n"

func TestExtractSubjectAndBody_ParsesWellFormedMessage(t *testing.T) {
	subject, body, err := extractSubjectAndBody([]byte(sampleMessage))
	if err != nil {
		t.Fatalf("extractSubjectAndBody: %v", err)
	}
	want := "abcd1234ef567890abcd1234ef567890abcd1234ef567890abcd1234ef5678"
	if subject != want {
		t.Errorf("subject = %q, want %q", subject, want)
	}
	if !strings.Contains(string(body), "[BAS-SIM-DLP]") {
		t.Errorf("body does not contain the expected synthetic marker: %q", body)
	}
}

func TestExtractSubjectAndBody_MissingSubjectIsEmptyNotError(t *testing.T) {
	raw := "From: a@b.com\r\nTo: c@d.com\r\n\r\nno subject here\r\n"
	subject, _, err := extractSubjectAndBody([]byte(raw))
	if err != nil {
		t.Fatalf("extractSubjectAndBody: %v", err)
	}
	if subject != "" {
		t.Errorf("subject = %q, want empty for a message with no Subject header", subject)
	}
}

func TestExtractSubjectAndBody_RejectsMalformedMessage(t *testing.T) {
	if _, _, err := extractSubjectAndBody([]byte("not a valid message at all, no headers")); err == nil {
		t.Error("expected an error for a message with no header/body separator")
	}
}

func TestIsMultipart_DetectsMultipartContentType(t *testing.T) {
	raw := "Content-Type: multipart/mixed; boundary=xyz\r\n\r\nbody\r\n"
	if !isMultipart([]byte(raw)) {
		t.Error("expected a multipart/mixed Content-Type to be detected")
	}
}

func TestIsMultipart_PlainTextIsNotMultipart(t *testing.T) {
	if isMultipart([]byte(sampleMessage)) {
		t.Error("a plain text/plain message must not be flagged as multipart")
	}
}

func TestRateLimiter_AllowsUpToLimitPerWindow(t *testing.T) {
	rl := newRateLimiter(3, time.Minute)
	for i := 0; i < 3; i++ {
		if !rl.allow("10.0.0.1") {
			t.Fatalf("request %d should be allowed within the limit", i)
		}
	}
	if rl.allow("10.0.0.1") {
		t.Error("4th request in the same window should be rejected")
	}
}

func TestRateLimiter_TracksSourcesIndependently(t *testing.T) {
	rl := newRateLimiter(1, time.Minute)
	if !rl.allow("10.0.0.1") {
		t.Fatal("first request from 10.0.0.1 should be allowed")
	}
	if !rl.allow("10.0.0.2") {
		t.Error("a different source IP must have its own independent limit")
	}
}
