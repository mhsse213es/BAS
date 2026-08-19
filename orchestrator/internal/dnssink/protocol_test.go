package dnssink

import (
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func aQuery(name string) *dns.Msg {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), dns.TypeA)
	return m
}

func TestTooLarge(t *testing.T) {
	small := make([]byte, maxPacketBytes)
	if tooLarge(small) {
		t.Error("packet at exactly the limit should not be rejected")
	}
	big := make([]byte, maxPacketBytes+1)
	if !tooLarge(big) {
		t.Error("packet one byte over the limit should be rejected")
	}
}

func TestExtractRecord_HeaderRecord(t *testing.T) {
	rec, ok := extractRecord(aQuery("000.4.abcd1234ef567890.dnssink.audspect.local"), "dnssink.audspect.local")
	if !ok {
		t.Fatal("expected a valid header record")
	}
	if rec.Seq != 0 {
		t.Errorf("Seq = %d, want 0", rec.Seq)
	}
	if rec.Payload != "4" {
		t.Errorf("Payload = %q, want %q", rec.Payload, "4")
	}
	if rec.Campaign != "abcd1234ef567890" {
		t.Errorf("Campaign = %q, want %q", rec.Campaign, "abcd1234ef567890")
	}
}

func TestExtractRecord_DataChunk(t *testing.T) {
	rec, ok := extractRecord(aQuery("001.MFXHI2DJNZSQ.abcd1234ef567890.dnssink.audspect.local"), "dnssink.audspect.local")
	if !ok {
		t.Fatal("expected a valid data chunk record")
	}
	if rec.Seq != 1 {
		t.Errorf("Seq = %d, want 1", rec.Seq)
	}
	if rec.Payload != "MFXHI2DJNZSQ" {
		t.Errorf("Payload = %q, want %q", rec.Payload, "MFXHI2DJNZSQ")
	}
}

func TestExtractRecord_WrongDomainSuffixRejected(t *testing.T) {
	_, ok := extractRecord(aQuery("001.MFXHI2DJNZSQ.abcd1234ef567890.evil.example"), "dnssink.audspect.local")
	if ok {
		t.Error("a query for a different domain suffix must not be treated as a tunneling record")
	}
}

func TestExtractRecord_NonAQueryRejected(t *testing.T) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn("001.MFXHI2DJNZSQ.abcd1234ef567890.dnssink.audspect.local"), dns.TypeAAAA)
	_, ok := extractRecord(m, "dnssink.audspect.local")
	if ok {
		t.Error("a non-A query must not be treated as a tunneling record")
	}
}

func TestExtractRecord_TooFewLabelsRejected(t *testing.T) {
	_, ok := extractRecord(aQuery("001.MFXHI2DJNZSQ.local"), "dnssink.audspect.local")
	if ok {
		t.Error("a query without enough labels for seq.chunk.campaign must be rejected")
	}
}

func TestExtractRecord_NonNumericSeqRejected(t *testing.T) {
	_, ok := extractRecord(aQuery("abc.MFXHI2DJNZSQ.abcd1234ef567890.dnssink.audspect.local"), "dnssink.audspect.local")
	if ok {
		t.Error("a non-numeric seq label must be rejected")
	}
}

func TestBuildResponse_NOERRORWithFixedARecord(t *testing.T) {
	query := aQuery("001.MFXHI2DJNZSQ.abcd1234ef567890.dnssink.audspect.local")
	resp := buildResponse(query)
	if resp.Rcode != dns.RcodeSuccess {
		t.Errorf("Rcode = %v, want NOERROR", resp.Rcode)
	}
	if resp.Id != query.Id {
		t.Errorf("Id = %d, want %d (must echo the query's transaction ID)", resp.Id, query.Id)
	}
	if len(resp.Answer) != 1 {
		t.Fatalf("Answer records = %d, want 1", len(resp.Answer))
	}
	a, ok := resp.Answer[0].(*dns.A)
	if !ok {
		t.Fatalf("Answer[0] is not an A record: %T", resp.Answer[0])
	}
	if !a.A.Equal(net.ParseIP(fixedResponseIP)) {
		t.Errorf("A = %v, want %v", a.A, fixedResponseIP)
	}
}

func TestBuildResponse_NonAQueryStillNOERRORNoAnswer(t *testing.T) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn("whatever.example"), dns.TypeTXT)
	resp := buildResponse(m)
	if resp.Rcode != dns.RcodeSuccess {
		t.Errorf("Rcode = %v, want NOERROR", resp.Rcode)
	}
	if len(resp.Answer) != 0 {
		t.Errorf("Answer records = %d, want 0 for a non-A query", len(resp.Answer))
	}
}

func TestRateLimiter_AllowsUpToLimitThenBlocks(t *testing.T) {
	rl := newRateLimiter(3, time.Minute)
	for i := 0; i < 3; i++ {
		if !rl.allow("10.0.0.1") {
			t.Fatalf("request %d should be allowed within the limit", i+1)
		}
	}
	if rl.allow("10.0.0.1") {
		t.Error("request beyond the limit should be blocked")
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
