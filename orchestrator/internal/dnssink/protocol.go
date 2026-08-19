// Package dnssink implements a purpose-built DNS-tunneling exfiltration
// sink for the DLP validation suite -- a minimal UDP/53 listener that
// reassembles a base32-encoded payload from a sequence of DNS query
// labels, never a recursive resolver or general-purpose DNS server. See
// docs/superpowers/specs/2026-08-19-dns-tunneling-exfiltration-channel-design.md.
package dnssink

import (
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// DomainSuffix is the fixed label suffix a scenario's DNS-tunneling step
// targets (e.g. "000.4.<campaign-id>.dnssink.audspect.local"). It is a
// naming convention only, never a delegated DNS zone -- queries target
// {{SINK_DNS_SERVER}} (the orchestrator's own IP) directly and never go
// through recursive resolution.
const DomainSuffix = "dnssink.audspect.local"

// fixedResponseIP is returned in every A-record response this listener
// ever sends, regardless of whether the query was a recognized tunneling
// record. RFC 5737 TEST-NET-1 -- documentation-only, never routable.
const fixedResponseIP = "192.0.2.1"

// maxPacketBytes bounds the raw UDP payload size this listener will parse.
// A generous ceiling for legitimate DNS-over-UDP traffic; anything larger
// is dropped without being unpacked.
const maxPacketBytes = 512

// record is what this listener cares about from an incoming tunneling
// query -- deliberately narrow, not a general DNS message wrapper.
// Seq == 0 marks a header record, whose Payload is the declared total
// chunk count as a decimal string (not base32 -- see the plan's note on
// this simplification). Seq >= 1 marks a data chunk, whose Payload is the
// base32-encoded chunk text.
type record struct {
	Seq      int
	Payload  string
	Campaign string
}

// tooLarge reports whether raw exceeds this listener's maximum accepted
// UDP packet size. Checked before attempting to unpack -- oversized
// packets are dropped without ever being parsed.
func tooLarge(raw []byte) bool {
	return len(raw) > maxPacketBytes
}

// extractRecord validates msg against this listener's shape requirements
// and, if it matches, extracts its seq/payload/campaign components. ok is
// false for every rejection reason uniformly (wrong query type, too few
// labels, non-numeric seq, wrong domain suffix) -- callers always respond
// with the same fixed NOERROR record regardless of why a query didn't
// parse as a tunneling record.
func extractRecord(msg *dns.Msg, domainSuffix string) (rec record, ok bool) {
	if len(msg.Question) != 1 || msg.Question[0].Qtype != dns.TypeA {
		return record{}, false
	}
	name := strings.TrimSuffix(msg.Question[0].Name, ".")
	labels := strings.Split(name, ".")
	if len(labels) < 4 {
		return record{}, false
	}
	seq, err := strconv.Atoi(labels[0])
	if err != nil || seq < 0 || seq > 999 {
		return record{}, false
	}
	suffix := strings.Join(labels[3:], ".")
	if !strings.EqualFold(suffix, domainSuffix) {
		return record{}, false
	}
	return record{Seq: seq, Payload: labels[1], Campaign: labels[2]}, true
}

// buildResponse always returns a NOERROR response echoing the query's
// transaction ID and question section. An A-type query gets a single
// fixed A answer (fixedResponseIP); any other query type gets NOERROR
// with no answer section. Never NXDOMAIN -- see the design spec's
// rationale (a clean, consistent response lets every query in an
// nslookup-driven sequence complete without triggering retries or
// error-looking script output).
func buildResponse(query *dns.Msg) *dns.Msg {
	resp := new(dns.Msg)
	resp.SetReply(query)
	resp.Authoritative = true
	if len(query.Question) == 1 && query.Question[0].Qtype == dns.TypeA {
		resp.Answer = append(resp.Answer, &dns.A{
			Hdr: dns.RR_Header{Name: query.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
			A:   net.ParseIP(fixedResponseIP),
		})
	}
	return resp
}

// rateLimiter is a coarse, fixed-window per-source-IP abuse guard -- not a
// precision rate limiter, adequate for a low-throughput purpose-built
// listener that only ever expects traffic from BAS agents running a
// scenario step.
type rateLimiter struct {
	mu     sync.Mutex
	limit  int
	window time.Duration
	counts map[string]*windowCount
}

type windowCount struct {
	count      int
	windowEnds time.Time
}

func newRateLimiter(limit int, window time.Duration) *rateLimiter {
	return &rateLimiter{limit: limit, window: window, counts: map[string]*windowCount{}}
}

// allow reports whether sourceIP may send another packet in the current
// window, incrementing its count as a side effect.
func (rl *rateLimiter) allow(sourceIP string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	now := time.Now()
	wc, ok := rl.counts[sourceIP]
	if !ok || now.After(wc.windowEnds) {
		rl.counts[sourceIP] = &windowCount{count: 1, windowEnds: now.Add(rl.window)}
		return true
	}
	wc.count++
	return wc.count <= rl.limit
}
