# Network BAS Mastery Phase 5A: DNS Security Checks Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task (Native/inline execution, pre-selected for this plan — see Execution Handoff). Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build and expose two real DNS-security checks — an open-resolver test and a DNSSEC chain validator — as a new, independently-triggerable package with its own run/results persistence and HTTP API, satisfying the DNS half of Network BAS Phase 5's definition of done.

**Architecture:** New package `internal/networkdns`. The open-resolver test reuses `networkgraph.NetworkObservation`/`cloudgraph.PathState` exactly as Phase 1 does (it's genuinely reachability-shaped). DNSSEC chain validation gets its own four-state enum (`DNSSECState`), since `PathState`'s three reachability values and `networksecurity.SecurityState`'s three values both fail to represent "legitimately unsigned" vs. "signature validation failed" as distinct facts. Orchestration (`RunChecks`), persistence, and the HTTP API all mirror Phase 1's `RunDiscovery`/`network_discovery_runs` precedent directly.

**Tech Stack:** Go, `github.com/miekg/dns` (already a dependency via `internal/dnssink`, reused — no new library), Postgres (`pgxpool`), chi router.

**Spec:** `docs/superpowers/specs/2026-10-14-network-bas-phase5-dns-protocol-security-design.md` (§3-§6, §8 for this plan's scope; §4.1/§5.3-5.4/transport tables belong to the sibling Plan 5B, not this one)

## Global Constraints

- `MaxChecksPerRun = 50` (mirrors `networkgraph.MaxTargetsPerRun`).
- `DefaultCheckTimeout = 5 * time.Second`, `MaxCheckTimeout = 10 * time.Second` (more generous than Phase 1's 2s/5s — DNSSEC chain-walking is several sequential round-trips).
- `maxConcurrency = 10`, `MaxRunDuration = 60 * time.Second` (a `var`, not `const`, so tests can shorten it — mirrors `networkgraph.MaxRunDuration`'s exact reason).
- Every `Target`/domain/query parameter is explicitly caller-supplied — never auto-discovered, never inferred from a prior result.
- No credential interception, no crafted payloads: both checks send only standard, single, bounded DNS queries (normal record types, no amplification shape, no retries-as-abuse).
- Encrypted/incomplete-evidence limitations are surfaced as explicit `Unknown` + `Reason`, never silently promoted to a clean pass.
- `internal/dnssink` and the `dlp-exfiltration-dns-tunnel` scenario are not modified, not imported, not duplicated.
- Every new struct field gets an explicit, lowerCamelCase `json:` tag from the first draft — a non-negotiable lesson from this session's own Phase 3 regression (see Task 1, Task 3).
- The DNSSEC root trust anchor is an **injectable parameter** with a real production default, never hardcoded directly inside the validation function — the same seam `networkgraph.DialerProbe`'s injectable `dial` field uses, for the same reason: tests must be able to substitute their own self-signed chain instead of depending on live internet DNS.

## Review Focus

- **A missing DS record at a delegation point is not automatically "legitimately unsigned."** The spec requires a *signed* NSEC/NSEC3 proof of absence before classifying `DNSSECInsecure` — any other reason a DS record is missing (truncated response, stripped in transit, an NSEC3 hash-algorithm this validator doesn't support) must fall through to `DNSSECUnknown`. A test that only exercises "DS record present and valid" vs. "DS record present and invalid" would miss this distinction entirely. Owned by Task 3.
- **Presence of a DNSKEY/RRSIG record is not proof of a valid signature.** A test must construct a record set with a syntactically well-formed but *cryptographically wrong* RRSIG (signed with the wrong key, or over the wrong RRset) and confirm it's classified `DNSSECInvalid`, not `DNSSECSecure` — a validator that only checks "did I find an RRSIG" without actually verifying it would pass every other test in this plan while being completely wrong. Owned by Task 2.
- **A `REFUSED` open-resolver response and a timeout must classify differently** (`Blocked` vs. `Unknown`) even though both mean "no useful answer came back" — a test that only exercises one of the two could let a future refactor collapse them. Owned by Task 1.
- **`RunChecks` must isolate one check's failure from every other check in the same run** (mirroring `networkgraph.RunDiscovery`'s own isolation guarantee) — a test with a mixed batch (one check that errors, one that succeeds) must confirm the failing check doesn't block or corrupt the succeeding one's result. Owned by Task 4.
- **The tagged-union `DNSCheckResult` must never have both `Observation` and `DNSSEC` populated, or neither, for a given `CheckType`.** A test should assert this invariant directly for both check types, since a bug here would silently produce a result an API consumer can't correctly interpret. Owned by Task 4.

---

### Task 1: Open-Resolver Probe

**Files:**
- Create: `orchestrator/internal/networkdns/openresolver.go`
- Test: `orchestrator/internal/networkdns/openresolver_test.go`

**Interfaces:**
- Consumes: `networkgraph.Target`, `networkgraph.VantagePoint`, `networkgraph.NetworkObservation`, `cloudgraph.PathState`/`Provenance` (all existing, read-only).
- Produces: `type OpenResolverProbe interface { Probe(ctx context.Context, target networkgraph.Target, queryDomain string, timeout time.Duration) (cloudgraph.PathState, error) }`, `type DNSOpenResolverProbe struct{}` (the real implementation, with an injectable `exchange` func field for tests, mirroring `DialerProbe`'s injectable `dial` field).

- [ ] **Step 1: Write the failing tests**

```go
// orchestrator/internal/networkdns/openresolver_test.go
package networkdns

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/audspect/bas/internal/cloudgraph"
	"github.com/audspect/bas/internal/networkgraph"
	"github.com/miekg/dns"
)

func TestDNSOpenResolverProbe_AnswerComesBack_Observed(t *testing.T) {
	p := DNSOpenResolverProbe{exchange: func(m *dns.Msg, addr string) (*dns.Msg, error) {
		resp := new(dns.Msg)
		resp.SetReply(m)
		resp.Rcode = dns.RcodeSuccess
		rr, _ := dns.NewRR("example.test. 300 IN A 192.0.2.1")
		resp.Answer = append(resp.Answer, rr)
		return resp, nil
	}}
	state, err := p.Probe(context.Background(), networkgraph.Target{Host: "10.0.1.5", Port: 53}, "example.test.", time.Second)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if state != cloudgraph.Observed {
		t.Fatalf("state = %q, want Observed -- the resolver answered a recursive query it shouldn't have", state)
	}
}

func TestDNSOpenResolverProbe_Refused_Blocked(t *testing.T) {
	p := DNSOpenResolverProbe{exchange: func(m *dns.Msg, addr string) (*dns.Msg, error) {
		resp := new(dns.Msg)
		resp.SetReply(m)
		resp.Rcode = dns.RcodeRefused
		return resp, nil
	}}
	state, err := p.Probe(context.Background(), networkgraph.Target{Host: "10.0.1.5", Port: 53}, "example.test.", time.Second)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if state != cloudgraph.Blocked {
		t.Fatalf("state = %q, want Blocked -- REFUSED means correctly restricted", state)
	}
}

func TestDNSOpenResolverProbe_Timeout_Unknown(t *testing.T) {
	p := DNSOpenResolverProbe{exchange: func(m *dns.Msg, addr string) (*dns.Msg, error) {
		return nil, errors.New("i/o timeout")
	}}
	state, err := p.Probe(context.Background(), networkgraph.Target{Host: "10.0.1.5", Port: 53}, "example.test.", time.Second)
	if err == nil {
		t.Fatal("want a non-nil error alongside Unknown")
	}
	if state != cloudgraph.Unknown {
		t.Fatalf("state = %q, want Unknown -- a timeout proves nothing, never Blocked", state)
	}
}

func TestDNSOpenResolverProbe_ReferralComesBack_Observed(t *testing.T) {
	// A referral (no answer, but authority records pointing elsewhere)
	// still proves the resolver attempted recursion for a domain outside
	// its own authority -- the same misconfiguration as a direct answer.
	p := DNSOpenResolverProbe{exchange: func(m *dns.Msg, addr string) (*dns.Msg, error) {
		resp := new(dns.Msg)
		resp.SetReply(m)
		resp.Rcode = dns.RcodeSuccess
		ns, _ := dns.NewRR("test. 300 IN NS ns1.test.")
		resp.Ns = append(resp.Ns, ns)
		return resp, nil
	}}
	state, err := p.Probe(context.Background(), networkgraph.Target{Host: "10.0.1.5", Port: 53}, "example.test.", time.Second)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if state != cloudgraph.Observed {
		t.Fatalf("state = %q, want Observed", state)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd orchestrator && go test ./internal/networkdns/... -v`
Expected: FAIL — package/types do not exist yet.

- [ ] **Step 3: Write the probe**

```go
// orchestrator/internal/networkdns/openresolver.go

// Package networkdns adds two DNS-security checks -- an open-resolver
// reachability test and a DNSSEC chain validator -- as a new,
// independently-triggerable check family. It does not modify
// internal/dnssink (a passive DNS-tunnel-exfiltration receiver, zero
// overlap) or internal/networkgraph's existing types, which it reuses
// read-only. See
// docs/superpowers/specs/2026-10-14-network-bas-phase5-dns-protocol-security-design.md.
package networkdns

import (
	"context"
	"net"
	"strconv"
	"time"

	"github.com/miekg/dns"

	"github.com/audspect/bas/internal/cloudgraph"
	"github.com/audspect/bas/internal/networkgraph"
)

// OpenResolverProbe performs one bounded, single recursive DNS query
// against target, classifying whether the resolver answered a query it
// shouldn't have.
type OpenResolverProbe interface {
	Probe(ctx context.Context, target networkgraph.Target, queryDomain string, timeout time.Duration) (cloudgraph.PathState, error)
}

// exchangeFunc matches the shape of a single query/response round trip
// -- a seam so tests can inject a synthetic DNS response without ever
// sending real traffic. Production code always uses the real dns.Client.
type exchangeFunc func(m *dns.Msg, addr string) (*dns.Msg, error)

// DNSOpenResolverProbe is the only real implementation:
//   - any answer or referral       -> Observed (misconfigured: it recursed)
//   - REFUSED                      -> Blocked (correctly restricted)
//   - timeout, or any other error  -> Unknown (never Blocked -- a timeout proves nothing)
type DNSOpenResolverProbe struct {
	exchange exchangeFunc // nil in production use; set only by tests
}

func (p DNSOpenResolverProbe) Probe(ctx context.Context, target networkgraph.Target, queryDomain string, timeout time.Duration) (cloudgraph.PathState, error) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(queryDomain), dns.TypeA)
	m.RecursionDesired = true

	addr := net.JoinHostPort(target.Host, portOrDefault(target.Port))

	exchange := p.exchange
	if exchange == nil {
		client := &dns.Client{Timeout: timeout}
		exchange = func(msg *dns.Msg, a string) (*dns.Msg, error) {
			resp, _, err := client.ExchangeContext(ctx, msg, a)
			return resp, err
		}
	}

	resp, err := exchange(m, addr)
	if err != nil {
		return cloudgraph.Unknown, err
	}
	if resp.Rcode == dns.RcodeRefused {
		return cloudgraph.Blocked, nil
	}
	if len(resp.Answer) > 0 || len(resp.Ns) > 0 {
		return cloudgraph.Observed, nil
	}
	return cloudgraph.Unknown, nil
}

func portOrDefault(port int) string {
	if port == 0 {
		return "53"
	}
	return strconv.Itoa(port)
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd orchestrator && go test ./internal/networkdns/... -v`
Expected: PASS — 4/4.

- [ ] **Step 5: Commit**

```bash
git add orchestrator/internal/networkdns/openresolver.go orchestrator/internal/networkdns/openresolver_test.go
git commit -m "feat(networkdns): add open-resolver reachability probe"
```

---

### Task 2: DNSSEC Chain Validator — Core Signature Verification

**Files:**
- Create: `orchestrator/internal/networkdns/dnssec.go`
- Test: `orchestrator/internal/networkdns/dnssec_test.go`

**Interfaces:**
- Consumes: `github.com/miekg/dns`'s `RRSIG.Verify`, `DNSKEY.ToDS`, `DNSKEY.KeyTag`, `RRSIG.Sign` (test fixtures only), `cloudgraph.Provenance` (existing, read-only).
- Produces: `DNSSECState` + its four constants, `DNSSECResult`, `TrustAnchor{Zone string, DS *dns.DS}`, `RootTrustAnchor` (the real production default — see Step 3's note on verifying the live value), `type dnsQueryFunc func(domain string, qtype uint16) (*dns.Msg, error)` (the seam Task 3 wires to a real resolver), `func validateChain(domain string, anchor TrustAnchor, query dnsQueryFunc) DNSSECResult` (unexported — Task 4 is this package's only caller, via the exported `ValidateDNSSEC` wrapper Task 3 adds).

This task covers the happy path and cryptographic-failure path only (`DNSSECSecure`, `DNSSECInvalid` from a bad signature, `DNSSECUnknown` from a query error). Task 3 adds the `DNSSECInsecure`/authenticated-denial-of-existence path and the production `ValidateDNSSEC` entry point.

- [ ] **Step 1: Write the failing tests**

```go
// orchestrator/internal/networkdns/dnssec_test.go
package networkdns

import (
	"crypto"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// signedTestChain builds a minimal, self-contained DNSSEC chain for one
// zone: a KSK, a signed DNSKEY RRset, and a signed A record -- entirely
// deterministic, no network, no dependency on real DNS infrastructure.
// DNSKEY.Generate (the library's own key-generation helper, used
// identically in its own dnssec_test.go's TestSignVerify) creates the
// key pair AND populates ksk.PublicKey's wire-format encoding --
// callers never hand-encode the public key bytes themselves.
func signedTestChain(t *testing.T, zone string) (ksk *dns.DNSKEY, priv crypto.Signer, dnskeySet []dns.RR, aRecordSet []dns.RR) {
	t.Helper()
	ksk = &dns.DNSKEY{
		Hdr:       dns.RR_Header{Name: dns.Fqdn(zone), Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 300},
		Flags:     dns.SEP | dns.ZONE,
		Protocol:  3,
		Algorithm: dns.ECDSAP256SHA256,
	}
	privAny, err := ksk.Generate(256) // ECDSAP256SHA256 requires exactly 256
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	priv = privAny.(crypto.Signer)

	dnskeySig := signRRSet(t, ksk, priv, []dns.RR{ksk})
	dnskeySet = []dns.RR{ksk, dnskeySig}

	a, err := dns.NewRR(zone + " 300 IN A 192.0.2.1")
	if err != nil {
		t.Fatalf("build A record: %v", err)
	}
	aSig := signRRSet(t, ksk, priv, []dns.RR{a})
	aRecordSet = []dns.RR{a, aSig}

	return ksk, priv, dnskeySet, aRecordSet
}

// signRRSet signs rrset (all records sharing one name/type) with priv,
// under ksk's key tag -- same field-population sequence as the
// library's own TestSignVerify. Inception/Expiration span a year
// centered on now, so the fixture never expires mid-test-run.
func signRRSet(t *testing.T, ksk *dns.DNSKEY, priv crypto.Signer, rrset []dns.RR) *dns.RRSIG {
	t.Helper()
	sig := &dns.RRSIG{
		Hdr:         dns.RR_Header{Name: ksk.Hdr.Name, Rrtype: dns.TypeRRSIG, Class: dns.ClassINET, Ttl: 300},
		TypeCovered: rrset[0].Header().Rrtype,
		Algorithm:   ksk.Algorithm,
		Labels:      uint8(dns.CountLabel(rrset[0].Header().Name)),
		OrigTtl:     rrset[0].Header().Ttl,
		Expiration:  uint32(time.Now().Add(365 * 24 * time.Hour).Unix()),
		Inception:   uint32(time.Now().Add(-time.Hour).Unix()),
		KeyTag:      ksk.KeyTag(),
		SignerName:  ksk.Hdr.Name,
	}
	if err := sig.Sign(priv, rrset); err != nil {
		t.Fatalf("sign rrset: %v", err)
	}
	return sig
}
```

- [ ] **Step 2: Write the real tests using the fixture helper**

```go
func TestValidateChain_ValidSignature_Secure(t *testing.T) {
	ksk, _, dnskeySet, aRecordSet := signedTestChain(t, "example-test.")
	anchor := TrustAnchor{Zone: "example-test.", DS: ksk.ToDS(dns.SHA256)}
	query := func(domain string, qtype uint16) (*dns.Msg, error) {
		resp := new(dns.Msg)
		switch qtype {
		case dns.TypeDNSKEY:
			resp.Answer = dnskeySet
		case dns.TypeA:
			resp.Answer = aRecordSet
		}
		return resp, nil
	}
	result := validateChain("example-test.", anchor, query)
	if result.State != DNSSECSecure {
		t.Fatalf("State = %q, want secure -- Reason: %s", result.State, result.Reason)
	}
}

func TestValidateChain_TamperedSignature_Invalid(t *testing.T) {
	ksk, _, dnskeySet, aRecordSet := signedTestChain(t, "example-test.")
	// Corrupt the A record's RRSIG so it no longer verifies against the
	// correct key -- this must be caught by actual cryptographic
	// verification, not just "an RRSIG record was present".
	if sig, ok := aRecordSet[len(aRecordSet)-1].(*dns.RRSIG); ok {
		sig.Signature = sig.Signature[:len(sig.Signature)-4] + "AAAA"
	}
	anchor := TrustAnchor{Zone: "example-test.", DS: ksk.ToDS(dns.SHA256)}
	query := func(domain string, qtype uint16) (*dns.Msg, error) {
		resp := new(dns.Msg)
		switch qtype {
		case dns.TypeDNSKEY:
			resp.Answer = dnskeySet
		case dns.TypeA:
			resp.Answer = aRecordSet
		}
		return resp, nil
	}
	result := validateChain("example-test.", anchor, query)
	if result.State != DNSSECInvalid {
		t.Fatalf("State = %q, want invalid -- a tampered signature must fail verification, not merely be noticed as present", result.State)
	}
}

func TestValidateChain_QueryError_Unknown(t *testing.T) {
	anchor := TrustAnchor{Zone: "example-test.", DS: &dns.DS{}}
	query := func(domain string, qtype uint16) (*dns.Msg, error) {
		return nil, errTestQueryFailed
	}
	result := validateChain("example-test.", anchor, query)
	if result.State != DNSSECUnknown {
		t.Fatalf("State = %q, want unknown", result.State)
	}
}
```

Add `var errTestQueryFailed = errors.New("simulated query failure")` at the bottom of the test file, and add `"errors"` to the import block.

- [ ] **Step 3: Run tests to verify they fail**

Run: `cd orchestrator && go test ./internal/networkdns/... -run TestValidateChain -v`
Expected: FAIL — `DNSSECState`, `TrustAnchor`, `validateChain` undefined.

- [ ] **Step 4: Write the validator**

```go
// orchestrator/internal/networkdns/dnssec.go
package networkdns

import (
	"fmt"
	"time"

	"github.com/miekg/dns"

	"github.com/audspect/bas/internal/cloudgraph"
)

// DNSSECState mirrors the four validation states RFC 4035 defines for a
// validating resolver (Secure/Insecure/Bogus/Indeterminate), using this
// codebase's plainer wording for Bogus ("Invalid") and Indeterminate
// ("Unknown"). Kept separate from networksecurity.SecurityState -- that
// type's three values cannot faithfully represent the distinction
// between "legitimately unsigned" and "signature validation failed".
type DNSSECState string

const (
	DNSSECSecure   DNSSECState = "secure"
	DNSSECInsecure DNSSECState = "insecure"
	DNSSECInvalid  DNSSECState = "invalid"
	DNSSECUnknown  DNSSECState = "unknown"
)

type DNSSECResult struct {
	Domain     string                `json:"domain"`
	State      DNSSECState           `json:"state"`
	Reason     string                `json:"reason,omitempty"`
	Provenance cloudgraph.Provenance `json:"provenance"`
}

// TrustAnchor is the starting point for a chain-walk. DS is the
// published Delegation Signer record for Zone -- for the real root
// zone, this is RootTrustAnchor; tests inject their own self-signed
// anchor instead of depending on live internet DNS.
type TrustAnchor struct {
	Zone string
	DS   *dns.DS
}

// RootTrustAnchor is the production default: the current IANA-published
// root zone KSK (tag 20326, algorithm 8/RSASHA256, digest type 2/SHA-256).
// VERIFY THIS VALUE against https://data.iana.org/root-anchors/root-anchors.xml
// before relying on it for anything beyond this plan's fixture-only tests --
// getting it wrong silently fails every real validation. Never fetched at
// runtime; embedded here as a compile-time constant.
var RootTrustAnchor = TrustAnchor{
	Zone: ".",
	DS: &dns.DS{
		Hdr:        dns.RR_Header{Name: ".", Rrtype: dns.TypeDS, Class: dns.ClassINET},
		KeyTag:     20326,
		Algorithm:  dns.RSASHA256,
		DigestType: dns.SHA256,
		Digest:     "E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8",
	},
}

// dnsQueryFunc performs one DNS query, returning the raw response. A
// seam: Task 3 wires this to a real resolver; tests inject fixture data.
type dnsQueryFunc func(domain string, qtype uint16) (*dns.Msg, error)

// validateChain verifies domain's DNSSEC chain starting from anchor.
// This task implements only the signature-verification path (Secure /
// Invalid-on-bad-signature / Unknown-on-query-error); Task 3 adds the
// authenticated-denial-of-existence path for DNSSECInsecure.
func validateChain(domain string, anchor TrustAnchor, query dnsQueryFunc) DNSSECResult {
	now := time.Now()
	result := DNSSECResult{Domain: domain, Provenance: cloudgraph.Provenance{ObservedAt: now, Source: "networkdns"}}

	dnskeyResp, err := query(domain, dns.TypeDNSKEY)
	if err != nil {
		result.State = DNSSECUnknown
		result.Reason = fmt.Sprintf("DNSKEY query failed: %v", err)
		return result
	}
	var matchedKey *dns.DNSKEY
	var dnskeySig *dns.RRSIG
	var dnskeySet []dns.RR
	for _, rr := range dnskeyResp.Answer {
		dnskeySet = append(dnskeySet, rr)
		if sig, ok := rr.(*dns.RRSIG); ok {
			dnskeySig = sig
		}
	}
	for _, rr := range dnskeyResp.Answer {
		if key, ok := rr.(*dns.DNSKEY); ok {
			ds := key.ToDS(anchor.DS.DigestType)
			if ds != nil && ds.Digest == anchor.DS.Digest && ds.KeyTag == anchor.DS.KeyTag {
				matchedKey = key
				break
			}
		}
	}
	if matchedKey == nil {
		result.State = DNSSECInvalid
		result.Reason = "no DNSKEY in the response matches the trust anchor's DS record"
		return result
	}
	if dnskeySig == nil {
		result.State = DNSSECInvalid
		result.Reason = "DNSKEY RRset has no RRSIG to verify"
		return result
	}
	if err := dnskeySig.Verify(matchedKey, dnskeySet); err != nil {
		result.State = DNSSECInvalid
		result.Reason = fmt.Sprintf("DNSKEY RRset signature does not verify: %v", err)
		return result
	}

	aResp, err := query(domain, dns.TypeA)
	if err != nil {
		result.State = DNSSECUnknown
		result.Reason = fmt.Sprintf("A query failed: %v", err)
		return result
	}
	var aSig *dns.RRSIG
	var aSet []dns.RR
	for _, rr := range aResp.Answer {
		aSet = append(aSet, rr)
		if sig, ok := rr.(*dns.RRSIG); ok {
			aSig = sig
		}
	}
	if aSig == nil {
		result.State = DNSSECUnknown
		result.Reason = "answer RRset has no RRSIG to verify"
		return result
	}
	if err := aSig.Verify(matchedKey, aSet); err != nil {
		result.State = DNSSECInvalid
		result.Reason = fmt.Sprintf("answer RRset signature does not verify: %v", err)
		return result
	}

	result.State = DNSSECSecure
	return result
}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cd orchestrator && go test ./internal/networkdns/... -v`
Expected: PASS — 7/7 (4 from Task 1 + 3 from this task).

- [ ] **Step 6: Commit**

```bash
git add orchestrator/internal/networkdns/dnssec.go orchestrator/internal/networkdns/dnssec_test.go
git commit -m "feat(networkdns): add DNSSEC chain validator signature-verification path"
```

---

### Task 3: DNSSEC Chain Validator — Authenticated Denial of Existence & Production Entry Point

**Files:**
- Modify: `orchestrator/internal/networkdns/dnssec.go`
- Modify: `orchestrator/internal/networkdns/dnssec_test.go`

**Interfaces:**
- Consumes: Task 2's `validateChain`, `TrustAnchor`, `RootTrustAnchor`, `miekg/dns`'s `NSEC3.Cover`/`NSEC3.Match`.
- Produces: `func ValidateDNSSEC(domain string) DNSSECResult` (the real, production-facing entry point — wires `validateChain` to a real `dns.Client` against the system resolver, using `RootTrustAnchor`). Extends `validateChain`'s own logic in place (no new exported symbol) to classify `DNSSECInsecure` when a DS query returns a signed NSEC/NSEC3 proof of absence.

- [ ] **Step 1: Write the failing tests**

```go
// append to orchestrator/internal/networkdns/dnssec_test.go

func TestValidateChain_SignedNSECProvesNoDS_Insecure(t *testing.T) {
	ksk, priv, dnskeySet, _ := signedTestChain(t, "parent-test.")
	// A signed NSEC record at the parent, covering the child's name,
	// with no DS type bit set -- the standard authenticated-denial-of-
	// existence proof that no DS record exists for this delegation.
	nsec := &dns.NSEC{
		Hdr:        dns.RR_Header{Name: dns.Fqdn("child.parent-test."), Rrtype: dns.TypeNSEC, Class: dns.ClassINET, Ttl: 300},
		NextDomain: dns.Fqdn("zzz.parent-test."),
		TypeBitMap: []uint16{dns.TypeA, dns.TypeRRSIG, dns.TypeNSEC}, // deliberately no TypeDS
	}
	nsecSig := signRRSet(t, ksk, priv, []dns.RR{nsec})
	nsecSet := []dns.RR{nsec, nsecSig}

	anchor := TrustAnchor{Zone: "parent-test.", DS: ksk.ToDS(dns.SHA256)}
	query := func(domain string, qtype uint16) (*dns.Msg, error) {
		resp := new(dns.Msg)
		switch qtype {
		case dns.TypeDNSKEY:
			resp.Answer = dnskeySet
		case dns.TypeDS:
			resp.Ns = nsecSet // authority section carries the denial proof
		}
		return resp, nil
	}
	result := validateChain("child.parent-test.", anchor, query)
	if result.State != DNSSECInsecure {
		t.Fatalf("State = %q, want insecure -- a signed NSEC proving no DS exists is a legitimate unsigned delegation, Reason: %s", result.State, result.Reason)
	}
}

func TestValidateChain_MissingDSWithNoProof_Unknown(t *testing.T) {
	ksk, _, dnskeySet, _ := signedTestChain(t, "parent-test.")
	anchor := TrustAnchor{Zone: "parent-test.", DS: ksk.ToDS(dns.SHA256)}
	query := func(domain string, qtype uint16) (*dns.Msg, error) {
		resp := new(dns.Msg)
		if qtype == dns.TypeDNSKEY {
			resp.Answer = dnskeySet
		}
		// DS query returns nothing at all -- no answer, no NSEC/NSEC3
		// denial proof either. This must NOT be assumed Insecure.
		return resp, nil
	}
	result := validateChain("child.parent-test.", anchor, query)
	if result.State != DNSSECUnknown {
		t.Fatalf("State = %q, want unknown -- a missing DS with no authenticated denial proof is not evidence of anything", result.State)
	}
}
```

Both tests reuse `signedTestChain` and `signRRSet` exactly as Task 2 defined them — no new helper needed here.

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd orchestrator && go test ./internal/networkdns/... -run 'TestValidateChain_SignedNSEC|TestValidateChain_MissingDS' -v`
Expected: FAIL — current `validateChain` has no DS-query step at all yet (Task 2 only implemented the DNSKEY/A path); these tests need the DS step added.

- [ ] **Step 3: Extend `validateChain` and add `ValidateDNSSEC`**

Insert a DS-lookup step into `validateChain` (in `dnssec.go`) right after the DNSKEY-verification block and before the A-record query:

```go
	dsResp, err := query(domain, dns.TypeDS)
	if err != nil {
		result.State = DNSSECUnknown
		result.Reason = fmt.Sprintf("DS query failed: %v", err)
		return result
	}
	if len(dsResp.Answer) == 0 {
		if provenInsecureDelegation(domain, dsResp, matchedKey) {
			result.State = DNSSECInsecure
			result.Reason = "a signed NSEC/NSEC3 record proves no DS record exists for this delegation (legitimately unsigned)"
			return result
		}
		result.State = DNSSECUnknown
		result.Reason = "no DS record and no authenticated denial-of-existence proof -- insufficient evidence"
		return result
	}
```

Add the helper function:

```go
// provenInsecureDelegation reports whether resp's authority section
// carries a signed NSEC or NSEC3 record that authenticates the absence
// of a DS record for domain, verified against key. A missing DS record
// with no such proof is never treated as evidence of anything.
func provenInsecureDelegation(domain string, resp *dns.Msg, key *dns.DNSKEY) bool {
	var proofSet []dns.RR
	var proofSig *dns.RRSIG
	for _, rr := range resp.Ns {
		proofSet = append(proofSet, rr)
		if sig, ok := rr.(*dns.RRSIG); ok {
			proofSig = sig
			continue
		}
		switch denial := rr.(type) {
		case *dns.NSEC:
			if denial.Hdr.Name != dns.Fqdn(domain) {
				continue
			}
			for _, t := range denial.TypeBitMap {
				if t == dns.TypeDS {
					return false // DS bit IS set -- this proves the opposite
				}
			}
		case *dns.NSEC3:
			if !denial.Match(domain) && !denial.Cover(domain) {
				continue
			}
			for _, t := range denial.TypeBitMap {
				if t == dns.TypeDS {
					return false
				}
			}
		default:
			continue
		}
		if proofSig != nil && proofSig.Verify(key, proofSet) == nil {
			return true
		}
	}
	return false
}
```

Then add the production entry point:

```go
// ValidateDNSSEC validates domain's DNSSEC chain from the real root
// trust anchor, querying the system resolver. The only production
// caller of validateChain -- tests call validateChain directly with
// their own injected anchor and query function.
func ValidateDNSSEC(domain string) DNSSECResult {
	client := &dns.Client{Timeout: MaxCheckTimeout}
	query := func(d string, qtype uint16) (*dns.Msg, error) {
		m := new(dns.Msg)
		m.SetQuestion(dns.Fqdn(d), qtype)
		m.SetEdns0(4096, true) // DO bit -- request DNSSEC records
		resp, _, err := client.Exchange(m, "127.0.0.1:53") // system resolver; see Task 4's note on configurability
		return resp, err
	}
	return validateChain(domain, RootTrustAnchor, query)
}
```

Note: `ValidateDNSSEC`'s hardcoded `"127.0.0.1:53"` is a placeholder the implementer must replace with whatever this host's actual system-resolver address resolution looks like (e.g. parsing `/etc/resolv.conf` equivalently, or accepting the resolver address as a parameter) — ruled on and fixed during this task's own execution, not deferred, since an untested hardcoded loopback address would silently break this function in any real deployment. Ledger the exact fix chosen.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd orchestrator && go test ./internal/networkdns/... -v`
Expected: PASS — 9/9 (7 from Tasks 1-2 + 2 from this task).

- [ ] **Step 5: Commit**

```bash
git add orchestrator/internal/networkdns/dnssec.go orchestrator/internal/networkdns/dnssec_test.go
git commit -m "feat(networkdns): add authenticated-denial-of-existence handling and production DNSSEC entry point"
```

---

### Task 4: Orchestration — `RunChecks`

**Files:**
- Create: `orchestrator/internal/networkdns/run.go`
- Test: `orchestrator/internal/networkdns/run_test.go`

**Interfaces:**
- Consumes: `OpenResolverProbe`/`DNSOpenResolverProbe` (Task 1), `ValidateDNSSEC` (Task 3), `networkgraph.VantagePoint`/`Target`/`NetworkObservation`, `cloudgraph.Provenance`.
- Produces: `CheckType` (`CheckOpenResolver`, `CheckDNSSEC`), `DNSCheckRequest{CheckType, Target, QueryDomain}`, `DNSCheckResult{CheckType, Observation *networkgraph.NetworkObservation, DNSSEC *DNSSECResult}`, `RunStatus` (`RunCompleted`, `RunPartial` — same names/meaning as `networkgraph.RunStatus`, redeclared in this package per the "duplicate small logic across domain packages" convention), `MaxChecksPerRun`, `DefaultCheckTimeout`, `MaxCheckTimeout`, `MaxRunDuration` (var), `func RunChecks(ctx context.Context, probe OpenResolverProbe, vp networkgraph.VantagePoint, checks []DNSCheckRequest) (*RunResult, error)`, `RunResult{Status RunStatus, Results []DNSCheckResult}`.

- [ ] **Step 1: Write the failing tests**

```go
// orchestrator/internal/networkdns/run_test.go
package networkdns

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/audspect/bas/internal/cloudgraph"
	"github.com/audspect/bas/internal/networkgraph"
)

type stubOpenResolverProbe struct {
	state cloudgraph.PathState
	err   error
}

func (s stubOpenResolverProbe) Probe(ctx context.Context, target networkgraph.Target, queryDomain string, timeout time.Duration) (cloudgraph.PathState, error) {
	return s.state, s.err
}

func TestRunChecks_OpenResolverCheck_ProducesObservation(t *testing.T) {
	checks := []DNSCheckRequest{{CheckType: CheckOpenResolver, Target: networkgraph.Target{Host: "10.0.1.5", Port: 53}, QueryDomain: "example.test."}}
	result, err := RunChecks(context.Background(), stubOpenResolverProbe{state: cloudgraph.Blocked}, networkgraph.VantagePoint{ID: "vp1", NetworkPosition: "lab"}, checks)
	if err != nil {
		t.Fatalf("RunChecks: %v", err)
	}
	if len(result.Results) != 1 || result.Results[0].CheckType != CheckOpenResolver {
		t.Fatalf("got %+v, want one open-resolver result", result.Results)
	}
	if result.Results[0].Observation == nil || result.Results[0].Observation.State != cloudgraph.Blocked {
		t.Fatalf("Observation = %+v, want State=Blocked", result.Results[0].Observation)
	}
	if result.Results[0].DNSSEC != nil {
		t.Fatal("DNSSEC must be nil for an open-resolver check result")
	}
}

func TestRunChecks_EmptyChecksRejected(t *testing.T) {
	_, err := RunChecks(context.Background(), stubOpenResolverProbe{}, networkgraph.VantagePoint{ID: "vp1", NetworkPosition: "lab"}, nil)
	if err == nil {
		t.Fatal("want an error for zero checks")
	}
}

func TestRunChecks_TooManyChecksRejected(t *testing.T) {
	checks := make([]DNSCheckRequest, MaxChecksPerRun+1)
	for i := range checks {
		checks[i] = DNSCheckRequest{CheckType: CheckOpenResolver, Target: networkgraph.Target{Host: "10.0.1.5", Port: 53}, QueryDomain: "example.test."}
	}
	_, err := RunChecks(context.Background(), stubOpenResolverProbe{}, networkgraph.VantagePoint{ID: "vp1", NetworkPosition: "lab"}, checks)
	if err == nil {
		t.Fatal("want an error for exceeding MaxChecksPerRun")
	}
}

func TestRunChecks_OneFailingCheckDoesNotBlockOthers(t *testing.T) {
	checks := []DNSCheckRequest{
		{CheckType: CheckOpenResolver, Target: networkgraph.Target{Host: "10.0.1.5", Port: 53}, QueryDomain: "fails.test."},
		{CheckType: CheckOpenResolver, Target: networkgraph.Target{Host: "10.0.1.6", Port: 53}, QueryDomain: "succeeds.test."},
	}
	failingProbe := failingOnDomainProbe{failDomain: "fails.test."}
	result, err := RunChecks(context.Background(), failingProbe, networkgraph.VantagePoint{ID: "vp1", NetworkPosition: "lab"}, checks)
	if err != nil {
		t.Fatalf("RunChecks: %v", err)
	}
	if len(result.Results) != 2 {
		t.Fatalf("got %d results, want 2 -- one check's failure must not drop the other's result", len(result.Results))
	}
}

type failingOnDomainProbe struct{ failDomain string }

func (f failingOnDomainProbe) Probe(ctx context.Context, target networkgraph.Target, queryDomain string, timeout time.Duration) (cloudgraph.PathState, error) {
	if queryDomain == f.failDomain {
		return cloudgraph.Unknown, errors.New("simulated probe failure")
	}
	return cloudgraph.Observed, nil
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd orchestrator && go test ./internal/networkdns/... -run TestRunChecks -v`
Expected: FAIL — `RunChecks`, `DNSCheckRequest`, `MaxChecksPerRun` undefined.

- [ ] **Step 3: Implement**

```go
// orchestrator/internal/networkdns/run.go
package networkdns

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/audspect/bas/internal/cloudgraph"
	"github.com/audspect/bas/internal/networkgraph"
)

const (
	MaxChecksPerRun     = 50
	DefaultCheckTimeout = 5 * time.Second
	MaxCheckTimeout     = 10 * time.Second
	maxConcurrency      = 10
)

// MaxRunDuration is a var, not a const, so tests can shorten it --
// mirrors networkgraph.MaxRunDuration's exact reason.
var MaxRunDuration = 60 * time.Second

type CheckType string

const (
	CheckOpenResolver CheckType = "open-resolver"
	CheckDNSSEC       CheckType = "dnssec"
)

// DNSCheckRequest declares one check. Target is required for
// CheckOpenResolver and ignored for CheckDNSSEC (DNSSEC validation
// resolves the chain itself starting from the root trust anchor).
type DNSCheckRequest struct {
	CheckType   CheckType           `json:"checkType"`
	Target      networkgraph.Target `json:"target,omitempty"`
	QueryDomain string              `json:"queryDomain"`
}

// DNSCheckResult is a tagged union: exactly one of Observation/DNSSEC is
// populated, selected by CheckType.
type DNSCheckResult struct {
	CheckType   CheckType                        `json:"checkType"`
	Observation *networkgraph.NetworkObservation `json:"observation,omitempty"`
	DNSSEC      *DNSSECResult                    `json:"dnssec,omitempty"`
}

type RunStatus string

const (
	RunCompleted RunStatus = "completed"
	RunPartial   RunStatus = "partial"
)

type RunResult struct {
	Status  RunStatus
	Results []DNSCheckResult
}

// RunChecks executes every check with bounded concurrency, isolating
// one check's failure from every other -- mirrors
// networkgraph.RunDiscovery's own isolation guarantee.
func RunChecks(ctx context.Context, probe OpenResolverProbe, vp networkgraph.VantagePoint, checks []DNSCheckRequest) (*RunResult, error) {
	if len(checks) == 0 {
		return nil, fmt.Errorf("networkdns: RunChecks requires at least one check")
	}
	if len(checks) > MaxChecksPerRun {
		return nil, fmt.Errorf("networkdns: too many checks -- got %d, max %d", len(checks), MaxChecksPerRun)
	}

	runCtx, cancel := context.WithTimeout(ctx, MaxRunDuration)
	defer cancel()

	results := make([]DNSCheckResult, len(checks))
	sem := make(chan struct{}, maxConcurrency)
	var wg sync.WaitGroup
	for i, check := range checks {
		wg.Add(1)
		go func(i int, check DNSCheckRequest) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-runCtx.Done():
				results[i] = deadlineExceededResult(check)
				return
			}
			results[i] = runOneCheck(runCtx, probe, vp, check)
		}(i, check)
	}
	wg.Wait()

	status := RunCompleted
	if runCtx.Err() != nil {
		status = RunPartial
	}
	return &RunResult{Status: status, Results: results}, nil
}

func runOneCheck(ctx context.Context, probe OpenResolverProbe, vp networkgraph.VantagePoint, check DNSCheckRequest) DNSCheckResult {
	switch check.CheckType {
	case CheckDNSSEC:
		dnssec := ValidateDNSSEC(check.QueryDomain)
		return DNSCheckResult{CheckType: CheckDNSSEC, DNSSEC: &dnssec}
	default: // CheckOpenResolver
		state, probeErr := probe.Probe(ctx, check.Target, check.QueryDomain, DefaultCheckTimeout)
		errDetail := ""
		if probeErr != nil {
			errDetail = probeErr.Error()
		}
		obs := networkgraph.NetworkObservation{
			Target:         check.Target,
			VantagePointID: vp.ID,
			State:          state,
			ErrorDetail:    errDetail,
			Provenance:     cloudgraph.Provenance{Source: vp.NetworkPosition, ObservedAt: time.Now()},
		}
		return DNSCheckResult{CheckType: CheckOpenResolver, Observation: &obs}
	}
}

func deadlineExceededResult(check DNSCheckRequest) DNSCheckResult {
	if check.CheckType == CheckDNSSEC {
		return DNSCheckResult{CheckType: CheckDNSSEC, DNSSEC: &DNSSECResult{
			Domain: check.QueryDomain, State: DNSSECUnknown, Reason: "run deadline exceeded before this check ran",
			Provenance: cloudgraph.Provenance{ObservedAt: time.Now()},
		}}
	}
	return DNSCheckResult{CheckType: CheckOpenResolver, Observation: &networkgraph.NetworkObservation{
		Target: check.Target, State: cloudgraph.Unknown, ErrorDetail: "run deadline exceeded before this check ran",
		Provenance: cloudgraph.Provenance{ObservedAt: time.Now(), Confidence: "none"},
	}}
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd orchestrator && go test ./internal/networkdns/... -v`
Expected: PASS — 13/13 (9 from Tasks 1-3 + 4 from this task).

- [ ] **Step 5: Commit**

```bash
git add orchestrator/internal/networkdns/run.go orchestrator/internal/networkdns/run_test.go
git commit -m "feat(networkdns): add bounded-concurrency check orchestration"
```

---

### Task 5: Persistence

**Files:**
- Create: `orchestrator/internal/db/networkdnscheck_store.go`
- Test: `orchestrator/internal/db/networkdnscheck_store_test.go`
- Modify: `orchestrator/internal/testutil/testdb.go` (immediately after the existing `EnsureNetworkControlExpectationSchema` block — re-grep the exact current line number before editing, since Phase 4's fix pass may have shifted it)
- Modify: `orchestrator/cmd/server/main.go` (same, after `EnsureNetworkControlExpectationSchema`)

**Interfaces:**
- Consumes: `networkdns.DNSCheckRequest`/`DNSCheckResult`/`CheckType`/`RunStatus` (Tasks 1-4), the existing `nullableString` helper (`internal/db/networkdiscovery_store.go:78`, same package, reused).
- Produces: `func EnsureDNSSecurityCheckSchema(ctx, pool) error`, `type DNSSecurityCheckRun struct{ID, VantagePointID, RequestedBy, CheckCount, Status string/int, StartedAt, CompletedAt}`, `func InsertDNSSecurityCheckRun(ctx, pool, run *DNSSecurityCheckRun) error`, `func InsertDNSSecurityCheckResults(ctx, pool, runID string, results []networkdns.DNSCheckResult) error`, `func GetDNSSecurityCheckRun(ctx, pool, id) (*DNSSecurityCheckRun, error)`, `func ListDNSSecurityCheckRuns(ctx, pool, limit) ([]*DNSSecurityCheckRun, error)`, `func ListDNSSecurityCheckResultsByRun(ctx, pool, runID) ([]networkdns.DNSCheckResult, error)`, `func UpdateDNSSecurityCheckRunStatus(ctx, pool, id, status) error`.

- [ ] **Step 1: Write the failing tests**

```go
// orchestrator/internal/db/networkdnscheck_store_test.go
package db_test

import (
	"context"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/cloudgraph"
	"github.com/audspect/bas/internal/db"
	"github.com/audspect/bas/internal/networkdns"
	"github.com/audspect/bas/internal/networkgraph"
)

func TestInsertDNSSecurityCheckRun_RoundTripsThroughGetAndList(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		run := &db.DNSSecurityCheckRun{ID: "dnsrun-roundtrip-1", VantagePointID: "vp1", RequestedBy: "alice", CheckCount: 2, Status: "completed"}
		if err := db.InsertDNSSecurityCheckRun(context.Background(), pool, run); err != nil {
			t.Fatalf("insert run: %v", err)
		}

		obs := networkgraph.NetworkObservation{Target: networkgraph.Target{Host: "10.0.1.5", Port: 53}, VantagePointID: "vp1", State: cloudgraph.Blocked}
		dnssec := networkdns.DNSSECResult{Domain: "example.test.", State: networkdns.DNSSECSecure}
		results := []networkdns.DNSCheckResult{
			{CheckType: networkdns.CheckOpenResolver, Observation: &obs},
			{CheckType: networkdns.CheckDNSSEC, DNSSEC: &dnssec},
		}
		if err := db.InsertDNSSecurityCheckResults(context.Background(), pool, run.ID, results); err != nil {
			t.Fatalf("insert results: %v", err)
		}

		gotRun, err := db.GetDNSSecurityCheckRun(context.Background(), pool, run.ID)
		if err != nil {
			t.Fatalf("get run: %v", err)
		}
		if gotRun.RequestedBy != "alice" || gotRun.CheckCount != 2 {
			t.Fatalf("got %+v, want RequestedBy=alice CheckCount=2", gotRun)
		}

		gotResults, err := db.ListDNSSecurityCheckResultsByRun(context.Background(), pool, run.ID)
		if err != nil {
			t.Fatalf("list results: %v", err)
		}
		if len(gotResults) != 2 {
			t.Fatalf("got %d results, want 2", len(gotResults))
		}
		var sawOpenResolver, sawDNSSEC bool
		for _, r := range gotResults {
			if r.CheckType == networkdns.CheckOpenResolver {
				sawOpenResolver = true
				if r.Observation == nil || r.Observation.State != cloudgraph.Blocked {
					t.Fatalf("open-resolver result round-trip mismatch: %+v", r.Observation)
				}
			}
			if r.CheckType == networkdns.CheckDNSSEC {
				sawDNSSEC = true
				if r.DNSSEC == nil || r.DNSSEC.State != networkdns.DNSSECSecure {
					t.Fatalf("dnssec result round-trip mismatch: %+v", r.DNSSEC)
				}
			}
		}
		if !sawOpenResolver || !sawDNSSEC {
			t.Fatalf("missing a result type in round-trip: openResolver=%v dnssec=%v", sawOpenResolver, sawDNSSEC)
		}

		list, err := db.ListDNSSecurityCheckRuns(context.Background(), pool, 100)
		if err != nil {
			t.Fatalf("list runs: %v", err)
		}
		found := false
		for _, r := range list {
			if r.ID == run.ID {
				found = true
			}
		}
		if !found {
			t.Fatal("inserted run should appear in the list")
		}
	})
}

func TestGetDNSSecurityCheckRun_NonexistentIDReturnsErrNoRows(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		_, err := db.GetDNSSecurityCheckRun(context.Background(), pool, "nonexistent-id")
		if !errors.Is(err, pgx.ErrNoRows) {
			t.Fatalf("got %v, want an error satisfying errors.Is(err, pgx.ErrNoRows)", err)
		}
	})
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd orchestrator && go vet ./internal/db/...`
Expected: FAIL — `db.DNSSecurityCheckRun`, `db.InsertDNSSecurityCheckRun`, etc. undefined.

- [ ] **Step 3: Implement the store**

```go
// orchestrator/internal/db/networkdnscheck_store.go
package db

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/cloudgraph"
	"github.com/audspect/bas/internal/networkdns"
	"github.com/audspect/bas/internal/networkgraph"
)

func EnsureDNSSecurityCheckSchema(ctx context.Context, pool *pgxpool.Pool) error {
	_, err := pool.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS dns_security_check_runs (
			id               text        PRIMARY KEY DEFAULT gen_random_uuid()::text,
			vantage_point_id text        NOT NULL,
			requested_by     text,
			check_count      int         NOT NULL,
			status           text        NOT NULL,
			started_at       timestamptz NOT NULL DEFAULT NOW(),
			completed_at     timestamptz
		)`)
	if err != nil {
		return fmt.Errorf("dns_security_check_runs: ensure schema: %w", err)
	}
	_, err = pool.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS dns_security_check_results (
			id                text        PRIMARY KEY DEFAULT gen_random_uuid()::text,
			run_id            text        NOT NULL REFERENCES dns_security_check_runs(id),
			check_type        text        NOT NULL,
			target_host       text,
			target_port       int,
			path_state        text,
			error_detail      text,
			dnssec_domain     text,
			dnssec_state      text,
			dnssec_reason     text,
			observed_at       timestamptz NOT NULL DEFAULT NOW()
		)`)
	if err != nil {
		return fmt.Errorf("dns_security_check_results: ensure schema: %w", err)
	}
	_, err = pool.Exec(ctx, `CREATE INDEX IF NOT EXISTS idx_dns_security_check_results_run ON dns_security_check_results (run_id)`)
	if err != nil {
		return fmt.Errorf("dns_security_check_results: ensure index: %w", err)
	}
	return nil
}

type DNSSecurityCheckRun struct {
	ID             string     `json:"id"`
	VantagePointID string     `json:"vantagePointId"`
	RequestedBy    string     `json:"requestedBy,omitempty"`
	CheckCount     int        `json:"checkCount"`
	Status         string     `json:"status"`
	StartedAt      time.Time  `json:"startedAt"`
	CompletedAt    *time.Time `json:"completedAt,omitempty"`
}

func InsertDNSSecurityCheckRun(ctx context.Context, pool *pgxpool.Pool, run *DNSSecurityCheckRun) error {
	_, err := pool.Exec(ctx,
		`INSERT INTO dns_security_check_runs (id, vantage_point_id, requested_by, check_count, status)
		 VALUES ($1,$2,$3,$4,$5)`,
		run.ID, run.VantagePointID, nullableString(run.RequestedBy), run.CheckCount, run.Status)
	if err != nil {
		return fmt.Errorf("dns_security_check_runs: insert %s: %w", run.ID, err)
	}
	return nil
}

func UpdateDNSSecurityCheckRunStatus(ctx context.Context, pool *pgxpool.Pool, id string, status string) error {
	_, err := pool.Exec(ctx, `UPDATE dns_security_check_runs SET status = $1, completed_at = NOW() WHERE id = $2`, status, id)
	if err != nil {
		return fmt.Errorf("dns_security_check_runs: update status for %s: %w", id, err)
	}
	return nil
}

func scanDNSSecurityCheckRun(row pgx.Row) (*DNSSecurityCheckRun, error) {
	run := &DNSSecurityCheckRun{}
	var requestedBy *string
	if err := row.Scan(&run.ID, &run.VantagePointID, &requestedBy, &run.CheckCount, &run.Status, &run.StartedAt, &run.CompletedAt); err != nil {
		return nil, err
	}
	if requestedBy != nil {
		run.RequestedBy = *requestedBy
	}
	return run, nil
}

func GetDNSSecurityCheckRun(ctx context.Context, pool *pgxpool.Pool, id string) (*DNSSecurityCheckRun, error) {
	row := pool.QueryRow(ctx,
		`SELECT id, vantage_point_id, requested_by, check_count, status, started_at, completed_at
		 FROM dns_security_check_runs WHERE id = $1`, id)
	run, err := scanDNSSecurityCheckRun(row)
	if err != nil {
		return nil, fmt.Errorf("dns_security_check_runs: get %s: %w", id, err)
	}
	return run, nil
}

func ListDNSSecurityCheckRuns(ctx context.Context, pool *pgxpool.Pool, limit int) ([]*DNSSecurityCheckRun, error) {
	rows, err := pool.Query(ctx,
		`SELECT id, vantage_point_id, requested_by, check_count, status, started_at, completed_at
		 FROM dns_security_check_runs ORDER BY started_at DESC LIMIT $1`, limit)
	if err != nil {
		return nil, fmt.Errorf("dns_security_check_runs: list: %w", err)
	}
	defer rows.Close()
	var out []*DNSSecurityCheckRun
	for rows.Next() {
		run, err := scanDNSSecurityCheckRun(rows)
		if err != nil {
			return nil, fmt.Errorf("dns_security_check_runs: list scan: %w", err)
		}
		out = append(out, run)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("dns_security_check_runs: list rows: %w", err)
	}
	return out, nil
}

// InsertDNSSecurityCheckResults writes every result for one run in a
// single transaction -- mirrors InsertNetworkObservations' own
// all-or-nothing semantics.
func InsertDNSSecurityCheckResults(ctx context.Context, pool *pgxpool.Pool, runID string, results []networkdns.DNSCheckResult) error {
	tx, err := pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("dns_security_check_results: begin tx: %w", err)
	}
	defer tx.Rollback(ctx)

	for _, r := range results {
		var host *string
		var port *int
		var pathState, errDetail *string
		var dnssecDomain, dnssecState, dnssecReason *string
		var observedAt time.Time

		switch r.CheckType {
		case networkdns.CheckOpenResolver:
			if r.Observation != nil {
				host = nullableString(r.Observation.Target.Host)
				p := r.Observation.Target.Port
				port = &p
				ps := string(r.Observation.State)
				pathState = &ps
				errDetail = nullableString(r.Observation.ErrorDetail)
				observedAt = r.Observation.Provenance.ObservedAt
			}
		case networkdns.CheckDNSSEC:
			if r.DNSSEC != nil {
				dnssecDomain = nullableString(r.DNSSEC.Domain)
				ds := string(r.DNSSEC.State)
				dnssecState = &ds
				dnssecReason = nullableString(r.DNSSEC.Reason)
				observedAt = r.DNSSEC.Provenance.ObservedAt
			}
		}
		if observedAt.IsZero() {
			observedAt = time.Now()
		}

		_, err := tx.Exec(ctx,
			`INSERT INTO dns_security_check_results
			 (run_id, check_type, target_host, target_port, path_state, error_detail, dnssec_domain, dnssec_state, dnssec_reason, observed_at)
			 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
			runID, string(r.CheckType), host, port, pathState, errDetail, dnssecDomain, dnssecState, dnssecReason, observedAt)
		if err != nil {
			return fmt.Errorf("dns_security_check_results: insert for run %s: %w", runID, err)
		}
	}
	return tx.Commit(ctx)
}

func ListDNSSecurityCheckResultsByRun(ctx context.Context, pool *pgxpool.Pool, runID string) ([]networkdns.DNSCheckResult, error) {
	rows, err := pool.Query(ctx,
		`SELECT check_type, target_host, target_port, path_state, error_detail, dnssec_domain, dnssec_state, dnssec_reason, observed_at
		 FROM dns_security_check_results WHERE run_id = $1 ORDER BY observed_at ASC`, runID)
	if err != nil {
		return nil, fmt.Errorf("dns_security_check_results: list for run %s: %w", runID, err)
	}
	defer rows.Close()
	var out []networkdns.DNSCheckResult
	for rows.Next() {
		var checkType string
		var host, pathState, errDetail, dnssecDomain, dnssecState, dnssecReason *string
		var port *int
		var observedAt time.Time
		if err := rows.Scan(&checkType, &host, &port, &pathState, &errDetail, &dnssecDomain, &dnssecState, &dnssecReason, &observedAt); err != nil {
			return nil, fmt.Errorf("dns_security_check_results: scan for run %s: %w", runID, err)
		}
		r := networkdns.DNSCheckResult{CheckType: networkdns.CheckType(checkType)}
		switch r.CheckType {
		case networkdns.CheckOpenResolver:
			obs := networkgraph.NetworkObservation{Provenance: cloudgraph.Provenance{ObservedAt: observedAt}}
			if host != nil {
				obs.Target.Host = *host
			}
			if port != nil {
				obs.Target.Port = *port
			}
			if pathState != nil {
				obs.State = cloudgraph.PathState(*pathState)
			}
			if errDetail != nil {
				obs.ErrorDetail = *errDetail
			}
			r.Observation = &obs
		case networkdns.CheckDNSSEC:
			d := networkdns.DNSSECResult{Provenance: cloudgraph.Provenance{ObservedAt: observedAt}}
			if dnssecDomain != nil {
				d.Domain = *dnssecDomain
			}
			if dnssecState != nil {
				d.State = networkdns.DNSSECState(*dnssecState)
			}
			if dnssecReason != nil {
				d.Reason = *dnssecReason
			}
			r.DNSSEC = &d
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("dns_security_check_results: rows for run %s: %w", runID, err)
	}
	return out, nil
}
```

- [ ] **Step 4: Wire schema creation into the test pool and server startup**

Re-grep `orchestrator/internal/testutil/testdb.go` and `orchestrator/cmd/server/main.go` for the current exact text/line number of the last `EnsureNetworkControlExpectationSchema` call (Phase 4's fix pass may have shifted it) and add, immediately after each:

In `testdb.go`:
```go
	if err := db.EnsureDNSSecurityCheckSchema(ctx, pool); err != nil {
		pool.Close()
		_ = container.Terminate(context.Background())
		return nil, fmt.Errorf("testutil: EnsureDNSSecurityCheckSchema: %w", err)
	}
```

In `main.go`:
```go
	if err := db.EnsureDNSSecurityCheckSchema(context.Background(), adminPool); err != nil {
		log.Fatalf("[FATAL] DNS security check schema: %v", err)
	}
```

- [ ] **Step 5: Run tests to verify they pass**

Check memory headroom first: `Get-CimInstance Win32_OperatingSystem | Select-Object FreePhysicalMemory,TotalVisibleMemorySize` (PowerShell); if free memory is below ~1GB, check for stray Docker testcontainers / orphaned `*.test.exe` processes before proceeding (this happened twice already this session and was resolved safely both times).

Run: `cd orchestrator && go build ./... && go test ./internal/db/... -run 'TestInsertDNSSecurityCheckRun|TestGetDNSSecurityCheckRun' -v`
Expected: PASS — 2/2.

- [ ] **Step 6: Run the full `internal/db` suite to confirm no regression**

Run: `cd orchestrator && go test ./internal/db/... -v`
Expected: PASS — all tests, no regressions.

- [ ] **Step 7: Commit**

```bash
git add orchestrator/internal/db/networkdnscheck_store.go orchestrator/internal/db/networkdnscheck_store_test.go orchestrator/internal/testutil/testdb.go orchestrator/cmd/server/main.go
git commit -m "feat(networkdns): add schema and store layer for DNS security check runs"
```

---

### Task 6: HTTP API

**Files:**
- Create: `orchestrator/internal/api/networkdnscheck_handlers.go`
- Test: `orchestrator/internal/api/networkdnscheck_handlers_test.go`
- Modify: `orchestrator/internal/api/routes.go` (re-grep current line numbers for the last network-discovery GET/POST routes before editing)
- Modify: `orchestrator/internal/api/rbac_matrix_test.go` (same)

**Interfaces:**
- Consumes: `networkdns.RunChecks`/`DNSCheckRequest`/`DNSOpenResolverProbe`/`MaxChecksPerRun` (Tasks 1-4), `db.InsertDNSSecurityCheckRun`/`InsertDNSSecurityCheckResults`/`GetDNSSecurityCheckRun`/`ListDNSSecurityCheckRuns`/`ListDNSSecurityCheckResultsByRun`/`UpdateDNSSecurityCheckRunStatus` (Task 5), existing `h.networkVantagePoint`, `jsonError`/`respond`/`respondStatus`/`newID`/`auth.ClaimsFrom`/`h.auditLog` (unchanged), `auth.CanRunScenario` (existing permission, reused — same risk class as triggering a TCP discovery probe).
- Produces: `func (h *Handler) TriggerDNSSecurityCheckRun(w, r)`, `func (h *Handler) ListDNSSecurityCheckRuns(w, r)`, `func (h *Handler) GetDNSSecurityCheckRun(w, r)`, routes `POST /api/dns-security-checks`, `GET /api/dns-security-checks`, `GET /api/dns-security-checks/{id}`.

- [ ] **Step 1: Write the failing tests**

```go
// orchestrator/internal/api/networkdnscheck_handlers_test.go
package api

import (
	"bytes"
	"encoding/json"
	"net"
	"net/http"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/miekg/dns"

	"github.com/audspect/bas/internal/auth"
	"github.com/audspect/bas/internal/networkdns"
	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/ws"
)

// startTestDNSServer spins up a real local UDP DNS server bound to an
// ephemeral loopback port, always answering with rcode -- mirrors
// networkdiscovery_handlers_test.go's own real-local-listener pattern
// (an ephemeral net.Listen'd TCP port there; an ephemeral dns.Server
// here) rather than pointing at an arbitrary unreachable IP, which
// would make the test's timing depend on the test host's network
// stack instead of being fast and deterministic.
func startTestDNSServer(t *testing.T, rcode int) (host string, port int) {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	srv := &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		resp := new(dns.Msg)
		resp.SetReply(r)
		resp.Rcode = rcode
		_ = w.WriteMsg(resp)
	})}
	go srv.ActivateAndServe()
	t.Cleanup(func() { _ = srv.Shutdown() })
	addr := pc.LocalAddr().(*net.UDPAddr)
	return addr.IP.String(), addr.Port
}

func validDNSCheckBody(host string, port int) map[string]any {
	return map[string]any{
		"checks": []map[string]any{
			{"checkType": "open-resolver", "target": map[string]any{"host": host, "port": port}, "queryDomain": "example.test."},
		},
	}
}

func TestTriggerDNSSecurityCheckRun_ValidChecksPersist(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		vp := testVantagePoint()
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret).WithNetworkVantagePoint(vp)
		host, port := startTestDNSServer(t, dns.RcodeRefused)
		b, _ := json.Marshal(validDNSCheckBody(host, port))
		userID := seedUser(t, pool, "dns-op", "pw12345678", string(auth.RoleAnalyst), true)
		req := authedRequest(t, http.MethodPost, "/api/dns-security-checks", bytes.NewReader(b), auth.RoleAnalyst, userID)
		rec := callAuthed(h.TriggerDNSSecurityCheckRun, req)
		if rec.Code != http.StatusCreated {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}
		var resp struct {
			RunID string `json:"runId"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if resp.RunID == "" {
			t.Fatal("want non-empty runId")
		}
	})
}

func TestTriggerDNSSecurityCheckRun_EmptyChecksRejected(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		vp := testVantagePoint()
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret).WithNetworkVantagePoint(vp)
		body := map[string]any{"checks": []map[string]any{}}
		b, _ := json.Marshal(body)
		userID := seedUser(t, pool, "dns-op-empty", "pw12345678", string(auth.RoleAnalyst), true)
		req := authedRequest(t, http.MethodPost, "/api/dns-security-checks", bytes.NewReader(b), auth.RoleAnalyst, userID)
		rec := callAuthed(h.TriggerDNSSecurityCheckRun, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}
	})
}

func TestTriggerDNSSecurityCheckRun_UnconfiguredVantagePointReturns503(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret) // no vantage point configured
		// Rejected before any probe is attempted, so the target need not
		// resolve to anything real -- the 503 fires on the Configured()
		// check alone.
		b, _ := json.Marshal(validDNSCheckBody("10.0.1.5", 53))
		userID := seedUser(t, pool, "dns-op-novp", "pw12345678", string(auth.RoleAnalyst), true)
		req := authedRequest(t, http.MethodPost, "/api/dns-security-checks", bytes.NewReader(b), auth.RoleAnalyst, userID)
		rec := callAuthed(h.TriggerDNSSecurityCheckRun, req)
		if rec.Code != http.StatusServiceUnavailable {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}
	})
}

func TestListAndGetDNSSecurityCheckRun_RoundTrip(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		vp := testVantagePoint()
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret).WithNetworkVantagePoint(vp)
		host, port := startTestDNSServer(t, dns.RcodeRefused)
		b, _ := json.Marshal(validDNSCheckBody(host, port))
		userID := seedUser(t, pool, "dns-op-rt", "pw12345678", string(auth.RoleAnalyst), true)
		triggerReq := authedRequest(t, http.MethodPost, "/api/dns-security-checks", bytes.NewReader(b), auth.RoleAnalyst, userID)
		triggerRec := callAuthed(h.TriggerDNSSecurityCheckRun, triggerReq)
		if triggerRec.Code != http.StatusCreated {
			t.Fatalf("trigger status = %d, body = %s", triggerRec.Code, triggerRec.Body.String())
		}
		var created struct {
			RunID string `json:"runId"`
		}
		if err := json.Unmarshal(triggerRec.Body.Bytes(), &created); err != nil {
			t.Fatalf("decode trigger: %v", err)
		}

		listReq := authedRequest(t, http.MethodGet, "/api/dns-security-checks", nil, auth.RoleViewer, "")
		listRec := callAuthed(h.ListDNSSecurityCheckRuns, listReq)
		if listRec.Code != http.StatusOK {
			t.Fatalf("list status = %d, body = %s", listRec.Code, listRec.Body.String())
		}

		getReq := authedRequest(t, http.MethodGet, "/api/dns-security-checks/"+created.RunID, nil, auth.RoleViewer, "")
		getReq = withURLParam(getReq, "id", created.RunID)
		getRec := callAuthed(h.GetDNSSecurityCheckRun, getReq)
		if getRec.Code != http.StatusOK {
			t.Fatalf("get status = %d, body = %s", getRec.Code, getRec.Body.String())
		}
		var getResp struct {
			Results []networkdns.DNSCheckResult `json:"results"`
		}
		if err := json.Unmarshal(getRec.Body.Bytes(), &getResp); err != nil {
			t.Fatalf("decode get: %v", err)
		}
		if len(getResp.Results) != 1 {
			t.Fatalf("got %d results, want 1", len(getResp.Results))
		}
	})
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd orchestrator && go vet ./internal/api/...`
Expected: FAIL — `h.TriggerDNSSecurityCheckRun` etc. undefined.

- [ ] **Step 3: Implement the handlers**

```go
// orchestrator/internal/api/networkdnscheck_handlers.go
package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"

	"github.com/audspect/bas/internal/auth"
	"github.com/audspect/bas/internal/db"
	"github.com/audspect/bas/internal/networkdns"
)

const maxDNSSecurityCheckRequestBytes = 1 << 20

// TriggerDNSSecurityCheckRun -- POST /api/dns-security-checks.
func (h *Handler) TriggerDNSSecurityCheckRun(w http.ResponseWriter, r *http.Request) {
	if !h.networkVantagePoint.Configured() {
		jsonError(w, "network discovery vantage point not configured", http.StatusServiceUnavailable)
		return
	}

	var req struct {
		Checks []networkdns.DNSCheckRequest `json:"checks"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxDNSSecurityCheckRequestBytes)).Decode(&req); err != nil {
		jsonError(w, "invalid request body: "+err.Error(), http.StatusBadRequest)
		return
	}
	if len(req.Checks) == 0 {
		jsonError(w, "at least one check is required", http.StatusBadRequest)
		return
	}
	if len(req.Checks) > networkdns.MaxChecksPerRun {
		jsonError(w, fmt.Sprintf("too many checks — got %d, max %d", len(req.Checks), networkdns.MaxChecksPerRun), http.StatusBadRequest)
		return
	}
	for i, c := range req.Checks {
		if c.CheckType == networkdns.CheckOpenResolver && (c.Target.Host == "" || c.Target.Port < 1 || c.Target.Port > 65535) {
			jsonError(w, fmt.Sprintf("checks[%d]: a valid target host/port is required for an open-resolver check", i), http.StatusBadRequest)
			return
		}
		if c.QueryDomain == "" {
			jsonError(w, fmt.Sprintf("checks[%d]: queryDomain is required", i), http.StatusBadRequest)
			return
		}
	}

	var requestedBy string
	if c, ok := auth.ClaimsFrom(r.Context()); ok && c != nil {
		requestedBy = c.UserID
	}

	result, err := networkdns.RunChecks(r.Context(), networkdns.DNSOpenResolverProbe{}, h.networkVantagePoint, req.Checks)
	if err != nil {
		jsonError(w, err.Error(), http.StatusBadRequest)
		return
	}

	run := &db.DNSSecurityCheckRun{
		ID:             newID(),
		VantagePointID: h.networkVantagePoint.ID,
		RequestedBy:    requestedBy,
		CheckCount:     len(req.Checks),
		Status:         string(result.Status),
	}
	if err := db.InsertDNSSecurityCheckRun(r.Context(), h.db, run); err != nil {
		h.auditLog(r, "networkdns.run", "", map[string]any{"checkCount": len(req.Checks), "error": err.Error()}, "error")
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if err := db.InsertDNSSecurityCheckResults(r.Context(), h.db, run.ID, result.Results); err != nil {
		_ = db.UpdateDNSSecurityCheckRunStatus(r.Context(), h.db, run.ID, "failed")
		h.auditLog(r, "networkdns.run", run.ID, map[string]any{"checkCount": len(req.Checks), "error": err.Error()}, "error")
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	h.auditLog(r, "networkdns.run", run.ID, map[string]any{"checkCount": len(req.Checks), "status": string(result.Status)}, "ok")
	respondStatus(w, map[string]any{"runId": run.ID, "status": result.Status}, http.StatusCreated)
}

// ListDNSSecurityCheckRuns -- GET /api/dns-security-checks.
func (h *Handler) ListDNSSecurityCheckRuns(w http.ResponseWriter, r *http.Request) {
	limit := 20
	if l, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && l > 0 && l <= 100 {
		limit = l
	}
	runs, err := db.ListDNSSecurityCheckRuns(r.Context(), h.db, limit)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if runs == nil {
		runs = []*db.DNSSecurityCheckRun{}
	}
	respond(w, runs)
}

// GetDNSSecurityCheckRun -- GET /api/dns-security-checks/{id}.
func (h *Handler) GetDNSSecurityCheckRun(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	run, err := db.GetDNSSecurityCheckRun(r.Context(), h.db, id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			jsonError(w, "dns security check run not found", http.StatusNotFound)
			return
		}
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	results, err := db.ListDNSSecurityCheckResultsByRun(r.Context(), h.db, id)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if results == nil {
		results = []networkdns.DNSCheckResult{}
	}
	respond(w, map[string]any{"run": run, "results": results})
}
```

- [ ] **Step 4: Wire routes and RBAC matrix rows**

Re-grep `orchestrator/internal/api/routes.go` and `orchestrator/internal/api/rbac_matrix_test.go` for the current exact text of the network-discovery-runs GET/POST lines before editing. Add, after the existing `network-discovery-runs` GET lines in `routes.go`:
```go
		r.Get("/api/dns-security-checks", h.ListDNSSecurityCheckRuns)
		r.Get("/api/dns-security-checks/{id}", h.GetDNSSecurityCheckRun)
```
After the `network-discovery-runs` POST line (gated by `auth.CanRunScenario`):
```go
		r.With(auth.RequirePermission(auth.CanRunScenario)).Post("/api/dns-security-checks", h.TriggerDNSSecurityCheckRun)
```

In `rbac_matrix_test.go`, add the matching GET rows (`tierAny`) and POST row (`tierPermission, auth.CanRunScenario`) at the corresponding anchors.

- [ ] **Step 5: Run tests to verify they pass**

Check memory headroom first (same check as Task 5).

Run: `cd orchestrator && go build ./... && go test ./internal/api/... -run 'TestTriggerDNSSecurityCheckRun|TestListAndGetDNSSecurityCheckRun|TestRBACMatrix_NoDrift' -v`
Expected: PASS — 5/5.

- [ ] **Step 6: Run the full network+RBAC regression set**

Run: `cd orchestrator && go vet ./... && go test ./internal/api/... -run 'Network|RBACMatrix' -v`
Expected: PASS — all tests, no regressions.

- [ ] **Step 7: Commit**

```bash
git add orchestrator/internal/api/networkdnscheck_handlers.go orchestrator/internal/api/networkdnscheck_handlers_test.go orchestrator/internal/api/routes.go orchestrator/internal/api/rbac_matrix_test.go
git commit -m "feat(networkdns): add DNS security check HTTP API"
```

---

## Execution Handoff

This plan uses **Native/inline execution** (pre-selected — standing convention for this session, same as every prior Network BAS Mastery phase this session): implement every task directly in this session, then one fresh reviewer on the most capable model checks the whole branch at the end.

**REQUIRED SUB-SKILL:** Use superpowers:executing-plans.
