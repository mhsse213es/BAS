package networkdns

import (
	"context"
	"crypto"
	"errors"
	"net"
	"strings"
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

func TestValidateChain_ValidSignature_Secure(t *testing.T) {
	ksk, _, dnskeySet, aRecordSet := signedTestChain(t, "example-test.")
	anchor := TrustAnchor{Zone: "example-test.", DS: ksk.ToDS(dns.SHA256)}
	query := func(domain string, qtype uint16) (*dns.Msg, error) {
		resp := new(dns.Msg)
		switch qtype {
		case dns.TypeDNSKEY:
			resp.Answer = dnskeySet
		case dns.TypeDS:
			resp.Answer = []dns.RR{anchor.DS} // a non-empty DS answer -- this task's own delegation-insecurity path is covered separately
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
		case dns.TypeDS:
			resp.Answer = []dns.RR{anchor.DS} // a non-empty DS answer -- this task's own delegation-insecurity path is covered separately
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

var errTestQueryFailed = errors.New("simulated query failure")

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

// TestValidateChain_TwoHopRealChain_Secure proves validateChain actually
// walks the delegation from anchor.Zone down through an intermediate
// zone cut to domain -- not merely checking domain's own DNSKEY against
// anchor.DS directly, which is cryptographically meaningless once
// domain and anchor.Zone are different zones with different keys. The
// query stub below deliberately returns DIFFERENT DNSKEY data per zone
// name queried (unlike the single-hop tests above, whose domain-
// agnostic stubs cannot catch this class of bug), so this test can only
// pass if validateChain queries and verifies each hop's own key.
func TestValidateChain_TwoHopRealChain_Secure(t *testing.T) {
	parentKsk, parentPriv, parentDNSKEYSet, _ := signedTestChain(t, "parent-chain-test.")
	childKsk, _, childDNSKEYSet, childASet := signedTestChain(t, "child.parent-chain-test.")

	// The DS record for the child, as published and signed by the
	// PARENT zone -- the cryptographic link between the two hops.
	childDS := childKsk.ToDS(dns.SHA256)
	childDS.Hdr = dns.RR_Header{Name: dns.Fqdn("child.parent-chain-test."), Rrtype: dns.TypeDS, Class: dns.ClassINET, Ttl: 300}
	dsSig := signRRSet(t, parentKsk, parentPriv, []dns.RR{childDS})
	dsSet := []dns.RR{childDS, dsSig}

	anchor := TrustAnchor{Zone: "parent-chain-test.", DS: parentKsk.ToDS(dns.SHA256)}
	query := func(domain string, qtype uint16) (*dns.Msg, error) {
		resp := new(dns.Msg)
		switch {
		case domain == "parent-chain-test." && qtype == dns.TypeDNSKEY:
			resp.Answer = parentDNSKEYSet
		case domain == "child.parent-chain-test." && qtype == dns.TypeDS:
			resp.Answer = dsSet
		case domain == "child.parent-chain-test." && qtype == dns.TypeDNSKEY:
			resp.Answer = childDNSKEYSet
		case domain == "child.parent-chain-test." && qtype == dns.TypeA:
			resp.Answer = childASet
		}
		return resp, nil
	}
	result := validateChain("child.parent-chain-test.", anchor, query)
	if result.State != DNSSECSecure {
		t.Fatalf("State = %q, want secure -- a genuine two-hop chain with correctly linked keys must validate, Reason: %s", result.State, result.Reason)
	}
}

// TestValidateChain_TwoHopTamperedDS_Invalid proves the walk actually
// cryptographically links each hop to the next: the child's own
// DNSKEY/A records are validly self-signed, but the DS published by
// the parent describes a DIFFERENT key than the child actually uses --
// exactly what an attacker who controls the child zone but not the
// parent's delegation would present. This must be caught, not treated
// as secure just because each zone's own signatures check out in
// isolation.
func TestValidateChain_TwoHopTamperedDS_Invalid(t *testing.T) {
	parentKsk, parentPriv, parentDNSKEYSet, _ := signedTestChain(t, "parent-chain-test.")
	childKsk, _, childDNSKEYSet, childASet := signedTestChain(t, "child.parent-chain-test.")
	_ = childKsk

	// DS published by the parent does NOT match the child's real key --
	// built from an unrelated, never-published key pair.
	wrongKsk, _, _, _ := signedTestChain(t, "unrelated-test.")
	wrongDS := wrongKsk.ToDS(dns.SHA256)
	wrongDS.Hdr = dns.RR_Header{Name: dns.Fqdn("child.parent-chain-test."), Rrtype: dns.TypeDS, Class: dns.ClassINET, Ttl: 300}
	dsSig := signRRSet(t, parentKsk, parentPriv, []dns.RR{wrongDS})
	dsSet := []dns.RR{wrongDS, dsSig}

	anchor := TrustAnchor{Zone: "parent-chain-test.", DS: parentKsk.ToDS(dns.SHA256)}
	query := func(domain string, qtype uint16) (*dns.Msg, error) {
		resp := new(dns.Msg)
		switch {
		case domain == "parent-chain-test." && qtype == dns.TypeDNSKEY:
			resp.Answer = parentDNSKEYSet
		case domain == "child.parent-chain-test." && qtype == dns.TypeDS:
			resp.Answer = dsSet
		case domain == "child.parent-chain-test." && qtype == dns.TypeDNSKEY:
			resp.Answer = childDNSKEYSet
		case domain == "child.parent-chain-test." && qtype == dns.TypeA:
			resp.Answer = childASet
		}
		return resp, nil
	}
	result := validateChain("child.parent-chain-test.", anchor, query)
	if result.State != DNSSECInvalid {
		t.Fatalf("State = %q, want invalid -- the parent's DS does not match any key the child actually publishes, Reason: %s", result.State, result.Reason)
	}
}

// TestValidateChain_DigestCaseInsensitive_Secure pins the fix for a
// real bug: hex.EncodeToString (used internally by DNSKEY.ToDS) always
// produces lowercase hex, but a hand-written trust-anchor literal (like
// RootTrustAnchor's) may be uppercase. The digest comparison must not
// be a case-sensitive string match, or every hand-entered anchor whose
// casing doesn't happen to match the computed digest's casing silently
// fails -- exactly what shipped in RootTrustAnchor before this fix.
func TestValidateChain_DigestCaseInsensitive_Secure(t *testing.T) {
	ksk, _, dnskeySet, aRecordSet := signedTestChain(t, "example-test.")
	ds := ksk.ToDS(dns.SHA256)
	ds.Digest = strings.ToUpper(ds.Digest) // the computed digest is always lowercase; force a case mismatch
	anchor := TrustAnchor{Zone: "example-test.", DS: ds}
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
		t.Fatalf("State = %q, want secure -- digest comparison must be case-insensitive, Reason: %s", result.State, result.Reason)
	}
}

// TestValidateChain_SignedNSECProvesNoDS_MultipleDenialRecords_Insecure
// pins a real bug: a parent's authority section often carries more than
// one NSEC/NSEC3 record (e.g. the real proof plus an unrelated
// closest-encloser record), each with ITS OWN owner name and ITS OWN
// RRSIG. The two records here have different owner names on purpose --
// lumping them into one flat rrset and verifying with a single
// signature (as provenInsecureDelegation's original implementation
// did) fails RRSIG.Verify's IsRRset check outright (mixed owner
// names), so the real proof is never recognized. Each denial record
// must be grouped with its own signature and verified independently.
func TestValidateChain_SignedNSECProvesNoDS_MultipleDenialRecords_Insecure(t *testing.T) {
	ksk, priv, dnskeySet, _ := signedTestChain(t, "parent-test.")

	// An unrelated denial record at a different owner name -- noise
	// that a real closest-encloser proof would also include.
	unrelatedNSEC := &dns.NSEC{
		Hdr:        dns.RR_Header{Name: dns.Fqdn("aaa.parent-test."), Rrtype: dns.TypeNSEC, Class: dns.ClassINET, Ttl: 300},
		NextDomain: dns.Fqdn("bbb.parent-test."),
		TypeBitMap: []uint16{dns.TypeA, dns.TypeRRSIG, dns.TypeNSEC},
	}
	unrelatedSig := signRRSet(t, ksk, priv, []dns.RR{unrelatedNSEC})

	// The actual proof: no DS bit set at the exact queried name.
	nsec := &dns.NSEC{
		Hdr:        dns.RR_Header{Name: dns.Fqdn("child.parent-test."), Rrtype: dns.TypeNSEC, Class: dns.ClassINET, Ttl: 300},
		NextDomain: dns.Fqdn("zzz.parent-test."),
		TypeBitMap: []uint16{dns.TypeA, dns.TypeRRSIG, dns.TypeNSEC},
	}
	nsecSig := signRRSet(t, ksk, priv, []dns.RR{nsec})

	// Deliberately interleaved so a naive implementation can't rely on
	// ordering to accidentally group them correctly.
	authority := []dns.RR{unrelatedNSEC, nsec, unrelatedSig, nsecSig}

	anchor := TrustAnchor{Zone: "parent-test.", DS: ksk.ToDS(dns.SHA256)}
	query := func(domain string, qtype uint16) (*dns.Msg, error) {
		resp := new(dns.Msg)
		switch qtype {
		case dns.TypeDNSKEY:
			resp.Answer = dnskeySet
		case dns.TypeDS:
			resp.Ns = authority
		}
		return resp, nil
	}
	result := validateChain("child.parent-test.", anchor, query)
	if result.State != DNSSECInsecure {
		t.Fatalf("State = %q, want insecure -- the real proof must be recognized independently of the unrelated denial record alongside it, Reason: %s", result.State, result.Reason)
	}
}

// TestValidateDNSSEC_ContextCancelled_UnknownFast pins the fix for a
// real gap: ValidateDNSSEC must thread the caller's context into every
// DNS exchange, or RunChecks's MaxRunDuration deadline has no effect on
// an in-flight DNSSEC check. A real local listener that never responds
// stands in for a hung resolver; with a context cancelled before the
// call even starts, ValidateDNSSEC must return almost immediately --
// bounded by context cancellation, never by the full per-query timeout.
func TestValidateDNSSEC_ContextCancelled_UnknownFast(t *testing.T) {
	ln, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	defer ln.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 512)
		_, _, _ = ln.ReadFrom(buf) // read once, then never reply -- the hang this test targets
	}()

	originalAddr := defaultDNSResolverAddr
	defaultDNSResolverAddr = ln.LocalAddr().String()
	defer func() { defaultDNSResolverAddr = originalAddr }()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // already cancelled before ValidateDNSSEC is even called

	start := time.Now()
	result := ValidateDNSSEC(ctx, "example-test.")
	elapsed := time.Since(start)

	if result.State != DNSSECUnknown {
		t.Fatalf("State = %q, want unknown -- a cancelled context must never be read as a DNSSEC validation failure, Reason: %s", result.State, result.Reason)
	}
	if elapsed > time.Second {
		t.Fatalf("ValidateDNSSEC took %s to return after an already-cancelled context -- it is not threading ctx into the DNS exchange, only bounded by the full per-query timeout", elapsed)
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
