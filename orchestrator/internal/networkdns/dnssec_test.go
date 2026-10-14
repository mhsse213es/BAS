package networkdns

import (
	"crypto"
	"errors"
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
