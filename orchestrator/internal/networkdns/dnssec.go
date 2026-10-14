package networkdns

import (
	"fmt"
	"slices"
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
		if sig, ok := rr.(*dns.RRSIG); ok {
			dnskeySig = sig
			continue
		}
		// Verify's rrset parameter must contain only the records the
		// signature covers -- never the RRSIG itself, or IsRRset's
		// type-consistency check rejects the mixed-type set outright.
		dnskeySet = append(dnskeySet, rr)
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

	aResp, err := query(domain, dns.TypeA)
	if err != nil {
		result.State = DNSSECUnknown
		result.Reason = fmt.Sprintf("A query failed: %v", err)
		return result
	}
	var aSig *dns.RRSIG
	var aSet []dns.RR
	for _, rr := range aResp.Answer {
		if sig, ok := rr.(*dns.RRSIG); ok {
			aSig = sig
			continue
		}
		aSet = append(aSet, rr)
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

// provenInsecureDelegation reports whether resp's authority section
// carries a signed NSEC or NSEC3 record that authenticates the absence
// of a DS record for domain, verified against key. A missing DS record
// with no such proof is never treated as evidence of anything.
func provenInsecureDelegation(domain string, resp *dns.Msg, key *dns.DNSKEY) bool {
	var proofSet []dns.RR
	var proofSig *dns.RRSIG
	provesAbsence := false
	for _, rr := range resp.Ns {
		if sig, ok := rr.(*dns.RRSIG); ok {
			proofSig = sig
			continue
		}
		// Verify's rrset parameter must contain only the records the
		// signature covers -- never the RRSIG itself (see dnskeySet's
		// own fix above for the same reason).
		proofSet = append(proofSet, rr)
		switch denial := rr.(type) {
		case *dns.NSEC:
			if denial.Hdr.Name != dns.Fqdn(domain) {
				continue
			}
			if slices.Contains(denial.TypeBitMap, dns.TypeDS) {
				return false // DS bit IS set -- this proves the opposite
			}
			provesAbsence = true
		case *dns.NSEC3:
			if !denial.Match(domain) && !denial.Cover(domain) {
				continue
			}
			if slices.Contains(denial.TypeBitMap, dns.TypeDS) {
				return false
			}
			provesAbsence = true
		}
	}
	// The signature is verified only once, after the whole authority
	// section has been scanned: the RRSIG covering a denial record
	// can appear anywhere in the section relative to that record, so
	// checking it mid-loop (tied to one specific record's own
	// iteration) would miss a signature that comes later in the slice.
	return provesAbsence && proofSig != nil && proofSig.Verify(key, proofSet) == nil
}

// defaultDNSResolverAddr is the production default resolver used only
// to fetch raw wire-format DNS records -- a var, not a const, so a
// deployment can override it. The specific resolver chosen does not
// matter for correctness: validateChain independently re-verifies
// every signature cryptographically from RootTrustAnchor down, never
// trusting the resolver's own answers or its AD flag. A well-known
// public resolver is used rather than "127.0.0.1:53" because nothing
// listens there on most hosts this orchestrator runs on, which would
// make every real validation silently fail with a connection error.
var defaultDNSResolverAddr = "1.1.1.1:53"

// ValidateDNSSEC validates domain's DNSSEC chain from the real root
// trust anchor. The only production caller of validateChain -- tests
// call validateChain directly with their own injected anchor and query
// function.
func ValidateDNSSEC(domain string) DNSSECResult {
	client := &dns.Client{Timeout: DefaultCheckTimeout}
	query := func(d string, qtype uint16) (*dns.Msg, error) {
		m := new(dns.Msg)
		m.SetQuestion(dns.Fqdn(d), qtype)
		m.SetEdns0(4096, true) // DO bit -- request DNSSEC records
		resp, _, err := client.Exchange(m, defaultDNSResolverAddr)
		return resp, err
	}
	return validateChain(domain, RootTrustAnchor, query)
}
