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
