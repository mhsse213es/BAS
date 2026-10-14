package networkdns

import (
	"context"
	"fmt"
	"slices"
	"strings"
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

// validateChain walks domain's DNSSEC chain of trust one zone cut at a
// time, starting from anchor: first verifying anchor.Zone's own DNSKEY
// against anchor.DS, then -- for each intermediate zone between
// anchor.Zone and domain -- fetching that zone's DS (published and
// signed by the zone above it) and DNSKEY (self-signed, matching that
// DS), carrying the newly verified key forward as the trust for the
// next hop. Only once the walk reaches domain itself is the actual A
// record fetched and verified against domain's own verified key.
//
// anchor.Zone == domain (the common case in this package's own unit
// tests, and always true for a query against a single already-trusted
// zone) walks zero intermediate hops: the anchor's own key, once
// verified, is used directly for the final A-record check.
func validateChain(domain string, anchor TrustAnchor, query dnsQueryFunc) DNSSECResult {
	now := time.Now()
	result := DNSSECResult{Domain: domain, Provenance: cloudgraph.Provenance{ObservedAt: now, Source: "networkdns"}}

	key, failState, failReason := verifyZoneKey(anchor.Zone, []*dns.DS{anchor.DS}, query)
	if failState != "" {
		result.State = failState
		result.Reason = failReason
		return result
	}

	for _, zone := range zonesBetween(anchor.Zone, domain) {
		dsResp, err := query(zone, dns.TypeDS)
		if err != nil {
			result.State = DNSSECUnknown
			result.Reason = fmt.Sprintf("DS query for %s failed: %v", zone, err)
			return result
		}
		var dsSig *dns.RRSIG
		var dsSet []dns.RR
		var dsCandidates []*dns.DS
		for _, rr := range dsResp.Answer {
			if sig, ok := rr.(*dns.RRSIG); ok {
				dsSig = sig
				continue
			}
			dsSet = append(dsSet, rr)
			if ds, ok := rr.(*dns.DS); ok {
				dsCandidates = append(dsCandidates, ds)
			}
		}
		if len(dsSet) == 0 {
			if provenInsecureDelegation(zone, dsResp, key) {
				result.State = DNSSECInsecure
				result.Reason = fmt.Sprintf("a signed NSEC/NSEC3 record proves no DS record exists for %s (legitimately unsigned)", zone)
				return result
			}
			result.State = DNSSECUnknown
			result.Reason = fmt.Sprintf("no DS record and no authenticated denial-of-existence proof for %s -- insufficient evidence", zone)
			return result
		}
		if dsSig == nil {
			result.State = DNSSECInvalid
			result.Reason = fmt.Sprintf("DS RRset for %s has no RRSIG to verify", zone)
			return result
		}
		if err := dsSig.Verify(key, dsSet); err != nil {
			result.State = DNSSECInvalid
			result.Reason = fmt.Sprintf("DS RRset signature for %s does not verify: %v", zone, err)
			return result
		}

		key, failState, failReason = verifyZoneKey(zone, dsCandidates, query)
		if failState != "" {
			result.State = failState
			result.Reason = failReason
			return result
		}
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
	if err := aSig.Verify(key, aSet); err != nil {
		result.State = DNSSECInvalid
		result.Reason = fmt.Sprintf("answer RRset signature does not verify: %v", err)
		return result
	}

	result.State = DNSSECSecure
	return result
}

// verifyZoneKey queries zone's own DNSKEY RRset, verifies it is validly
// self-signed, and confirms one of its keys matches one of dsCandidates
// -- the DS record(s) already established as trusted for zone (either
// the chain's starting TrustAnchor, or a DS just fetched from zone's
// parent and verified in the previous hop). Returns the matched,
// verified key on success, or a failure state/reason to surface
// directly from the caller.
func verifyZoneKey(zone string, dsCandidates []*dns.DS, query dnsQueryFunc) (key *dns.DNSKEY, failState DNSSECState, failReason string) {
	dnskeyResp, err := query(zone, dns.TypeDNSKEY)
	if err != nil {
		return nil, DNSSECUnknown, fmt.Sprintf("DNSKEY query for %s failed: %v", zone, err)
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
		dnskey, ok := rr.(*dns.DNSKEY)
		if !ok {
			continue
		}
		for _, ds := range dsCandidates {
			computed := dnskey.ToDS(ds.DigestType)
			// hex.EncodeToString (used internally by ToDS) always
			// produces lowercase hex; a hand-written trust-anchor
			// literal may not be -- the comparison must not silently
			// fail over casing alone.
			if computed != nil && strings.EqualFold(computed.Digest, ds.Digest) && computed.KeyTag == ds.KeyTag {
				matchedKey = dnskey
				break
			}
		}
		if matchedKey != nil {
			break
		}
	}
	if matchedKey == nil {
		return nil, DNSSECInvalid, fmt.Sprintf("no DNSKEY for %s matches the trust anchor's DS record", zone)
	}
	if dnskeySig == nil {
		return nil, DNSSECInvalid, fmt.Sprintf("DNSKEY RRset for %s has no RRSIG to verify", zone)
	}
	if err := dnskeySig.Verify(matchedKey, dnskeySet); err != nil {
		return nil, DNSSECInvalid, fmt.Sprintf("DNSKEY RRset signature for %s does not verify: %v", zone, err)
	}
	return matchedKey, "", ""
}

// zonesBetween returns the ordered zone names strictly below from and
// up to and including to, root-to-leaf (e.g. from="." to="www.a.com."
// returns ["com.", "a.com.", "www.a.com."]). from == to returns nil --
// zero intermediate hops.
func zonesBetween(from, to string) []string {
	fromLabels := dns.SplitDomainName(dns.Fqdn(from))
	toLabels := dns.SplitDomainName(dns.Fqdn(to))
	var zones []string
	for i := len(toLabels) - len(fromLabels) - 1; i >= 0; i-- {
		zones = append(zones, dns.Fqdn(strings.Join(toLabels[i:], ".")))
	}
	return zones
}

// denialGroup collects the records and RRSIG for exactly one (owner
// name, type) rrset within an authority section -- a real response
// commonly carries more than one NSEC/NSEC3 record (e.g. the actual
// proof plus an unrelated closest-encloser record), each at its own
// owner name with its own signature. RRSIG.Verify's IsRRset check
// requires every record in the set it verifies to share one owner name
// and type, so records from different groups must never be mixed.
type denialGroup struct {
	records []dns.RR
	sig     *dns.RRSIG
}

// provenInsecureDelegation reports whether resp's authority section
// carries a signed NSEC or NSEC3 record that authenticates the absence
// of a DS record for domain, verified against key. A missing DS record
// with no such proof is never treated as evidence of anything.
func provenInsecureDelegation(domain string, resp *dns.Msg, key *dns.DNSKEY) bool {
	groups := map[string]*denialGroup{}
	groupFor := func(name string, rrtype uint16) *denialGroup {
		k := fmt.Sprintf("%s|%d", dns.Fqdn(name), rrtype)
		g := groups[k]
		if g == nil {
			g = &denialGroup{}
			groups[k] = g
		}
		return g
	}
	for _, rr := range resp.Ns {
		if sig, ok := rr.(*dns.RRSIG); ok {
			groupFor(sig.Hdr.Name, sig.TypeCovered).sig = sig
			continue
		}
		groupFor(rr.Header().Name, rr.Header().Rrtype).records = append(groupFor(rr.Header().Name, rr.Header().Rrtype).records, rr)
	}

	for _, g := range groups {
		if len(g.records) == 0 || g.sig == nil {
			continue
		}
		provesAbsence := false
		switch denial := g.records[0].(type) {
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
		default:
			continue
		}
		// Each group's signature is verified only against that same
		// group's own records -- never a flat set spanning every
		// record in the authority section.
		if provesAbsence && g.sig.Verify(key, g.records) == nil {
			return true
		}
	}
	return false
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
// function. ctx bounds every DNS exchange the walk performs: a chain
// with several hops issues several sequential queries, and RunChecks's
// MaxRunDuration deadline must be able to cut this short mid-walk, not
// merely before it starts.
func ValidateDNSSEC(ctx context.Context, domain string) DNSSECResult {
	client := &dns.Client{Timeout: DefaultCheckTimeout}
	query := func(d string, qtype uint16) (*dns.Msg, error) {
		m := new(dns.Msg)
		m.SetQuestion(dns.Fqdn(d), qtype)
		m.SetEdns0(4096, true) // DO bit -- request DNSSEC records
		resp, _, err := client.ExchangeContext(ctx, m, defaultDNSResolverAddr)
		return resp, err
	}
	return validateChain(domain, RootTrustAnchor, query)
}
