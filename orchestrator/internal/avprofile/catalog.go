package avprofile

import (
	"fmt"

	"github.com/audspect/bas/internal/avcatalog"
)

// AudspectAVProfileCatalog returns Audspect's real, current seed
// industry-and-regional-profile set (av.txt §3's industry table), each
// validated against the real, live avcatalog output. Government/large
// enterprises and MSPs, also named in av.txt's table, are deliberately
// not mapped in this seed pass: no current catalog vector cleanly
// represents their distinguishing concern (centralized multi-tenant
// policy/auditability architecture, not a technique), and av.txt itself
// says to "map each requirement to an actual control assertion and
// evidence artifact" rather than force a weak mapping.
func AudspectAVProfileCatalog() ([]Profile, error) {
	realCatalog, err := avcatalog.AudspectAVAttackCatalog()
	if err != nil {
		return nil, fmt.Errorf("loading seed profile catalog: %w", err)
	}

	rbiBanks, err := NewComplianceReference("RBI Cyber Security Framework for banks", Unverified,
		"framework name and general existence only, drawn from secondary/vendor sources; no specific circular number or clause verified against RBI's own text", "")
	if err != nil {
		return nil, fmt.Errorf("loading seed profile catalog: %w", err)
	}
	bfsi, err := NewProfile("AVPROFILE-BFSI", "Banking, Financial Services and Insurance", ProfileIndustry,
		[]string{"AV-FILE-001", "AV-CREDACCESS-001", "AV-CONFIG-003", "AV-PERSIST-001"},
		[]ComplianceReference{rbiBanks},
		"BFSI payment workstations and privileged administrator endpoints concentrate on malware delivery, credential-access behavior, security-control tampering, and unauthorized persistence on privileged endpoints -- av.txt §3's own named BFSI priorities",
		"manually authored from av.txt §3's named BFSI item")
	if err != nil {
		return nil, fmt.Errorf("loading seed profile catalog: %w", err)
	}

	rbiNBFC, err := NewComplianceReference("RBI IT Governance requirements for NBFCs", Unverified,
		"framework name and general applicability (asset-threshold-gated) only, from secondary sources; no specific circular number verified against RBI's own text", "")
	if err != nil {
		return nil, fmt.Errorf("loading seed profile catalog: %w", err)
	}
	nbfc, err := NewProfile("AVPROFILE-NBFC", "Non-Banking Financial Companies and Fintech", ProfileIndustry,
		[]string{"AV-CONFIG-002", "AV-CREDACCESS-001", "AV-CONFIG-001"},
		[]ComplianceReference{rbiNBFC},
		"NBFC/fintech distributed and cloud-managed endpoints concentrate on degraded (cloud-lookup-unavailable) protection, identity/credential abuse, and exclusion-driven configuration drift -- av.txt §3's own named NBFC priorities",
		"manually authored from av.txt §3's named NBFC item")
	if err != nil {
		return nil, fmt.Errorf("loading seed profile catalog: %w", err)
	}

	certInManuf, err := NewComplianceReference("CERT-In Cyber Security Directions", Unverified,
		"framework name and the widely-reported 6-hour incident-reporting requirement only; no manufacturing-specific or AV-specific clause verified", "")
	if err != nil {
		return nil, fmt.Errorf("loading seed profile catalog: %w", err)
	}
	manufacturing, err := NewProfile("AVPROFILE-MANUFACTURING", "Manufacturing and Industrial", ProfileIndustry,
		[]string{"AV-FILE-001", "AV-SCRIPT-002", "AV-NET-001"},
		[]ComplianceReference{certInManuf},
		"manufacturing engineering workstations and jump hosts concentrate on removable-media-style file delivery, LOLBin abuse against legacy OS/engineering tooling, and network-delivered threats reaching isolated-network jump hosts -- av.txt §3's own named manufacturing priorities",
		"manually authored from av.txt §3's named manufacturing item")
	if err != nil {
		return nil, fmt.Errorf("loading seed profile catalog: %w", err)
	}

	dpdpHealth, err := NewComplianceReference("India DPDP Act 2023 (+ Rules)", Unverified,
		"framework name and general existence of technical-safeguard rules only; specific rule numbers not asserted here, pending primary-source confirmation", "")
	if err != nil {
		return nil, fmt.Errorf("loading seed profile catalog: %w", err)
	}
	healthcare, err := NewProfile("AVPROFILE-HEALTHCARE", "Healthcare", ProfileIndustry,
		[]string{"AV-FP-002", "AV-PERSIST-002", "AV-FILE-002"},
		[]ComplianceReference{dpdpHealth},
		"healthcare clinical workstations concentrate on operational-resilience/false-positive tolerance (critical-application compatibility), persistence precursors ahead of ransomware resilience, and malware delivery via nested-archive content -- av.txt §3's own named healthcare priorities",
		"manually authored from av.txt §3's named healthcare item")
	if err != nil {
		return nil, fmt.Errorf("loading seed profile catalog: %w", err)
	}

	dpdpIndia, err := NewComplianceReference("India DPDP Act 2023", Unverified,
		"nationwide applicability asserted at the framework-name level only", "")
	if err != nil {
		return nil, fmt.Errorf("loading seed profile catalog: %w", err)
	}
	certInIndia, err := NewComplianceReference("CERT-In Cyber Security Directions", Unverified,
		"nationwide incident-reporting framework, name-level only", "")
	if err != nil {
		return nil, fmt.Errorf("loading seed profile catalog: %w", err)
	}
	india, err := NewProfile("AVPROFILE-INDIA", "India (cross-industry baseline)", ProfileRegional,
		[]string{"AV-FILE-001", "AV-SCRIPT-001", "AV-CONFIG-003"},
		[]ComplianceReference{dpdpIndia, certInIndia},
		"a cross-industry baseline of the highest-severity, most-common vectors applicable regardless of sector for India-based deployments",
		"manually authored from av.txt §3's named India item")
	if err != nil {
		return nil, fmt.Errorf("loading seed profile catalog: %w", err)
	}

	uaeIAS, err := NewComplianceReference("UAE Information Assurance Standards (NESA-origin)", Unverified,
		"framework name only; sources disagree on the current overseeing authority's name, which is disclosed here rather than resolved by picking one", "")
	if err != nil {
		return nil, fmt.Errorf("loading seed profile catalog: %w", err)
	}
	uae, err := NewProfile("AVPROFILE-UAE", "United Arab Emirates (cross-industry baseline)", ProfileRegional,
		[]string{"AV-FILE-001", "AV-NET-001", "AV-CONFIG-002"},
		[]ComplianceReference{uaeIAS},
		"a cross-industry baseline of malware delivery, network-delivered threats, and degraded-protection resilience applicable regardless of sector for UAE-based deployments",
		"manually authored from av.txt §3's named UAE item")
	if err != nil {
		return nil, fmt.Errorf("loading seed profile catalog: %w", err)
	}

	profiles := []Profile{bfsi, nbfc, manufacturing, healthcare, india, uae}
	for _, p := range profiles {
		if err := ValidateAgainstCatalog(p, realCatalog); err != nil {
			return nil, fmt.Errorf("loading seed profile catalog: %w", err)
		}
	}
	return profiles, nil
}
