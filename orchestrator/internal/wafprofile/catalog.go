package wafprofile

import (
	"fmt"

	"github.com/audspect/bas/internal/wafcatalog"
)

// AudspectWAFProfileCatalog returns Audspect's real, current seed
// industry-and-regional-profile set: all 6 industries plus both regions
// named in waf.txt §4's own table (BFSI, NBFC, Manufacturing, Healthcare,
// Retail and e-commerce, Government and critical infrastructure, India,
// UAE), each validated against the real, live wafcatalog output. Retail
// and Government were added later than the other 6 -- found missing
// during a QA-log pass that re-read waf.txt §4 directly against this
// package's own shipped output (see docs/waf-mastery-qa-log.md item #2).
func AudspectWAFProfileCatalog() ([]Profile, error) {
	realCatalog, err := wafcatalog.AudspectWAFAttackCatalog()
	if err != nil {
		return nil, fmt.Errorf("loading seed profile catalog: %w", err)
	}

	rbiBanks, err := NewComplianceReference("RBI Cyber Security Framework for banks", Unverified,
		"framework name and general existence only, drawn from secondary/vendor sources in this session's research; no specific circular number or clause verified against RBI's own text", "")
	if err != nil {
		return nil, fmt.Errorf("loading seed profile catalog: %w", err)
	}
	pciDSS, err := NewComplianceReference("PCI-DSS", Unverified,
		"framework name only; payment-card-data scope not independently verified in this session", "")
	if err != nil {
		return nil, fmt.Errorf("loading seed profile catalog: %w", err)
	}
	bfsi, err := NewProfile("WAFPROFILE-BFSI", "Banking, Financial Services and Insurance", ProfileIndustry,
		[]string{"SQLI-001", "AUTH-001", "AUTH-003", "API-001", "RATE-001"},
		[]ComplianceReference{rbiBanks, pciDSS},
		"BFSI internet-facing apps concentrate on authenticated payment/account flows and APIs, where SQL injection, auth-bypass/credential and broken-object-level-authorization patterns, and burst-rate abuse are the highest-severity vectors already in wafcatalog",
		"manually authored from waf.txt Phase 9's named BFSI item")
	if err != nil {
		return nil, fmt.Errorf("loading seed profile catalog: %w", err)
	}

	rbiNBFC, err := NewComplianceReference("RBI IT Governance requirements for NBFCs", Unverified,
		"framework name and general applicability (asset-threshold-gated) only, from secondary sources; no specific circular number verified against RBI's own text", "")
	if err != nil {
		return nil, fmt.Errorf("loading seed profile catalog: %w", err)
	}
	nbfc, err := NewProfile("WAFPROFILE-NBFC", "Non-Banking Financial Companies", ProfileIndustry,
		[]string{"API-002", "AUTH-001", "SQLI-002", "FILEUP-001"},
		[]ComplianceReference{rbiNBFC},
		"many NBFCs run digital-lending apps with undocumented-field mass-assignment risk, credential-stuffing-exposed logins, blind SQL injection in form flows, and loan-document upload endpoints",
		"manually authored from waf.txt Phase 9's named NBFC item")
	if err != nil {
		return nil, fmt.Errorf("loading seed profile catalog: %w", err)
	}

	certIn, err := NewComplianceReference("CERT-In Cyber Security Directions", Unverified,
		"framework name and the widely-reported 6-hour incident-reporting requirement only; this session's research found no manufacturing-specific or WAF-specific clause, and that gap is disclosed rather than filled in", "")
	if err != nil {
		return nil, fmt.Errorf("loading seed profile catalog: %w", err)
	}
	manufacturing, err := NewProfile("WAFPROFILE-MANUFACTURING", "Manufacturing and OT-adjacent critical infrastructure", ProfileIndustry,
		[]string{"SSRF-002", "PATHTRAV-001", "HTTPPARSE-001"},
		[]ComplianceReference{certIn},
		"manufacturing/OT-adjacent management interfaces are exposed to cloud-metadata SSRF, directory traversal, and request-smuggling against legacy HTTP parsers",
		"manually authored from waf.txt Phase 9's named manufacturing item")
	if err != nil {
		return nil, fmt.Errorf("loading seed profile catalog: %w", err)
	}

	dpdpHealth, err := NewComplianceReference("India DPDP Act 2023 (+ Rules)", Unverified,
		"framework name and general existence of technical-safeguard rules only; specific rule numbers and retention periods surfaced by research are not asserted here, pending primary-source confirmation", "")
	if err != nil {
		return nil, fmt.Errorf("loading seed profile catalog: %w", err)
	}
	abdm, err := NewComplianceReference("Ayushman Bharat Digital Mission (ABDM)", Unverified,
		"framework name only; specific technical-specification clauses not verified", "")
	if err != nil {
		return nil, fmt.Errorf("loading seed profile catalog: %w", err)
	}
	healthcare, err := NewProfile("WAFPROFILE-HEALTHCARE", "Healthcare", ProfileIndustry,
		[]string{"AUTH-002", "API-003", "CACHE-001", "SQLI-003"},
		[]ComplianceReference{dpdpHealth, abdm},
		"healthcare apps expose patient-record account enumeration, verbose API data exposure, cache-poisoning leakage of cached PHI responses, and error-based SQL injection against record-ID parameters",
		"manually authored from waf.txt Phase 9's named healthcare item")
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
	india, err := NewProfile("WAFPROFILE-INDIA", "India (cross-industry baseline)", ProfileRegional,
		[]string{"SQLI-001", "XSS-001", "AUTH-001", "RATE-002"},
		[]ComplianceReference{dpdpIndia, certInIndia},
		"a cross-industry baseline of the highest-severity, most-common vectors applicable regardless of sector for India-based deployments",
		"manually authored from waf.txt Phase 9's named India item")
	if err != nil {
		return nil, fmt.Errorf("loading seed profile catalog: %w", err)
	}

	uaeIAS, err := NewComplianceReference("UAE Information Assurance Standards (NESA-origin)", Unverified,
		"framework name only; this session's research found disagreement across sources on the current overseeing authority's name, which is disclosed here rather than resolved by picking one", "")
	if err != nil {
		return nil, fmt.Errorf("loading seed profile catalog: %w", err)
	}
	uae, err := NewProfile("WAFPROFILE-UAE", "United Arab Emirates (cross-industry baseline)", ProfileRegional,
		[]string{"SQLI-002", "XSS-002", "SSRF-001", "API-002"},
		[]ComplianceReference{uaeIAS},
		"a cross-industry baseline of blind SQL injection, stored XSS, webhook-callback SSRF, and mass-assignment API abuse applicable regardless of sector for UAE-based deployments",
		"manually authored from waf.txt Phase 9's named UAE item")
	if err != nil {
		return nil, fmt.Errorf("loading seed profile catalog: %w", err)
	}

	pciDSSRetail, err := NewComplianceReference("PCI-DSS", Unverified,
		"framework name only; payment-card-data scope not independently verified in this session -- same disclosure as BFSI's own PCI-DSS reference, cited separately here since retail checkout flows carry the same card-data handling obligation independent of any banking-sector framework", "")
	if err != nil {
		return nil, fmt.Errorf("loading seed profile catalog: %w", err)
	}
	retail, err := NewProfile("WAFPROFILE-RETAIL", "Retail and e-commerce", ProfileIndustry,
		[]string{"API-001", "API-003", "AUTH-001", "RATE-001"},
		[]ComplianceReference{pciDSSRetail},
		"retail/e-commerce checkout and order flows concentrate on broken-object-level-authorization against orders endpoints, excessive data exposure on inventory/product APIs, credential-stuffing account abuse, and rate-limit-evading scraping/bot bursts against public pricing endpoints",
		"manually authored from waf.txt §4's named Retail and e-commerce item")
	if err != nil {
		return nil, fmt.Errorf("loading seed profile catalog: %w", err)
	}

	nistCSFGov, err := NewComplianceReference("NIST Cybersecurity Framework", Unverified,
		"framework name only, cited as a general-purpose critical-infrastructure reference since waf.txt names no specific national framework for this row (unlike BFSI/NBFC's RBI references or the India/UAE regional profiles); no specific subcategory or control verified against NIST's own text, and no sector- or jurisdiction-specific government framework (e.g. FedRAMP, India's own e-governance standards) is asserted here", "")
	if err != nil {
		return nil, fmt.Errorf("loading seed profile catalog: %w", err)
	}
	government, err := NewProfile("WAFPROFILE-GOVERNMENT", "Government and critical infrastructure", ProfileIndustry,
		[]string{"PATHTRAV-001", "SSRF-002", "SQLI-001", "POLICY-002"},
		[]ComplianceReference{nistCSFGov},
		"public service portals expose directory traversal on file-download endpoints, cloud-metadata SSRF against infrastructure hosted on public cloud, UNION-based SQL injection risking sensitive-data exposure, and policy misconfiguration via overly broad legacy-compatibility exceptions on aging systems -- waf.txt's own named \"logging\" priority for this sector has no corresponding wafcatalog vector and is deliberately not forced into this profile's attack-vector set; it belongs to internal/wafdetection's evidence-pipeline validation instead",
		"manually authored from waf.txt §4's named Government and critical infrastructure item")
	if err != nil {
		return nil, fmt.Errorf("loading seed profile catalog: %w", err)
	}

	profiles := []Profile{bfsi, nbfc, manufacturing, healthcare, retail, government, india, uae}
	for _, p := range profiles {
		if err := ValidateAgainstCatalog(p, realCatalog); err != nil {
			return nil, fmt.Errorf("loading seed profile catalog: %w", err)
		}
	}
	return profiles, nil
}
