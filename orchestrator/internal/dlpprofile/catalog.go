package dlpprofile

import "fmt"

// AudspectDLPProfileCatalog returns Audspect's real, current seed
// industry-and-regional-profile set (dlp.txt §4's "industry-specific
// mastery: India and UAE" item), each validated against RealDLPScenarioIDs
// -- the real, current set of DLP scenario IDs, since no dlpcatalog
// package exists (see the design spec's Non-goals).
//
// Industry grouping follows dlp.txt §4's own 5 headings exactly: BFSI and
// NBFCs combined, Healthcare, Manufacturing, Government/Legal/HR
// combined, and IT/SaaS/BPO/Telecom combined -- not AV's 6-way split,
// which doesn't match how this blueprint groups its industries.
//
// BFSI and the India regional baseline are the only two profiles whose
// real payload (fabricated PAN/Aadhaar/SWIFT/UPI/credit-card) matches
// what every scenario actually tests today, so they get a flat,
// ungapped VectorIDs-only shape. Every other profile -- Healthcare,
// Manufacturing, Government, IT/SaaS, and UAE -- gets the same
// channel-level VectorIDs (channel delivery mechanics are
// industry/region-agnostic) plus exactly one ControlObjectiveCoverage
// Gap recording that its sector/region-specific sensitive-data type was
// never actually exercised by any scenario payload. This asymmetry was
// found and resolved during this package's own builder-check review
// (2026-10-16): see the design spec for the full reasoning.
func AudspectDLPProfileCatalog() ([]Profile, error) {
	realScenarioIDs := RealDLPScenarioIDs()

	rbiSebiDpdp, err := NewComplianceReference("RBI Cyber Security Framework, SEBI framework (where relevant), and India's DPDP Act", Unverified,
		"framework names and general applicability only, drawn from secondary sources; no specific circular, clause, or rule number verified against any regulator's own text -- dlp.txt §4 names these three for BFSI/NBFCs", "")
	if err != nil {
		return nil, fmt.Errorf("loading seed profile catalog: %w", err)
	}
	bfsi, err := NewProfile("DLPPROFILE-BFSI", "Banking, Financial Services, Insurance and NBFCs", ProfileIndustry,
		[]string{"dlp-exfiltration-cloud-storage", "dlp-exfiltration-webhook", "dlp-exfiltration-sftp", "dlp-exfiltration-smtp"},
		[]ComplianceReference{rbiSebiDpdp},
		"BFSI/NBFC customer KYC, payment-card, and transaction data realistically leaves through cloud/collaboration uploads, webhook-style alerting integrations, SFTP transfers to outsourced BPOs/processors, and email -- dlp.txt §4's own named BFSI/NBFC channels. This is the one industry whose real scenario payload (fabricated PAN/Aadhaar/SWIFT/UPI/credit-card) actually matches the sensitive-data type it cares about, so no payload-fidelity gap applies here.",
		"manually authored from dlp.txt §4's named BFSI/NBFC item, scenario IDs selected from RealDLPScenarioIDs()")
	if err != nil {
		return nil, fmt.Errorf("loading seed profile catalog: %w", err)
	}

	healthData, err := NewComplianceReference("India health-data requirements and UAE federal/emirate/health-authority rules", Unverified,
		"framework names and general existence only; no specific rule or circular verified against any primary source -- dlp.txt §4 names both for Healthcare without a single canonical framework", "")
	if err != nil {
		return nil, fmt.Errorf("loading seed profile catalog: %w", err)
	}
	healthcareGap, err := NewControlObjectiveCoverage("patient/clinical record data-type fidelity", "",
		"no real scenario payload is shaped as a patient identifier, clinical record, lab report, or insurance claim -- every scenario today tests the same fabricated PAN/Aadhaar/SWIFT/UPI/credit-card record regardless of channel, so a healthcare deployment's actual sensitive-data type has never been exercised",
		"", CoverageStatusGap)
	if err != nil {
		return nil, fmt.Errorf("loading seed profile catalog: %w", err)
	}
	healthcare, err := NewProfile("DLPPROFILE-HEALTHCARE", "Healthcare, Hospitals and Insurance", ProfileIndustry,
		[]string{"dlp-exfiltration-cloud-storage", "dlp-exfiltration-smtp", "dlp-exfiltration-sftp"},
		[]ComplianceReference{healthData},
		"Healthcare patient exports, lab/imaging reports, and insurance claims realistically leave through cloud storage, email, and SFTP to diagnostic centers/billing vendors -- dlp.txt §4's own named Healthcare channels. Channel-level delivery mechanics are industry-agnostic so these scenarios genuinely apply, but the payload-fidelity gap below is recorded honestly rather than claiming full coverage.",
		"manually authored from dlp.txt §4's named Healthcare item, scenario IDs selected from RealDLPScenarioIDs()")
	if err != nil {
		return nil, fmt.Errorf("loading seed profile catalog: %w", err)
	}
	healthcare, err = WithControlObjectives(healthcare, []ControlObjectiveCoverage{healthcareGap})
	if err != nil {
		return nil, fmt.Errorf("loading seed profile catalog: %w", err)
	}

	certInManuf, err := NewComplianceReference("CERT-In Cyber Security Directions", Unverified,
		"framework name and the widely-reported 6-hour incident-reporting requirement only; no manufacturing-specific or DLP-specific clause verified", "")
	if err != nil {
		return nil, fmt.Errorf("loading seed profile catalog: %w", err)
	}
	manufacturingGap, err := NewControlObjectiveCoverage("CAD/engineering-design/source-code data-type fidelity", "",
		"no real scenario payload is shaped as a CAD drawing, BOM, engineering export, or proprietary source file -- the coderepo channel tests the same fabricated PAN/Aadhaar/SWIFT/UPI/credit-card record as every other channel, not CAD or source-code-shaped content, despite coderepo's own GitHub Gist/GitLab Snippet delivery mechanism being a realistic path for this data",
		"", CoverageStatusGap)
	if err != nil {
		return nil, fmt.Errorf("loading seed profile catalog: %w", err)
	}
	manufacturing, err := NewProfile("DLPPROFILE-MANUFACTURING", "Manufacturing, Engineering and Industrial", ProfileIndustry,
		[]string{"dlp-exfiltration-coderepo", "dlp-exfiltration-cloud-storage", "dlp-exfiltration-sftp"},
		[]ComplianceReference{certInManuf},
		"Manufacturing CAD drawings, engineering exports, and supplier designs realistically leave through developer/repository uploads, cloud storage, and SFTP to contractors/suppliers -- dlp.txt §4's own named Manufacturing channels.",
		"manually authored from dlp.txt §4's named Manufacturing item, scenario IDs selected from RealDLPScenarioIDs()")
	if err != nil {
		return nil, fmt.Errorf("loading seed profile catalog: %w", err)
	}
	manufacturing, err = WithControlObjectives(manufacturing, []ControlObjectiveCoverage{manufacturingGap})
	if err != nil {
		return nil, fmt.Errorf("loading seed profile catalog: %w", err)
	}

	govBaseline, err := NewComplianceReference("India DPDP Act 2023 (+ Rules) and UAE federal personal-data framework (cross-industry baseline)", Unverified,
		"dlp.txt §4 names no specific Government/Legal/HR framework beyond role-based/retention expectations, so this cites the same cross-industry DPDP/UAE baseline used for the regional profiles, disclosed as a best-effort substitute rather than a sector-specific citation", "")
	if err != nil {
		return nil, fmt.Errorf("loading seed profile catalog: %w", err)
	}
	governmentGap, err := NewControlObjectiveCoverage("citizen-record/case-file/legal-privilege data-type fidelity", "",
		"no real scenario payload is shaped as a government identity record, case file, or privileged legal document -- every scenario today tests the same fabricated PAN/Aadhaar/SWIFT/UPI/credit-card record regardless of channel",
		"", CoverageStatusGap)
	if err != nil {
		return nil, fmt.Errorf("loading seed profile catalog: %w", err)
	}
	government, err := NewProfile("DLPPROFILE-GOVERNMENT", "Government, Legal, Professional Services and HR", ProfileIndustry,
		[]string{"dlp-exfiltration-sftp", "dlp-exfiltration-smtp", "dlp-exfiltration-cloud-storage"},
		[]ComplianceReference{govBaseline},
		"Government case files, employee records, and client contracts realistically leave through SFTP to outsourced teams, email, and cloud storage -- dlp.txt §4's own named Government/Legal/HR channels.",
		"manually authored from dlp.txt §4's named Government/Legal/HR item, scenario IDs selected from RealDLPScenarioIDs()")
	if err != nil {
		return nil, fmt.Errorf("loading seed profile catalog: %w", err)
	}
	government, err = WithControlObjectives(government, []ControlObjectiveCoverage{governmentGap})
	if err != nil {
		return nil, fmt.Errorf("loading seed profile catalog: %w", err)
	}

	itSaasBaseline, err := NewComplianceReference("India DPDP Act 2023 (cross-industry baseline)", Unverified,
		"dlp.txt §4 names no IT/SaaS/BPO/telecom-specific framework beyond data-residency/shared-service expectations, so this cites the same cross-industry DPDP baseline used for the India regional profile, disclosed as a best-effort substitute rather than a sector-specific citation", "")
	if err != nil {
		return nil, fmt.Errorf("loading seed profile catalog: %w", err)
	}
	itSaasGap, err := NewControlObjectiveCoverage("source-code/API-credential data-type fidelity", "",
		"the coderepo and webhook channels exercise a realistic developer-tooling delivery mechanism (GitHub Gist/GitLab Snippet, Slack/Teams), but their payload is still the same fabricated PAN/Aadhaar/SWIFT/UPI/credit-card record, not source code, API credentials, or signing keys -- the data type this sector actually cares about has never been exercised",
		"", CoverageStatusGap)
	if err != nil {
		return nil, fmt.Errorf("loading seed profile catalog: %w", err)
	}
	itSaas, err := NewProfile("DLPPROFILE-ITSAAS", "IT, SaaS, BPO, Telecom and Technology", ProfileIndustry,
		[]string{"dlp-exfiltration-coderepo", "dlp-exfiltration-webhook", "dlp-exfiltration-cloud-storage"},
		[]ComplianceReference{itSaasBaseline},
		"IT/SaaS source code, API credentials, and customer exports realistically leave through developer-repository uploads, Slack/Teams-style webhook integrations, and cloud storage -- dlp.txt §4's own named IT/SaaS/BPO/Telecom channels.",
		"manually authored from dlp.txt §4's named IT/SaaS/BPO/Telecom item, scenario IDs selected from RealDLPScenarioIDs()")
	if err != nil {
		return nil, fmt.Errorf("loading seed profile catalog: %w", err)
	}
	itSaas, err = WithControlObjectives(itSaas, []ControlObjectiveCoverage{itSaasGap})
	if err != nil {
		return nil, fmt.Errorf("loading seed profile catalog: %w", err)
	}

	dpdpIndia, err := NewComplianceReference("India DPDP Act 2023 (+ Rules)", Unverified,
		"nationwide applicability asserted at the framework-name level only; the November 2025 Rules notification is noted in dlp.txt §4 but no specific rule number is verified here", "")
	if err != nil {
		return nil, fmt.Errorf("loading seed profile catalog: %w", err)
	}
	india, err := NewProfile("DLPPROFILE-INDIA", "India (cross-industry baseline)", ProfileRegional,
		[]string{"dlp-exfiltration-sftp", "dlp-exfiltration-smtp", "dlp-exfiltration-cloud-storage", "dlp-exfiltration-webhook"},
		[]ComplianceReference{dpdpIndia},
		"a cross-industry baseline of the highest-volume real channels for India-based deployments. Every one of these scenarios' real payload (fabricated PAN/Aadhaar/SWIFT/UPI/credit-card) is itself India-shaped, so -- unlike every industry profile above except BFSI -- this baseline has no payload-fidelity gap to record: the data type and the channels are both genuinely tested together.",
		"manually authored from dlp.txt §4's named India item, scenario IDs selected from RealDLPScenarioIDs()")
	if err != nil {
		return nil, fmt.Errorf("loading seed profile catalog: %w", err)
	}

	uaeBaseline, err := NewComplianceReference("UAE federal personal-data framework and sector-specific rules (e.g. UAE Central Bank for regulated financial institutions)", Unverified,
		"framework names only, drawn from secondary sources; dlp.txt §4 names the UAE federal framework plus sector-specific obligations that may apply separately, none of which is verified against a primary source here", "")
	if err != nil {
		return nil, fmt.Errorf("loading seed profile catalog: %w", err)
	}
	uaeGap, err := NewControlObjectiveCoverage("UAE-specific identifier-format fidelity (Emirates ID, IBAN)", "",
		"dlp.txt §4 names synthetic Emirates-ID-format and IBAN-format fixtures as the UAE-specific data profile, but no real scenario payload uses either format -- every scenario tests the same fabricated PAN/Aadhaar/SWIFT/UPI/credit-card record regardless of channel, which is India-shaped, not UAE-shaped",
		"", CoverageStatusGap)
	if err != nil {
		return nil, fmt.Errorf("loading seed profile catalog: %w", err)
	}
	uae, err := NewProfile("DLPPROFILE-UAE", "United Arab Emirates (cross-industry baseline)", ProfileRegional,
		[]string{"dlp-exfiltration-sftp", "dlp-exfiltration-smtp", "dlp-exfiltration-cloud-storage", "dlp-exfiltration-webhook"},
		[]ComplianceReference{uaeBaseline},
		"a cross-industry baseline of the same real, region-agnostic channels as the India baseline -- channel delivery mechanics (SFTP/SMTP/cloud-storage/webhook) work identically regardless of which region's identifiers flow through them. Unlike India, this baseline's real payload does not match the region's actual data profile, so the gap below is recorded honestly rather than reusing India's flat, ungapped shape.",
		"manually authored from dlp.txt §4's named UAE item, scenario IDs selected from RealDLPScenarioIDs()")
	if err != nil {
		return nil, fmt.Errorf("loading seed profile catalog: %w", err)
	}
	uae, err = WithControlObjectives(uae, []ControlObjectiveCoverage{uaeGap})
	if err != nil {
		return nil, fmt.Errorf("loading seed profile catalog: %w", err)
	}

	profiles := []Profile{bfsi, healthcare, manufacturing, government, itSaas, india, uae}
	for _, p := range profiles {
		if err := ValidateAgainstCatalog(p, realScenarioIDs); err != nil {
			return nil, fmt.Errorf("loading seed profile catalog: %w", err)
		}
	}
	return profiles, nil
}
