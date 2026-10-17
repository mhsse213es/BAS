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
// BFSI and the India regional baseline are the two profiles whose real
// payload (fabricated PAN/Aadhaar/SWIFT/UPI/credit-card) matches what
// every scenario's base step tests, so they get a flat, ungapped
// VectorIDs-only shape. UAE gets the same channel-level VectorIDs plus
// exactly one ControlObjectiveCoverage Gap, since no scenario anywhere
// tests Emirates ID/IBAN-format content (confirmed by grep across every
// scenario file during the 2026-10-17 final review). Healthcare,
// Manufacturing, Government, and IT/SaaS each get the same channel-level
// VectorIDs plus BOTH a real Covered entry and a narrower Gap: the
// scenarios cited by these profiles carry genuine "content-diversity"
// steps beyond the base payload (e.g. dlp-exfiltration-smtp's Medical
// Record step, dlp-exfiltration-coderepo's PHP/Perl source-code and
// Azure/DB2-credential steps) that the original builder-check review
// (2026-10-16) missed by reading only each scenario's top-level
// description, not its actual steps -- the 2026-10-17 final review caught
// this and this catalog now records both the real coverage that exists
// and the narrower slice that genuinely doesn't. See the design spec for
// the original reasoning and this file's own NewControlObjectiveCoverage
// calls for exactly what was corrected and why.
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
	healthcareCovered, err := NewControlObjectiveCoverage("patient/clinical record data-type fidelity", "dlp-exfiltration-smtp",
		"dlp-exfiltration-smtp's own \"SMTP Exfiltration of Medical Record\" step carries a real Patient/MRN/Diagnosis-shaped payload -- confirmed by reading the scenario's steps directly (2026-10-17 final review), not just its top-level description. This is real coverage, not the generic BFSI-shaped record every channel's first step carries.",
		"sink-receipt evidence from internal/smtpsink for the Medical Record step's fabricated Patient/MRN/Diagnosis payload",
		CoverageStatusCovered)
	if err != nil {
		return nil, fmt.Errorf("loading seed profile catalog: %w", err)
	}
	healthcareGap, err := NewControlObjectiveCoverage("lab-report/imaging-report/insurance-claim data-type fidelity", "",
		"no real scenario payload is shaped as a lab report, imaging report, or insurance claim -- only a generic Patient/MRN/Diagnosis medical record exists (via dlp-exfiltration-smtp, recorded as Covered above), so this narrower slice of healthcare data remains genuinely untested",
		"", CoverageStatusGap)
	if err != nil {
		return nil, fmt.Errorf("loading seed profile catalog: %w", err)
	}
	healthcare, err := NewProfile("DLPPROFILE-HEALTHCARE", "Healthcare, Hospitals and Insurance", ProfileIndustry,
		[]string{"dlp-exfiltration-cloud-storage", "dlp-exfiltration-smtp", "dlp-exfiltration-sftp"},
		[]ComplianceReference{healthData},
		"Healthcare patient exports, lab/imaging reports, and insurance claims realistically leave through cloud storage, email, and SFTP to diagnostic centers/billing vendors -- dlp.txt §4's own named Healthcare channels. dlp-exfiltration-smtp carries a real Medical Record step, so patient-record fidelity is genuinely Covered; the narrower lab-report/imaging/insurance-claim slice remains an honest Gap.",
		"manually authored from dlp.txt §4's named Healthcare item, scenario IDs selected from RealDLPScenarioIDs(), content-diversity steps verified directly 2026-10-17")
	if err != nil {
		return nil, fmt.Errorf("loading seed profile catalog: %w", err)
	}
	healthcare, err = WithControlObjectives(healthcare, []ControlObjectiveCoverage{healthcareCovered, healthcareGap})
	if err != nil {
		return nil, fmt.Errorf("loading seed profile catalog: %w", err)
	}

	certInManuf, err := NewComplianceReference("CERT-In Cyber Security Directions", Unverified,
		"framework name and the widely-reported 6-hour incident-reporting requirement only; no manufacturing-specific or DLP-specific clause verified", "")
	if err != nil {
		return nil, fmt.Errorf("loading seed profile catalog: %w", err)
	}
	manufacturingCovered, err := NewControlObjectiveCoverage("proprietary source-code data-type fidelity", "dlp-exfiltration-coderepo",
		"dlp-exfiltration-coderepo carries dedicated \"Exfiltration of PHP Source Code\" and \"...of Perl Source Code\" steps (plus Azure Cloud Credentials/DB2 Connection String steps) -- confirmed by reading the scenario's steps directly (2026-10-17 final review), not just its top-level description. Generic enterprise source code is genuinely covered via this channel, independent of whether it originated from engineering tooling specifically.",
		"sink-receipt evidence from the coderepo sink for the PHP/Perl Source Code steps",
		CoverageStatusCovered)
	if err != nil {
		return nil, fmt.Errorf("loading seed profile catalog: %w", err)
	}
	manufacturingGap, err := NewControlObjectiveCoverage("CAD drawing/BOM/schematic/engineering-design-file data-type fidelity", "",
		"no real scenario payload is shaped as a CAD drawing, bill of materials, schematic, or other CAD-native engineering export -- generic source code is Covered above via dlp-exfiltration-coderepo, but no scenario tests CAD-specific file formats or content",
		"", CoverageStatusGap)
	if err != nil {
		return nil, fmt.Errorf("loading seed profile catalog: %w", err)
	}
	manufacturing, err := NewProfile("DLPPROFILE-MANUFACTURING", "Manufacturing, Engineering and Industrial", ProfileIndustry,
		[]string{"dlp-exfiltration-coderepo", "dlp-exfiltration-cloud-storage", "dlp-exfiltration-sftp"},
		[]ComplianceReference{certInManuf},
		"Manufacturing CAD drawings, engineering exports, and supplier designs realistically leave through developer/repository uploads, cloud storage, and SFTP to contractors/suppliers -- dlp.txt §4's own named Manufacturing channels. dlp-exfiltration-coderepo carries real source-code content-diversity steps, so generic source-code fidelity is genuinely Covered; the narrower CAD-native-format slice remains an honest Gap.",
		"manually authored from dlp.txt §4's named Manufacturing item, scenario IDs selected from RealDLPScenarioIDs(), content-diversity steps verified directly 2026-10-17")
	if err != nil {
		return nil, fmt.Errorf("loading seed profile catalog: %w", err)
	}
	manufacturing, err = WithControlObjectives(manufacturing, []ControlObjectiveCoverage{manufacturingCovered, manufacturingGap})
	if err != nil {
		return nil, fmt.Errorf("loading seed profile catalog: %w", err)
	}

	govBaseline, err := NewComplianceReference("India DPDP Act 2023 (+ Rules) and UAE federal personal-data framework (cross-industry baseline)", Unverified,
		"dlp.txt §4 names no specific Government/Legal/HR framework beyond role-based/retention expectations, so this cites the same cross-industry DPDP/UAE baseline used for the regional profiles, disclosed as a best-effort substitute rather than a sector-specific citation", "")
	if err != nil {
		return nil, fmt.Errorf("loading seed profile catalog: %w", err)
	}
	governmentCovered, err := NewControlObjectiveCoverage("employment-record/client-contract data-type fidelity", "dlp-exfiltration-smtp",
		"dlp-exfiltration-smtp carries a real \"Exfiltration of Employment Contract\" step, and dlp-exfiltration-cloud-storage (this profile's other cited channel) carries a real \"Exfiltration of Partnership Agreement\" step -- confirmed by reading both scenarios' steps directly (2026-10-17 final review), not just their top-level descriptions. Employee-record and client-contract fidelity is genuinely covered, matching dlp.txt §4's own named Government/Legal/HR priorities for this data type.",
		"sink-receipt evidence from internal/smtpsink for the Employment Contract step",
		CoverageStatusCovered)
	if err != nil {
		return nil, fmt.Errorf("loading seed profile catalog: %w", err)
	}
	governmentGap, err := NewControlObjectiveCoverage("citizen-identity-record/case-file data-type fidelity", "",
		"no real scenario payload is shaped as a government citizen-identity record (e.g. an Indian-government-issued ID or case file) -- other countries' identity formats exist (Israeli ID, UK National Insurance Number, US SSN) but none is government-case-file-shaped, and employment/contract content is Covered above, not citizen-identity content",
		"", CoverageStatusGap)
	if err != nil {
		return nil, fmt.Errorf("loading seed profile catalog: %w", err)
	}
	government, err := NewProfile("DLPPROFILE-GOVERNMENT", "Government, Legal, Professional Services and HR", ProfileIndustry,
		[]string{"dlp-exfiltration-sftp", "dlp-exfiltration-smtp", "dlp-exfiltration-cloud-storage"},
		[]ComplianceReference{govBaseline},
		"Government case files, employee records, and client contracts realistically leave through SFTP to outsourced teams, email, and cloud storage -- dlp.txt §4's own named Government/Legal/HR channels. Employment-record/client-contract fidelity is genuinely Covered via real content-diversity steps; citizen-identity-record/case-file fidelity remains an honest Gap.",
		"manually authored from dlp.txt §4's named Government/Legal/HR item, scenario IDs selected from RealDLPScenarioIDs(), content-diversity steps verified directly 2026-10-17")
	if err != nil {
		return nil, fmt.Errorf("loading seed profile catalog: %w", err)
	}
	government, err = WithControlObjectives(government, []ControlObjectiveCoverage{governmentCovered, governmentGap})
	if err != nil {
		return nil, fmt.Errorf("loading seed profile catalog: %w", err)
	}

	itSaasBaseline, err := NewComplianceReference("India DPDP Act 2023 (cross-industry baseline)", Unverified,
		"dlp.txt §4 names no IT/SaaS/BPO/telecom-specific framework beyond data-residency/shared-service expectations, so this cites the same cross-industry DPDP baseline used for the India regional profile, disclosed as a best-effort substitute rather than a sector-specific citation", "")
	if err != nil {
		return nil, fmt.Errorf("loading seed profile catalog: %w", err)
	}
	itSaasCovered, err := NewControlObjectiveCoverage("source-code/API-credential data-type fidelity", "dlp-exfiltration-coderepo",
		"dlp-exfiltration-coderepo carries real PHP/Perl source-code steps plus Azure Cloud Credentials/DB2 Connection String steps, and dlp-exfiltration-webhook (this profile's other cited channel) carries real AWS Cloud Credentials/PostgreSQL Connection String steps -- confirmed by reading both scenarios' steps directly (2026-10-17 final review), not just their top-level descriptions. The data type this sector cares about is genuinely exercised.",
		"sink-receipt evidence from the coderepo sink for the PHP/Perl Source Code and Azure Cloud Credentials/DB2 Connection String steps",
		CoverageStatusCovered)
	if err != nil {
		return nil, fmt.Errorf("loading seed profile catalog: %w", err)
	}
	itSaasGap, err := NewControlObjectiveCoverage("customer-interaction-transcript/call-center-record data-type fidelity", "",
		"no real scenario payload is shaped as a customer-support transcript, call-center recording metadata, or large-volume support export -- source code and API credentials are Covered above, but this large-volume BPO/support data type remains genuinely untested",
		"", CoverageStatusGap)
	if err != nil {
		return nil, fmt.Errorf("loading seed profile catalog: %w", err)
	}
	itSaas, err := NewProfile("DLPPROFILE-ITSAAS", "IT, SaaS, BPO, Telecom and Technology", ProfileIndustry,
		[]string{"dlp-exfiltration-coderepo", "dlp-exfiltration-webhook", "dlp-exfiltration-cloud-storage"},
		[]ComplianceReference{itSaasBaseline},
		"IT/SaaS source code, API credentials, and customer exports realistically leave through developer-repository uploads, Slack/Teams-style webhook integrations, and cloud storage -- dlp.txt §4's own named IT/SaaS/BPO/Telecom channels. Source-code/API-credential fidelity is genuinely Covered via real content-diversity steps; the call-center/support-transcript data volume this sector also names remains an honest Gap.",
		"manually authored from dlp.txt §4's named IT/SaaS/BPO/Telecom item, scenario IDs selected from RealDLPScenarioIDs(), content-diversity steps verified directly 2026-10-17")
	if err != nil {
		return nil, fmt.Errorf("loading seed profile catalog: %w", err)
	}
	itSaas, err = WithControlObjectives(itSaas, []ControlObjectiveCoverage{itSaasCovered, itSaasGap})
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
