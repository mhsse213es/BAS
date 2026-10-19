package api

// phishEmailGWExpectation maps a phishing scenario to the EmailGW
// expectation ID whose dispatched message its catalog entry wraps. The
// pairing is proven by TestEmailGWMapping_ConsistentWithPhishCatalogExpectation,
// not by variant name: EG "known-good"/"known-bad" labels are not uniform
// across scenarios (EG-002.known-good expects quarantine). Scenarios whose
// wrapped builder has no entry in emailgwefficacy's dispatch table, or whose
// expectation has no verified counterpart, are deliberately absent.
var phishEmailGWExpectation = map[string]string{
	"PH-AUTH-002": "EG-001.spf.known-bad",
	"PH-AUTH-003": "EG-001.dkim.known-bad",
	"PH-AUTH-004": "EG-001.dmarc.known-bad",
	"PH-AUTH-008": "EG-009.known-bad",
	"PH-BEC-001":  "EG-002.known-good",
	"PH-URL-001":  "EG-003.credential-url.known-good",
	"PH-ATT-001":  "EG-004.known-good",
	"PH-ATT-010":  "EG-008.known-good",
	"PH-CHN-005":  "EG-011.qr-code-lure.known-good",
	"PH-ATT-002":  "EG-012.pdf-embedded-link.known-good",
	"PH-ATT-003":  "EG-013.office-external-link.known-good",
}

func emailGWExpectationFor(scenarioID string) (string, bool) {
	id, ok := phishEmailGWExpectation[scenarioID]
	return id, ok
}
