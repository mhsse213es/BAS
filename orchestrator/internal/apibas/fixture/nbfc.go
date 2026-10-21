package fixture

// NBFCTwoBorrower is the NBFC pack's fixture: two borrowers with separate loans, KYC records and repayments, plus one loan
// officer and one administrator. Every identity, amount, KYC detail and repayment is synthetic, and every protected value is
// tagged BAS-SIM.
//
// Ownership:
//   - Borrower A owns BOR-A, LOAN-A-001, KYC-A-001 and REP-A-001.
//   - Borrower B owns BOR-B, LOAN-B-001, KYC-B-001 and REP-B-001.
//   - The loan officer is assigned LOAN-A-001 only. LOAN-B-001 is not assigned to any officer.
//   - The administrator manages access; no pack route grants the administrator a record by default.
func NBFCTwoBorrower() Fixture {
	return Fixture{
		Name: "nbfc-two-borrower",
		Identities: []Identity{
			{Name: "borrower-a", CustomerID: "borrower-a", TokenRef: "apibas/lab/borrower-a", Role: "borrower"},
			{Name: "borrower-b", CustomerID: "borrower-b", TokenRef: "apibas/lab/borrower-b", Role: "borrower"},
			{Name: "loan-officer", CustomerID: "loan-officer", TokenRef: "apibas/lab/loan-officer", Role: "officer"},
			// The administrator holds the administrator role, and only the grants listed here. Each admin route checks one grant.
			{Name: "nbfc-admin", CustomerID: "nbfc-admin", TokenRef: "apibas/lab/nbfc-admin", Role: "administrator", Permissions: []string{"loans:read"}},
		},
		Objects: []Object{
			{
				ID: "BOR-A", OwnerID: "borrower-a", Status: "active", Kind: "borrower",
				Public: map[string]string{"segment": "salaried"},
			},
			{
				ID: "BOR-B", OwnerID: "borrower-b", Status: "active", Kind: "borrower",
				Public: map[string]string{"segment": "self-employed"},
			},
			{
				ID: "LOAN-A-001", OwnerID: "borrower-a", Status: "submitted", Kind: "loan", Parent: "BOR-A", Assignee: "loan-officer",
				Public:    map[string]string{"amount": "250000", "product": "personal-loan"},
				Protected: map[string]string{"disbursement_account": "BAS-SIM-LOAN-A-ACC"},
			},
			{
				ID: "LOAN-B-001", OwnerID: "borrower-b", Status: "submitted", Kind: "loan", Parent: "BOR-B",
				Public:    map[string]string{"amount": "480000", "product": "business-loan"},
				Protected: map[string]string{"disbursement_account": "BAS-SIM-LOAN-B-ACC"},
			},
			{
				ID: "KYC-A-001", OwnerID: "borrower-a", Status: "verified", Kind: "kyc", Parent: "BOR-A",
				Public:    map[string]string{"document_type": "pan"},
				Protected: map[string]string{"pan_number": "BAS-SIM-PAN-A", "aadhaar_ref": "BAS-SIM-AADHAAR-A"},
			},
			{
				ID: "KYC-B-001", OwnerID: "borrower-b", Status: "verified", Kind: "kyc", Parent: "BOR-B",
				Public:    map[string]string{"document_type": "pan"},
				Protected: map[string]string{"pan_number": "BAS-SIM-PAN-B", "aadhaar_ref": "BAS-SIM-AADHAAR-B"},
			},
			{
				ID: "REP-A-001", OwnerID: "borrower-a", Status: "scheduled", Kind: "repayment", Parent: "LOAN-A-001",
				Public:    map[string]string{"amount": "10000"},
				Protected: map[string]string{"debit_mandate": "BAS-SIM-MANDATE-A"},
			},
			{
				ID: "REP-B-001", OwnerID: "borrower-b", Status: "scheduled", Kind: "repayment", Parent: "LOAN-B-001",
				Public:    map[string]string{"amount": "16000"},
				Protected: map[string]string{"debit_mandate": "BAS-SIM-MANDATE-B"},
			},
		},
	}
}
