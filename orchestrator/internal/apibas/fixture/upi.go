package fixture

// UPITwoCustomer is the UPI / open-banking pack's fixture: two UPI customers with their own VPA-linked account, a UPI
// transaction, a standing-instruction mandate and an Account Aggregator consent, plus one merchant/PSP identity. Every VPA,
// account reference, transaction reference and consent artifact is synthetic, and every protected value is tagged BAS-SIM.
//
// Ownership:
//   - Customer A owns VPA-A-001, TXN-A-001, MANDATE-A-001, CONSENT-A-001 (revoked) and CONSENT-A-002 (active).
//   - Customer B owns VPA-B-001 and TXN-B-001.
//   - The merchant is assigned MANDATE-A-001 only, as the counterparty entitled to execute it.
func UPITwoCustomer() Fixture {
	return Fixture{
		Name: "upi-two-customer",
		Identities: []Identity{
			{Name: "upi-cust-a", CustomerID: "upi-cust-a", TokenRef: "apibas/lab/upi-cust-a", Role: "customer"},
			{Name: "upi-cust-b", CustomerID: "upi-cust-b", TokenRef: "apibas/lab/upi-cust-b", Role: "customer"},
			{Name: "upi-merchant-1", CustomerID: "upi-merchant-1", TokenRef: "apibas/lab/upi-merchant-1", Role: "merchant"},
		},
		Objects: []Object{
			{
				ID: "VPA-A-001", OwnerID: "upi-cust-a", Status: "active", Kind: "vpa",
				Public:    map[string]string{"handle": "upicust.a@psp"},
				Protected: map[string]string{"linked_account": "BAS-SIM-UPI-ACC-A"},
			},
			{
				ID: "VPA-B-001", OwnerID: "upi-cust-b", Status: "active", Kind: "vpa",
				Public:    map[string]string{"handle": "upicust.b@psp"},
				Protected: map[string]string{"linked_account": "BAS-SIM-UPI-ACC-B"},
			},
			{
				ID: "TXN-A-001", OwnerID: "upi-cust-a", Status: "settled", Kind: "transaction",
				Public:    map[string]string{"amount": "500", "direction": "debit"},
				Protected: map[string]string{"payee_vpa": "merchant.1@psp", "utr": "BAS-SIM-UTR-A"},
			},
			{
				ID: "TXN-B-001", OwnerID: "upi-cust-b", Status: "settled", Kind: "transaction",
				Public:    map[string]string{"amount": "1200", "direction": "debit"},
				Protected: map[string]string{"payee_vpa": "merchant.1@psp", "utr": "BAS-SIM-UTR-B"},
			},
			{
				ID: "MANDATE-A-001", OwnerID: "upi-cust-a", Status: "active", Kind: "mandate", Assignee: "upi-merchant-1",
				Public:    map[string]string{"frequency": "monthly"},
				Protected: map[string]string{"debit_account": "BAS-SIM-UPI-ACC-A", "max_amount": "2000"},
			},
			{
				// CONSENT-A-001 is the revoked consent the DATA-501 attack step replays (RBI Account Aggregator framework:
				// a revoked consent must not be usable for any further financial-information fetch).
				ID: "CONSENT-A-001", OwnerID: "upi-cust-a", Status: "revoked", Kind: "consent",
				Public:    map[string]string{"purpose": "account_aggregation", "fip": "BAS-SIM-BANK-A"},
				Protected: map[string]string{"linked_accounts": "BAS-SIM-FI-A"},
			},
			{
				// CONSENT-A-002 is the active consent the DATA-501 baseline step fetches with. If this fetch fails, the
				// scenario is not testable.
				ID: "CONSENT-A-002", OwnerID: "upi-cust-a", Status: "active", Kind: "consent",
				Public:    map[string]string{"purpose": "account_aggregation", "fip": "BAS-SIM-BANK-A"},
				Protected: map[string]string{"linked_accounts": "BAS-SIM-FI-A"},
			},
		},
	}
}
