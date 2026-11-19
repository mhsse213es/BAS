package fixture

// CommerceTelecomTwoTenant is the retail, logistics and telecom pack's fixture: two shoppers each with a retail order and a
// shipment, two subscribers each with a subscriber record, a SIM and a usage record, two partners each with an API key, one
// carrier that reports delivery, and one support agent. Every identity, address, national ID, call log and key secret is
// synthetic, and every protected value is tagged BAS-SIM.
//
// Ownership:
//   - Shopper A owns RORD-A-001 and SHIP-A-001; Shopper B owns RORD-B-001 and SHIP-B-001.
//   - Subscriber A owns SUBR-A-001, SIM-A-001 and USG-A-001; Subscriber B owns SUBR-B-001, SIM-B-001 and USG-B-001.
//   - Partner 1 owns PKEY-1-001 (read scope); Partner 2 owns PKEY-2-001 (read scope).
//   - The carrier and the agent own nothing. The carrier reports delivery; the agent is staff who may reprice an order and
//     change a partner key's scope.
func CommerceTelecomTwoTenant() Fixture {
	return Fixture{
		Name: "commerce-telecom-two-tenant",
		Identities: []Identity{
			{Name: "shopper-a", CustomerID: "shopper-a", TokenRef: "apibas/lab/shopper-a", Role: "shopper"},
			{Name: "shopper-b", CustomerID: "shopper-b", TokenRef: "apibas/lab/shopper-b", Role: "shopper"},
			{Name: "subscriber-a", CustomerID: "subscriber-a", TokenRef: "apibas/lab/subscriber-a", Role: "subscriber"},
			{Name: "subscriber-b", CustomerID: "subscriber-b", TokenRef: "apibas/lab/subscriber-b", Role: "subscriber"},
			{Name: "partner-1", CustomerID: "partner-1", TokenRef: "apibas/lab/partner-1", Role: "partner"},
			{Name: "partner-2", CustomerID: "partner-2", TokenRef: "apibas/lab/partner-2", Role: "partner"},
			{Name: "carrier-1", CustomerID: "carrier-1", TokenRef: "apibas/lab/carrier-1", Role: "carrier"},
			{Name: "agent-1", CustomerID: "agent-1", TokenRef: "apibas/lab/agent-1", Role: "agent"},
		},
		Objects: []Object{
			{
				ID: "RORD-A-001", OwnerID: "shopper-a", Status: "placed", Kind: "retail_order",
				Public: map[string]string{"item": "kettle", "amount": "4000"},
			},
			{
				ID: "RORD-B-001", OwnerID: "shopper-b", Status: "placed", Kind: "retail_order",
				Public: map[string]string{"item": "lamp", "amount": "2500"},
			},
			{
				ID: "SHIP-A-001", OwnerID: "shopper-a", Status: "in_transit", Kind: "shipment", Parent: "RORD-A-001",
				Public:    map[string]string{"carrier": "carrier-1"},
				Protected: map[string]string{"delivery_address": "BAS-SIM-ADDR-A"},
			},
			{
				ID: "SHIP-B-001", OwnerID: "shopper-b", Status: "in_transit", Kind: "shipment", Parent: "RORD-B-001",
				Public:    map[string]string{"carrier": "carrier-1"},
				Protected: map[string]string{"delivery_address": "BAS-SIM-ADDR-B"},
			},
			{
				ID: "SUBR-A-001", OwnerID: "subscriber-a", Status: "active", Kind: "subscriber",
				Public:    map[string]string{"plan": "postpaid-basic"},
				Protected: map[string]string{"national_id": "BAS-SIM-NID-A"},
			},
			{
				ID: "SUBR-B-001", OwnerID: "subscriber-b", Status: "active", Kind: "subscriber",
				Public:    map[string]string{"plan": "postpaid-plus"},
				Protected: map[string]string{"national_id": "BAS-SIM-NID-B"},
			},
			{
				ID: "SIM-A-001", OwnerID: "subscriber-a", Status: "active", Kind: "sim", Parent: "SUBR-A-001",
				Public: map[string]string{"line": "line-a"},
			},
			{
				ID: "SIM-B-001", OwnerID: "subscriber-b", Status: "active", Kind: "sim", Parent: "SUBR-B-001",
				Public: map[string]string{"line": "line-b"},
			},
			{
				ID: "USG-A-001", OwnerID: "subscriber-a", Status: "billed", Kind: "usage",
				Public:    map[string]string{"minutes": "120"},
				Protected: map[string]string{"call_log": "BAS-SIM-CALLS-A"},
			},
			{
				ID: "USG-B-001", OwnerID: "subscriber-b", Status: "billed", Kind: "usage",
				Public:    map[string]string{"minutes": "340"},
				Protected: map[string]string{"call_log": "BAS-SIM-CALLS-B"},
			},
			{
				ID: "PKEY-1-001", OwnerID: "partner-1", Status: "read_scope", Kind: "partner_key",
				Public:    map[string]string{"scope": "read"},
				Protected: map[string]string{"key_secret": "BAS-SIM-KEY-1"},
			},
			{
				ID: "PKEY-2-001", OwnerID: "partner-2", Status: "read_scope", Kind: "partner_key",
				Public:    map[string]string{"scope": "read"},
				Protected: map[string]string{"key_secret": "BAS-SIM-KEY-2"},
			},
		},
	}
}
