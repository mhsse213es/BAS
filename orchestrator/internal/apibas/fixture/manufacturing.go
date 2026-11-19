package fixture

// ManufacturingTwoPlant is the manufacturing pack's fixture: two plants, each with a planner, an operator, a production order,
// a bill of materials, a machine asset and an IoT device, plus two suppliers with purchase orders and one OT engineer who
// owns the OT management configuration. Every identity, part, price and credential is synthetic, and every protected value is
// tagged BAS-SIM. Machine commands are recorded in the lab only; nothing here drives real equipment.
//
// Ownership:
//   - Planner A owns PROD-A-001, BOM-A-001 and ASSET-A-001; Operator A is assigned PROD-A-001 and ASSET-A-001.
//   - Planner B owns PROD-B-001, BOM-B-001 and ASSET-B-001; Operator B is assigned PROD-B-001 and ASSET-B-001.
//   - Supplier 1 owns PUR-S1-001 and Supplier 2 owns PUR-S2-001.
//   - Device A owns DEV-A-001 and Device B owns DEV-B-001.
//   - The OT engineer owns OTCFG-A-001, the plant A OT management configuration.
func ManufacturingTwoPlant() Fixture {
	return Fixture{
		Name: "manufacturing-two-plant",
		Identities: []Identity{
			{Name: "planner-a", CustomerID: "planner-a", TokenRef: "apibas/lab/planner-a", Role: "planner"},
			{Name: "operator-a", CustomerID: "operator-a", TokenRef: "apibas/lab/operator-a", Role: "operator"},
			{Name: "planner-b", CustomerID: "planner-b", TokenRef: "apibas/lab/planner-b", Role: "planner"},
			{Name: "operator-b", CustomerID: "operator-b", TokenRef: "apibas/lab/operator-b", Role: "operator"},
			{Name: "supplier-1", CustomerID: "supplier-1", TokenRef: "apibas/lab/supplier-1", Role: "supplier"},
			{Name: "supplier-2", CustomerID: "supplier-2", TokenRef: "apibas/lab/supplier-2", Role: "supplier"},
			{Name: "device-a", CustomerID: "device-a", TokenRef: "apibas/lab/device-a", Role: "device"},
			{Name: "device-b", CustomerID: "device-b", TokenRef: "apibas/lab/device-b", Role: "device"},
			{Name: "ot-engineer", CustomerID: "ot-engineer", TokenRef: "apibas/lab/ot-engineer", Role: "ot-engineer"},
		},
		Objects: []Object{
			{
				ID: "PROD-A-001", OwnerID: "planner-a", Status: "planned", Kind: "production_order", Assignee: "operator-a",
				Public:    map[string]string{"product": "gearbox-housing", "amount": "500"},
				Protected: map[string]string{"customer_price": "BAS-SIM-MFG-PRICE-A"},
			},
			{
				ID: "PROD-B-001", OwnerID: "planner-b", Status: "planned", Kind: "production_order", Assignee: "operator-b",
				Public:    map[string]string{"product": "pump-casing", "amount": "300"},
				Protected: map[string]string{"customer_price": "BAS-SIM-MFG-PRICE-B"},
			},
			{
				ID: "BOM-A-001", OwnerID: "planner-a", Status: "released", Kind: "bom", Parent: "PROD-A-001",
				Public:    map[string]string{"part_count": "42"},
				Protected: map[string]string{"cad_ref": "BAS-SIM-CAD-A", "supplier_cost": "BAS-SIM-COST-A"},
			},
			{
				ID: "BOM-B-001", OwnerID: "planner-b", Status: "released", Kind: "bom", Parent: "PROD-B-001",
				Public:    map[string]string{"part_count": "27"},
				Protected: map[string]string{"cad_ref": "BAS-SIM-CAD-B", "supplier_cost": "BAS-SIM-COST-B"},
			},
			{
				ID: "PUR-S1-001", OwnerID: "supplier-1", Status: "open", Kind: "purchase_order",
				Public:    map[string]string{"item": "steel-coil", "amount": "90000"},
				Protected: map[string]string{"agreed_price": "BAS-SIM-PRICE-S1"},
			},
			{
				ID: "PUR-S2-001", OwnerID: "supplier-2", Status: "open", Kind: "purchase_order",
				Public:    map[string]string{"item": "bearing-set", "amount": "45000"},
				Protected: map[string]string{"agreed_price": "BAS-SIM-PRICE-S2"},
			},
			{
				ID: "ASSET-A-001", OwnerID: "planner-a", Status: "running", Kind: "asset", Assignee: "operator-a",
				Public:    map[string]string{"machine": "cnc-lathe-a1", "line": "line-1"},
				Protected: map[string]string{"telemetry_key": "BAS-SIM-TELEM-A"},
			},
			{
				ID: "ASSET-B-001", OwnerID: "planner-b", Status: "running", Kind: "asset", Assignee: "operator-b",
				Public:    map[string]string{"machine": "press-b1", "line": "line-2"},
				Protected: map[string]string{"telemetry_key": "BAS-SIM-TELEM-B"},
			},
			{
				ID: "DEV-A-001", OwnerID: "device-a", Status: "running", Kind: "device",
				Public: map[string]string{"model": "plc-gateway-a"},
			},
			{
				ID: "DEV-B-001", OwnerID: "device-b", Status: "running", Kind: "device",
				Public: map[string]string{"model": "plc-gateway-b"},
			},
			{
				ID: "OTCFG-A-001", OwnerID: "ot-engineer", Status: "active", Kind: "ot_config",
				Public:    map[string]string{"zone": "plant-a-ot"},
				Protected: map[string]string{"plc_admin_credential": "BAS-SIM-OT-ADMIN-A"},
			},
		},
	}
}
