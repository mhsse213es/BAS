package fixture

import "fmt"

// PagedOrderCount is how many orders the paged fixture gives the owner. It must exceed
// the largest page the fixed build allows (100), so an item-count check can fail.
const PagedOrderCount = 150

// OrdersPaged is the two-tenant fixture plus PagedOrderCount orders owned by customer-b.
// Each paged order has its own protected values, so a leak is attributable to one order.
func OrdersPaged() Fixture {
	f := OrdersTwoTenant()
	f.Name = "orders-paged"
	for i := 1; i <= PagedOrderCount; i++ {
		f.Objects = append(f.Objects, Object{
			ID:      fmt.Sprintf("ORD-P%03d", i),
			OwnerID: "cust-b",
			Status:  "open",
			Public:  map[string]string{"sku": "SKU-PAGED", "quantity": "1"},
			Protected: map[string]string{
				"card_last4":     fmt.Sprintf("BAS-SIM-PG-%03d", i),
				"account_ref":    fmt.Sprintf("BAS-SIM-PGA-%03d", i),
				"webhook_secret": fmt.Sprintf("BAS-SIM-PGW-%03d", i),
			},
		})
	}
	return f
}
