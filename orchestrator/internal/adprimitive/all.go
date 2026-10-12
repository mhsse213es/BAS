package adprimitive

// All returns every AD primitive across all catalogs, in a deterministic order
// (Kerberoasting, ACL, RBCD, DCSync, ADCS, delegation, trust, GPO). It is the
// single source for "the whole AD primitive set" -- e.g. the content-library
// inventory feeds it to adlibinv.Inventory.
func All() []Primitive {
	var out []Primitive
	out = append(out, KerberoastingCatalog...)
	out = append(out, ACLAbuseCatalog...)
	out = append(out, RBCDCatalog...)
	out = append(out, DCSyncCatalog...)
	out = append(out, ADCSCatalog...)
	out = append(out, DelegationCatalog...)
	out = append(out, TrustAbuseCatalog...)
	out = append(out, GPOAbuseCatalog...)
	return out
}
