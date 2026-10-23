package license

import (
	"fmt"
	"sort"
)

// Tier is the commercial licence tier. It is part of the signed payload, so it cannot be changed
// after a licence is issued.
type Tier string

const (
	TierCore       Tier = "Core"
	TierAdvanced   Tier = "Advanced"
	TierEnterprise Tier = "Enterprise"
)

// ProductLine is a licensable product area. A scenario carries one of these in its YAML.
type ProductLine string

const (
	// ProductCommon covers the general scenarios and the Threat Intelligence Factory. Every tier
	// includes it.
	ProductCommon     ProductLine = "common"
	ProductAV         ProductLine = "av"
	ProductWAF        ProductLine = "waf"
	ProductNetwork    ProductLine = "network"
	ProductEmail      ProductLine = "email"
	ProductDLP        ProductLine = "dlp"
	ProductPhishing   ProductLine = "phishing"
	ProductKillChain  ProductLine = "killchain"
	ProductRansomware ProductLine = "ransomware"
	ProductWebGW      ProductLine = "webgw"
	ProductCloud      ProductLine = "cloud"
	// ProductAPIBAS is the API BAS testing product. It is sold with Advanced.
	ProductAPIBAS ProductLine = "apibas"
	// ProductAD is the Active Directory BAS product line. It is sold with Advanced.
	ProductAD ProductLine = "ad"
	// ProductAleef is the Aleef API discovery product. It is a separate product outside the three
	// tiers: no tier includes it, and it is granted only by the signed add-on token "addon:aleef".
	ProductAleef ProductLine = "aleef"
)

// addonPrefix starts a Features entry that grants an add-on product.
const addonPrefix = "addon:"

// addonProducts is the explicit allowlist of add-ons: product line to add-on name. Only a listed
// product is ever granted by a Features token, so tier permissions are still never derived from
// free text. An add-on product is granted by its token alone, whatever the tier.
var addonProducts = map[ProductLine]string{ProductAleef: "aleef"}

// HasAddon reports whether the signed Features list carries the add-on token "addon:"+name. The
// match is exact: no prefix, substring or case folding, and no trimming. Features are covered by
// the licence signature, so the token cannot be added after issue.
func (l *License) HasAddon(name string) bool {
	return featuresHaveAddon(l.Features, name)
}

func featuresHaveAddon(features []string, name string) bool {
	want := addonPrefix + name
	for _, f := range features {
		if f == want {
			return true
		}
	}
	return false
}

// Addons returns the recognised add-on names this licence carries, sorted. Unrecognised
// "addon:" tokens are ignored.
func (l *License) Addons() []string {
	var out []string
	for _, name := range addonProducts {
		if l.HasAddon(name) {
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out
}

// tierProductLines is the one authoritative mapping. The server derives permissions only from this
// table, never from the free-text Features list.
var tierProductLines = map[Tier][]ProductLine{
	TierCore: {ProductAV, ProductWAF, ProductNetwork, ProductEmail},
	TierAdvanced: {
		ProductAV, ProductWAF, ProductNetwork, ProductEmail,
		ProductDLP, ProductPhishing, ProductAPIBAS, ProductAD,
	},
	TierEnterprise: {
		ProductAV, ProductWAF, ProductNetwork, ProductEmail,
		ProductDLP, ProductPhishing, ProductAPIBAS, ProductAD,
		ProductKillChain, ProductRansomware, ProductWebGW, ProductCloud,
	},
}

// TierProducts returns the product lines a tier permits, always including ProductCommon. An unknown
// tier is an error, and callers must refuse rather than fall back.
func TierProducts(t Tier) (map[ProductLine]bool, error) {
	lines, ok := tierProductLines[t]
	if !ok {
		return nil, fmt.Errorf("license: unknown tier %q", t)
	}
	out := map[ProductLine]bool{ProductCommon: true}
	for _, p := range lines {
		out[p] = true
	}
	return out, nil
}

// EffectiveTier returns the tier a licence grants. A licence with no tier was issued before tiers
// existed and keeps everything, so it is Enterprise.
func (l *License) EffectiveTier() Tier {
	if l.Tier == "" {
		return TierEnterprise
	}
	return Tier(l.Tier)
}

// Permits reports whether this licence allows the product line. An unknown tier permits nothing.
func (l *License) Permits(p ProductLine) bool {
	if name, ok := addonProducts[p]; ok {
		return l.HasAddon(name)
	}
	products, err := TierProducts(l.EffectiveTier())
	if err != nil {
		return false
	}
	return products[p]
}

// ValidProductLine reports whether p names a product line that some tier can license, or the
// common line. A scenario whose product line is not valid is never loaded.
func ValidProductLine(p string) bool {
	if ProductLine(p) == ProductCommon {
		return true
	}
	if _, ok := addonProducts[ProductLine(p)]; ok {
		return true
	}
	for _, lines := range tierProductLines {
		for _, l := range lines {
			if string(l) == p {
				return true
			}
		}
	}
	return false
}

// PermitsNow reports whether the most recently verified licence permits the product line. A locked
// licence permits nothing, and a state with no tier fails closed.
func PermitsNow(p ProductLine) bool {
	info := Current()
	if info.State.Blocked() {
		return false
	}
	if name, ok := addonProducts[p]; ok {
		for _, a := range info.Addons {
			if a == name {
				return true
			}
		}
		return false
	}
	products, err := TierProducts(info.Tier)
	if err != nil {
		return false
	}
	return products[p]
}

// ProductLinesFor returns the product lines a tier permits as a sorted list, for display.
func ProductLinesFor(t Tier) ([]string, error) {
	set, err := TierProducts(t)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(set))
	for p := range set {
		out = append(out, string(p))
	}
	sort.Strings(out)
	return out, nil
}
