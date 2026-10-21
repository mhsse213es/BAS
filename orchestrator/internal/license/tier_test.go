package license

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// Each tier includes exactly the product lines it is sold with, and each higher tier includes the
// lower ones.
func TestTierProducts_ExactSets(t *testing.T) {
	core := []ProductLine{ProductAV, ProductWAF, ProductNetwork, ProductEmail}
	advanced := append(append([]ProductLine{}, core...), ProductDLP, ProductPhishing, ProductAPIBAS)
	enterprise := append(append([]ProductLine{}, advanced...), ProductKillChain, ProductRansomware, ProductWebGW, ProductCloud)

	for _, c := range []struct {
		tier Tier
		want []ProductLine
	}{{TierCore, core}, {TierAdvanced, advanced}, {TierEnterprise, enterprise}} {
		got, err := TierProducts(c.tier)
		if err != nil {
			t.Fatalf("%s: %v", c.tier, err)
		}
		want := append([]ProductLine{ProductCommon}, c.want...)
		if len(got) != len(want) {
			t.Fatalf("%s: %d product lines, want %d: %v", c.tier, len(got), len(want), got)
		}
		for _, p := range want {
			if !got[p] {
				t.Fatalf("%s: missing %s", c.tier, p)
			}
		}
	}
}

// A licence without a tier is a pre-tier licence. It keeps every product line, as Enterprise did.
func TestPermits_LegacyLicenseIsEnterprise(t *testing.T) {
	lic := &License{Customer: "Legacy", CustomerID: "legacy-1"}
	for _, p := range []ProductLine{ProductDLP, ProductKillChain, ProductRansomware, ProductWebGW, ProductCloud} {
		if !lic.Permits(p) {
			t.Fatalf("legacy licence refused %s", p)
		}
	}
}

// A Core licence permits Core product lines and refuses the rest. Common scenarios are in every tier.
func TestPermits_CoreRefusesHigherTiers(t *testing.T) {
	lic := &License{Tier: string(TierCore)}
	for _, p := range []ProductLine{ProductAV, ProductWAF, ProductNetwork, ProductEmail, ProductCommon} {
		if !lic.Permits(p) {
			t.Fatalf("Core refused %s", p)
		}
	}
	for _, p := range []ProductLine{ProductDLP, ProductPhishing, ProductKillChain, ProductRansomware, ProductWebGW, ProductCloud} {
		if lic.Permits(p) {
			t.Fatalf("Core permitted %s", p)
		}
	}
}

// Advanced adds DLP and phishing, but not ransomware.
func TestPermits_AdvancedExcludesRansomware(t *testing.T) {
	lic := &License{Tier: string(TierAdvanced)}
	if !lic.Permits(ProductDLP) || !lic.Permits(ProductPhishing) {
		t.Fatal("Advanced refused DLP or phishing")
	}
	if lic.Permits(ProductRansomware) || lic.Permits(ProductKillChain) {
		t.Fatal("Advanced permitted ransomware or kill chain")
	}
}

// A tier that is not one of the three is refused everywhere: nothing is permitted.
func TestPermits_UnknownTierPermitsNothing(t *testing.T) {
	lic := &License{Tier: "Platinum"}
	if _, err := TierProducts(Tier(lic.Tier)); err == nil {
		t.Fatal("unknown tier accepted by TierProducts")
	}
	if lic.Permits(ProductAV) || lic.Permits(ProductCommon) {
		t.Fatal("unknown tier permitted a product line")
	}
}

// The tier is part of the signed payload. Changing it after signing breaks the signature, so a
// Core licence cannot be edited into an Enterprise one.
func TestTier_IsSigned(t *testing.T) {
	priv, pub := GenerateTestKeypair()
	orig := PublicKeyPEM
	PublicKeyPEM = pub
	t.Cleanup(func() { PublicKeyPEM = orig })

	signed := SignForTest(priv, License{
		Customer: "Acme", CustomerID: "acme-1", IssuedAt: "2026-01-01", ExpiresAt: "2099-01-01",
		Features: []string{"Core"}, Tier: string(TierCore),
	})
	raw, err := json.Marshal(signed)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verify(raw); err != nil {
		t.Fatalf("freshly signed Core licence rejected: %v", err)
	}
	tampered := strings.Replace(string(raw), `"tier":"Core"`, `"tier":"Enterprise"`, 1)
	if tampered == string(raw) {
		t.Fatal("test setup: tier field not found in JSON")
	}
	if _, err := verify([]byte(tampered)); err == nil {
		t.Fatal("Core licence edited to Enterprise still verified")
	}
}

// A licence with no tier keeps the original payload, so licences signed before tiers existed still
// verify.
func TestTier_EmptyTierPayloadUnchanged(t *testing.T) {
	lic := License{CustomerID: "c", IssuedAt: "2026-01-01", ExpiresAt: "2099-01-01", Features: []string{"full"}}
	want := "c|2026-01-01|2099-01-01|full"
	if lic.payload() != want {
		t.Fatalf("payload = %q, want the unchanged pre-tier form %q", lic.payload(), want)
	}
}

// API BAS is sold with Advanced. A Core licence refuses it, and Advanced and Enterprise permit it.
func TestPermits_APIBASIsAdvanced(t *testing.T) {
	if (&License{Tier: string(TierCore)}).Permits(ProductAPIBAS) {
		t.Fatal("Core permitted API BAS")
	}
	if !(&License{Tier: string(TierAdvanced)}).Permits(ProductAPIBAS) {
		t.Fatal("Advanced refused API BAS")
	}
	if !(&License{Tier: string(TierEnterprise)}).Permits(ProductAPIBAS) {
		t.Fatal("Enterprise refused API BAS")
	}
}

// Evaluate carries the licence tier into the state the runtime checks.
func TestEvaluate_CarriesTier(t *testing.T) {
	now := time.Date(2026, 10, 21, 0, 0, 0, 0, time.UTC)
	info, err := Evaluate(&License{Customer: "Acme", ExpiresAt: "2099-01-01", Tier: string(TierAdvanced)}, now)
	if err != nil {
		t.Fatal(err)
	}
	if info.Tier != TierAdvanced {
		t.Fatalf("Info.Tier = %q, want Advanced", info.Tier)
	}
	legacy, err := Evaluate(&License{Customer: "Legacy", ExpiresAt: "2099-01-01"}, now)
	if err != nil {
		t.Fatal(err)
	}
	if legacy.Tier != TierEnterprise {
		t.Fatalf("pre-tier licence Info.Tier = %q, want Enterprise", legacy.Tier)
	}
}

// PermitsNow reads the verified state. A locked licence permits nothing, and so does a state with no
// tier, so a missing tier fails closed.
func TestPermitsNow_FollowsVerifiedState(t *testing.T) {
	defer SetInitial(Info{})
	SetInitial(Info{State: StateValid, Tier: TierCore})
	if !PermitsNow(ProductAV) || PermitsNow(ProductDLP) {
		t.Fatal("valid Core state gated wrongly")
	}
	SetInitial(Info{State: StateLocked, Tier: TierEnterprise})
	if PermitsNow(ProductAV) || PermitsNow(ProductCommon) {
		t.Fatal("locked licence still permitted a product line")
	}
	SetInitial(Info{State: StateValid})
	if PermitsNow(ProductAV) {
		t.Fatal("state with no tier permitted a product line")
	}
}

// ProductLinesFor returns the tier's product lines sorted, for display. Common is included.
func TestProductLinesFor_SortedAndCommonIncluded(t *testing.T) {
	got, err := ProductLinesFor(TierCore)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"av", "common", "email", "network", "waf"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v, want %v", got, want)
		}
	}
	if _, err := ProductLinesFor(Tier("Platinum")); err == nil {
		t.Fatal("unknown tier accepted")
	}
}
