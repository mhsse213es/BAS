package intelligence

import "testing"

func TestNormalizeKey_NormalizesCase(t *testing.T) {
	if got := NormalizeKey("Emotet"); got != "emotet" {
		t.Fatalf("NormalizeKey(%q) = %q, want %q", "Emotet", got, "emotet")
	}
}

func TestNormalizeKey_StripsSpacesAndHyphens(t *testing.T) {
	cases := []struct{ in, want string }{
		{"Cobalt Strike", "cobaltstrike"},
		{"BlackCat/ALPHV", "blackcat/alphv"}, // slash intentionally untouched -- only spaces/hyphens are stripped, matching connector.actorKey()'s exact scope
		{"Trickbot-v2", "trickbotv2"},
	}
	for _, c := range cases {
		if got := NormalizeKey(c.in); got != c.want {
			t.Errorf("NormalizeKey(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestNormalizeKey_SameKeyForDifferentCasing(t *testing.T) {
	if NormalizeKey("Emotet") != NormalizeKey("EMOTET") {
		t.Fatal("expected case-insensitive dedup key")
	}
}
