package intelligence

import "testing"

func TestMalwareKey_NormalizesCase(t *testing.T) {
	if got := MalwareKey("Emotet"); got != "emotet" {
		t.Fatalf("MalwareKey(%q) = %q, want %q", "Emotet", got, "emotet")
	}
}

func TestMalwareKey_StripsSpacesAndHyphens(t *testing.T) {
	cases := []struct{ in, want string }{
		{"Cobalt Strike", "cobaltstrike"},
		{"BlackCat/ALPHV", "blackcat/alphv"}, // slash intentionally untouched -- only spaces/hyphens are stripped, matching connector.actorKey()'s exact scope
		{"Trickbot-v2", "trickbotv2"},
	}
	for _, c := range cases {
		if got := MalwareKey(c.in); got != c.want {
			t.Errorf("MalwareKey(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestMalwareKey_SameKeyForDifferentCasing(t *testing.T) {
	if MalwareKey("Emotet") != MalwareKey("EMOTET") {
		t.Fatal("expected case-insensitive dedup key")
	}
}
