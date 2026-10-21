package lab

import (
	"slices"
	"testing"

	"github.com/audspect/bas/internal/apibas/detect"
)

// A class is set only on the structure it names. Ordinary text, including text with a semicolon or the word "prototype",
// carries no class.
func TestInjectionClassCookieAttribute(t *testing.T) {
	positive := []string{
		"x; Domain=attacker.example",
		"x; path=/",
		"x; Max-Age=0",
		"x; SameSite=None",
		"x; HttpOnly",
		"x; Secure",
	}
	for _, text := range positive {
		if !slices.Contains(injectionClasses(text), detect.SignatureCookie) {
			t.Errorf("%q: no cookie_attribute class, want one", text)
		}
	}
	negative := []string{
		"invoice-42",
		"thanks; see you soon",
		"x; path of the work", // a semicolon and a word, no attribute value
		"domain name is example.com",
	}
	for _, text := range negative {
		if slices.Contains(injectionClasses(text), detect.SignatureCookie) {
			t.Errorf("%q: cookie_attribute class on ordinary text", text)
		}
	}
}

func TestInjectionClassPrototypeKey(t *testing.T) {
	positive := []string{
		`{"__proto__": {"owner_id": "cust-a"}}`,
		`{"constructor.prototype": {"x": 1}}`,
	}
	for _, text := range positive {
		if !slices.Contains(injectionClasses(text), detect.SignaturePrototype) {
			t.Errorf("%q: no prototype_key class, want one", text)
		}
	}
	negative := []string{
		`{"gift_note": "thanks"}`,
		`the prototype pattern is common`,
		`{"constructor": "a builder"}`,
		`{"a": "__proto__"}`, // the word as a string value is not a prototype key
	}
	for _, text := range negative {
		if slices.Contains(injectionClasses(text), detect.SignaturePrototype) {
			t.Errorf("%q: prototype_key class on ordinary text", text)
		}
	}
}
