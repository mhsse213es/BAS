package k8sscenario

import (
	"errors"
	"testing"
)

func TestCanonicalServerURL(t *testing.T) {
	cases := []struct {
		in, want string
		bad      bool
	}{
		{in: "https://K8s.Lab.Example:6443", want: "https://k8s.lab.example:6443"},
		{in: "https://k8s.lab.example/", want: "https://k8s.lab.example"},
		{in: "  https://10.0.0.5:6443  ", want: "https://10.0.0.5:6443"},
		{in: "http://k8s.lab.example:6443", bad: true},
		{in: "https://k8s.lab.example/api", bad: true},
		{in: "https://k8s.lab.example?x=1", bad: true},
		{in: "https://user:pw@k8s.lab.example", bad: true},
		{in: "https://", bad: true},
		{in: "not a url", bad: true},
	}
	for _, c := range cases {
		got, err := CanonicalServerURL(c.in)
		if c.bad {
			if !errors.Is(err, ErrInvalidRegistration) {
				t.Errorf("%q: want ErrInvalidRegistration, got %v (value %q)", c.in, err, got)
			}
			continue
		}
		if err != nil || got != c.want {
			t.Errorf("%q: got %q, %v; want %q", c.in, got, err, c.want)
		}
	}
}

func TestValidateRegistration(t *testing.T) {
	ok, err := ValidateRegistration("lab-east", "https://k8s.lab.example:6443", ClassLab, true)
	if err != nil {
		t.Fatalf("valid registration refused: %v", err)
	}
	if ok.Class != ClassLab || ok.ServerURL != "https://k8s.lab.example:6443" || ok.DisplayName != "lab-east" {
		t.Errorf("unexpected record: %+v", ok)
	}

	refusals := []struct {
		name, display, server, class string
		admin                        bool
	}{
		{"empty name", "  ", "https://a.example", ClassLab, true},
		{"name with slash", "prod/east", "https://a.example", ClassLab, true},
		{"name too long", string(make([]byte, 65)), "https://a.example", ClassLab, true},
		{"plain http server", "x", "http://a.example", ClassLab, true},
		{"non-admin sets class", "x", "https://a.example", ClassLab, false},
		{"unknown class", "x", "https://a.example", "prod", true},
		{"empty class", "x", "https://a.example", "", true},
	}
	for _, c := range refusals {
		if _, err := ValidateRegistration(c.display, c.server, c.class, c.admin); !errors.Is(err, ErrInvalidRegistration) {
			t.Errorf("%s: want refusal, got %v", c.name, err)
		}
	}
}

func TestAllowedProfilesByClass(t *testing.T) {
	cases := map[string][]string{
		ClassLab:           {"safe", "lab", "controlled"},
		ClassNonProduction: {"safe", "controlled"},
		ClassProduction:    {"safe"},
	}
	for class, want := range cases {
		got := AllowedProfiles(class)
		if len(got) != len(want) {
			t.Fatalf("%s: got %v want %v", class, got, want)
		}
		for i := range want {
			if got[i] != want[i] {
				t.Errorf("%s: got %v want %v", class, got, want)
			}
		}
	}
	if AllowedProfiles("bogus") != nil {
		t.Error("unknown class must allow no profile")
	}
	for _, p := range AllowedProfiles(ClassProduction) {
		if p == "lab" || p == "controlled" {
			t.Errorf("production must never allow %q in this phase", p)
		}
	}
}
