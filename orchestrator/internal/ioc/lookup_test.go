package ioc

import (
	"context"
	"testing"
)

type stubProvider struct {
	name string
}

func (s *stubProvider) Name() string { return s.name }
func (s *stubProvider) LookupIP(ctx context.Context, v string) (*Result, error) {
	return &Result{Indicator: v, Type: "ip"}, nil
}
func (s *stubProvider) LookupDomain(ctx context.Context, v string) (*Result, error) {
	return &Result{Indicator: v, Type: "domain"}, nil
}
func (s *stubProvider) LookupURL(ctx context.Context, v string) (*Result, error) {
	return &Result{Indicator: v, Type: "url"}, nil
}
func (s *stubProvider) LookupHash(ctx context.Context, v string) (*Result, error) {
	return &Result{Indicator: v, Type: "hash"}, nil
}
func (s *stubProvider) LookupCVE(ctx context.Context, v string) (*Result, error) {
	return &Result{Indicator: v, Type: "cve"}, nil
}

func TestLookup_DispatchesToCorrectMethod(t *testing.T) {
	p := &stubProvider{name: "stub"}
	cases := []string{"ip", "domain", "url", "hash", "cve"}
	for _, typ := range cases {
		got, err := Lookup(context.Background(), p, typ, "v")
		if err != nil {
			t.Fatalf("Lookup(%q): %v", typ, err)
		}
		if got.Type != typ {
			t.Errorf("Lookup(%q) returned Type %q", typ, got.Type)
		}
	}
}

func TestLookup_UnknownType_ReturnsError(t *testing.T) {
	p := &stubProvider{name: "stub"}
	_, err := Lookup(context.Background(), p, "not-a-type", "v")
	if err == nil {
		t.Fatal("Lookup with an unknown type returned no error")
	}
}
