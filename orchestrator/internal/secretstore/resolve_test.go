package secretstore

import (
	"context"
	"errors"
	"testing"
)

type memStore struct{ m map[string]string }

func (s memStore) Put(_ context.Context, ref, v string) error { s.m[ref] = v; return nil }
func (s memStore) Get(_ context.Context, ref string) (string, error) {
	v, ok := s.m[ref]
	if !ok {
		return "", ErrNotFound
	}
	return v, nil
}
func (s memStore) Delete(_ context.Context, ref string) error { delete(s.m, ref); return nil }

const testRef = "cred:siem_configs:row1:token"

func TestResolveEmptyRefUsesPlaintext(t *testing.T) {
	got, err := Resolve(context.Background(), nil, "", "plain-value")
	if err != nil || got != "plain-value" {
		t.Fatalf("Resolve = %q, %v; want plaintext", got, err)
	}
}

func TestResolveReadsStore(t *testing.T) {
	s := memStore{m: map[string]string{testRef: "stored"}}
	got, err := Resolve(context.Background(), s, testRef, "stale-plain")
	if err != nil || got != "stored" {
		t.Fatalf("Resolve = %q, %v; want the stored value, not the plaintext", got, err)
	}
}

func TestResolveFailsClosedWithoutStore(t *testing.T) {
	_, err := Resolve(context.Background(), nil, testRef, "plain-value")
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("err = %v, want ErrUnavailable: a reference must never fall back to plaintext", err)
	}
}

func TestResolveFailsClosedOnMissingValue(t *testing.T) {
	s := memStore{m: map[string]string{}}
	_, err := Resolve(context.Background(), s, testRef, "plain-value")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}

func TestResolveRefusesMalformedRef(t *testing.T) {
	_, err := Resolve(context.Background(), memStore{m: map[string]string{}}, "cred:x/../y:1:z", "")
	if !errors.Is(err, ErrBadRef) {
		t.Fatalf("err = %v, want ErrBadRef", err)
	}
}
