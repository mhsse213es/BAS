package dbsim

import (
	"context"
	"errors"
	"testing"
)

func TestMemoryResolverResolvesRegisteredTarget(t *testing.T) {
	want := goodTarget(ModeLab)
	want.Database, want.TLSMode, want.CredentialRef = "appdb", "require", "dbcred:lab-pg"
	r := NewMemoryResolver(want)
	got, err := r.Resolve(context.Background(), want.ID)
	if err != nil || got != want {
		t.Fatalf("got %+v, %v", got, err)
	}
}

func TestMemoryResolverUnknownTarget(t *testing.T) {
	r := NewMemoryResolver(goodTarget(ModeLab))
	_, err := r.Resolve(context.Background(), "nope")
	if !errors.Is(err, ErrTargetNotFound) {
		t.Fatalf("want ErrTargetNotFound, got %v", err)
	}
}

func TestMemoryResolverHonoursContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := NewMemoryResolver(goodTarget(ModeLab)).Resolve(ctx, "t1"); err == nil {
		t.Fatal("cancelled context resolved a target")
	}
}
