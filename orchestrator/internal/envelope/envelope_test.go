package envelope

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/audspect/bas/internal/kms"
	"github.com/audspect/bas/internal/kms/memprovider"
)

func newFixture(t *testing.T, cfg Config) (*Manager, *memprovider.Provider) {
	t.Helper()
	p := memprovider.New()
	if err := p.CreateKey("kek-a"); err != nil {
		t.Fatal(err)
	}
	if err := p.CreateKey("kek-b"); err != nil {
		t.Fatal(err)
	}
	return New(p, cfg), p
}

func TestSealOpenRoundTrip(t *testing.T) {
	m, _ := newFixture(t, Config{})
	ctx := context.Background()
	plain := []byte("connector password: hunter2")
	blob, err := m.Seal(ctx, "kek-a", "connector_credentials", plain)
	if err != nil {
		t.Fatal(err)
	}
	got, err := m.Open(ctx, "connector_credentials", blob)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, plain) {
		t.Errorf("round trip returned %q", got)
	}
}

// The blob must not contain the plaintext.
func TestCiphertextDoesNotContainPlaintext(t *testing.T) {
	m, _ := newFixture(t, Config{})
	plain := []byte("ABSOLUTELY-RECOGNISABLE-SECRET-VALUE")
	blob, err := m.Seal(context.Background(), "kek-a", "ctx", plain)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(blob, plain) {
		t.Fatal("plaintext appears in the envelope")
	}
}

// A blob moved to another context label fails: ciphertext cannot be swapped between tables or purposes.
func TestWrongContextLabelIsRejected(t *testing.T) {
	m, _ := newFixture(t, Config{})
	ctx := context.Background()
	blob, _ := m.Seal(ctx, "kek-a", "connector_credentials", []byte("x"))
	if _, err := m.Open(ctx, "run_results", blob); err == nil {
		t.Fatal("opening under a different context label must fail")
	}
}

func TestTamperedCiphertextIsRejected(t *testing.T) {
	m, _ := newFixture(t, Config{})
	ctx := context.Background()
	blob, _ := m.Seal(ctx, "kek-a", "ctx", []byte("payload"))
	blob[len(blob)-1] ^= 0x01
	if _, err := m.Open(ctx, "ctx", blob); err == nil {
		t.Fatal("a flipped ciphertext bit must fail authentication")
	}
}

func TestMalformedEnvelopeIsRejected(t *testing.T) {
	m, _ := newFixture(t, Config{})
	for _, b := range [][]byte{nil, {0x09}, {0x01, 0x00, 0x05, 'a'}} {
		if _, err := m.Open(context.Background(), "ctx", b); !errors.Is(err, ErrBadEnvelope) {
			t.Errorf("malformed %x: err = %v, want ErrBadEnvelope", b, err)
		}
	}
}

// Revocation takes effect at once, even for a DEK already cached from an earlier successful open.
func TestRevocationInvalidatesCachedDEK(t *testing.T) {
	m, p := newFixture(t, Config{})
	ctx := context.Background()
	blob, _ := m.Seal(ctx, "kek-a", "ctx", []byte("secret"))
	if _, err := m.Open(ctx, "ctx", blob); err != nil {
		t.Fatalf("baseline open failed: %v", err)
	}
	p.Revoke("kek-a")
	if _, err := m.Open(ctx, "ctx", blob); !errors.Is(err, kms.ErrKeyRevoked) {
		t.Fatalf("after revocation, open must fail closed with ErrKeyRevoked, got %v", err)
	}
}

// A disabled key blocks use; re-enabling it restores use. Revocation is not reversible, but disable is.
func TestDisabledKeyBlocksAndEnableRestores(t *testing.T) {
	m, p := newFixture(t, Config{})
	ctx := context.Background()
	blob, _ := m.Seal(ctx, "kek-a", "ctx", []byte("secret"))
	p.Disable("kek-a")
	if _, err := m.Open(ctx, "ctx", blob); !errors.Is(err, kms.ErrKeyDisabled) {
		t.Fatalf("disabled key: err = %v, want ErrKeyDisabled", err)
	}
	p.Enable("kek-a")
	if got, err := m.Open(ctx, "ctx", blob); err != nil || string(got) != "secret" {
		t.Fatalf("after re-enable: %q, %v", got, err)
	}
}

// If the key status cannot be confirmed, the decrypt fails closed, even with a warm cache.
func TestStatusFailureFailsClosed(t *testing.T) {
	m, p := newFixture(t, Config{})
	ctx := context.Background()
	blob, _ := m.Seal(ctx, "kek-a", "ctx", []byte("secret"))
	if _, err := m.Open(ctx, "ctx", blob); err != nil {
		t.Fatal(err)
	}
	p.Failing = true
	if _, err := m.Open(ctx, "ctx", blob); !errors.Is(err, kms.ErrStatusUnknown) {
		t.Fatalf("status unknown: err = %v, want ErrStatusUnknown", err)
	}
}

// A warm cache avoids a provider unwrap while the key is still active.
func TestCacheAvoidsRepeatedUnwrap(t *testing.T) {
	m, p := newFixture(t, Config{})
	ctx := context.Background()
	blob, _ := m.Seal(ctx, "kek-a", "ctx", []byte("secret"))
	for i := 0; i < 5; i++ {
		if _, err := m.Open(ctx, "ctx", blob); err != nil {
			t.Fatal(err)
		}
	}
	if p.UnwrapCalls != 1 {
		t.Errorf("unwrap calls = %d, want 1 (cache hit on the rest)", p.UnwrapCalls)
	}
}

// Cached DEKs expire after MaxCacheAge and are unwrapped again.
func TestCacheExpires(t *testing.T) {
	m, p := newFixture(t, Config{MaxCacheAge: time.Millisecond})
	ctx := context.Background()
	blob, _ := m.Seal(ctx, "kek-a", "ctx", []byte("secret"))
	if _, err := m.Open(ctx, "ctx", blob); err != nil {
		t.Fatal(err)
	}
	time.Sleep(5 * time.Millisecond)
	if _, err := m.Open(ctx, "ctx", blob); err != nil {
		t.Fatal(err)
	}
	if p.UnwrapCalls != 2 {
		t.Errorf("unwrap calls = %d, want 2 after expiry", p.UnwrapCalls)
	}
}

// Invalidating one key drops only its cached DEKs.
func TestInvalidateIsScopedToOneKey(t *testing.T) {
	m, p := newFixture(t, Config{})
	ctx := context.Background()
	ba, _ := m.Seal(ctx, "kek-a", "ctx", []byte("a"))
	bb, _ := m.Seal(ctx, "kek-b", "ctx", []byte("b"))
	m.Open(ctx, "ctx", ba)
	m.Open(ctx, "ctx", bb)
	before := p.UnwrapCalls
	m.Invalidate("kek-a")
	m.Open(ctx, "ctx", bb) // still cached
	if p.UnwrapCalls != before {
		t.Error("invalidating kek-a must not evict kek-b's DEK")
	}
	m.Open(ctx, "ctx", ba) // evicted, so unwrapped again
	if p.UnwrapCalls != before+1 {
		t.Error("invalidating kek-a must force kek-a's DEK to be unwrapped again")
	}
}

// Revoking one key does not make another key's data unreadable.
func TestRevokingOneKeyLeavesOthersReadable(t *testing.T) {
	m, p := newFixture(t, Config{})
	ctx := context.Background()
	bb, _ := m.Seal(ctx, "kek-b", "ctx", []byte("b"))
	p.Revoke("kek-a")
	if got, err := m.Open(ctx, "ctx", bb); err != nil || string(got) != "b" {
		t.Fatalf("kek-b must stay readable: %q, %v", got, err)
	}
}
