// Package memprovider is an in-memory kms.Provider for tests. It is NOT a production key store: its KEKs live in
// process memory and are lost on restart. Production providers (Vault Transit, PKCS#11, cloud KMS) are separate
// packages that implement kms.Provider against a customer-controlled system.
package memprovider

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
	"sync"

	"github.com/audspect/bas/internal/kms"
)

// Provider holds KEKs in memory. Revoke and Disable exist for tests to simulate a customer withdrawing a key.
type Provider struct {
	mu     sync.Mutex
	keys   map[kms.KeyRef][]byte
	status map[kms.KeyRef]kms.Status
	// Failing makes Status return an error, to test fail-closed behaviour.
	Failing bool
	// UnwrapCalls counts provider unwraps, so tests can verify cache behaviour.
	UnwrapCalls int
}

// New returns an empty provider.
func New() *Provider {
	return &Provider{keys: map[kms.KeyRef][]byte{}, status: map[kms.KeyRef]kms.Status{}}
}

// CreateKey makes a new active KEK under ref. It fails if ref already exists.
func (p *Provider) CreateKey(ref kms.KeyRef) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if _, ok := p.keys[ref]; ok {
		return fmt.Errorf("memprovider: key %q already exists", ref)
	}
	k := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, k); err != nil {
		return err
	}
	p.keys[ref] = k
	p.status[ref] = kms.StatusActive
	return nil
}

// Revoke withdraws a KEK permanently. Its key bytes are discarded.
func (p *Provider) Revoke(ref kms.KeyRef) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if k, ok := p.keys[ref]; ok {
		for i := range k {
			k[i] = 0
		}
		delete(p.keys, ref)
	}
	p.status[ref] = kms.StatusRevoked
}

// Disable makes a KEK unusable without destroying it.
func (p *Provider) Disable(ref kms.KeyRef) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.status[ref] = kms.StatusDisabled
}

// Enable makes a disabled KEK usable again. A revoked KEK cannot be enabled.
func (p *Provider) Enable(ref kms.KeyRef) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.status[ref] == kms.StatusDisabled {
		p.status[ref] = kms.StatusActive
	}
}

// Name implements kms.Provider.
func (p *Provider) Name() string { return "memory-test" }

// Status implements kms.Provider.
func (p *Provider) Status(_ context.Context, ref kms.KeyRef) (kms.Status, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.Failing {
		return "", kms.ErrStatusUnknown
	}
	s, ok := p.status[ref]
	if !ok {
		return "", kms.ErrKeyNotFound
	}
	return s, nil
}

// WrapDEK implements kms.Provider. The KEK is used inside this method and never returned.
func (p *Provider) WrapDEK(_ context.Context, ref kms.KeyRef, dek []byte) ([]byte, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if err := p.usable(ref); err != nil {
		return nil, err
	}
	return seal(p.keys[ref], dek)
}

// UnwrapDEK implements kms.Provider.
func (p *Provider) UnwrapDEK(_ context.Context, ref kms.KeyRef, wrapped []byte) ([]byte, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.UnwrapCalls++
	if err := p.usable(ref); err != nil {
		return nil, err
	}
	return open(p.keys[ref], wrapped)
}

func (p *Provider) usable(ref kms.KeyRef) error {
	switch p.status[ref] {
	case kms.StatusActive:
		return nil
	case kms.StatusDisabled:
		return kms.ErrKeyDisabled
	case kms.StatusRevoked:
		return kms.ErrKeyRevoked
	default:
		return kms.ErrKeyNotFound
	}
}

func seal(kek, plain []byte) ([]byte, error) {
	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	return append(nonce, gcm.Seal(nil, nonce, plain, nil)...), nil
}

func open(kek, wrapped []byte) ([]byte, error) {
	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(wrapped) < gcm.NonceSize() {
		return nil, fmt.Errorf("memprovider: wrapped key too short")
	}
	nonce, ct := wrapped[:gcm.NonceSize()], wrapped[gcm.NonceSize():]
	return gcm.Open(nil, nonce, ct, nil)
}
