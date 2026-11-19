// Package envelope encrypts application data with a fresh data-encryption key (DEK) per value, and wraps that
// DEK under a customer-controlled key-encryption key (KEK) held by a kms.Provider. See
// docs/superpowers/specs/2026-11-11-req039-key-management-architecture.md.
//
// Revocation is checked on every Open, not only on cache misses. A DEK in the cache is a performance shortcut
// for the provider's unwrap call, never a grant of access: if the KEK is disabled or revoked, or its status
// cannot be confirmed, Open fails even when the DEK is cached.
package envelope

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/audspect/bas/internal/kms"
)

const version byte = 0x01

// ErrBadEnvelope is returned for a blob that is not a well-formed envelope of this version.
var ErrBadEnvelope = errors.New("envelope: malformed or unsupported envelope")

// ErrDecrypt is returned when authentication fails. It never says why, so it cannot be used as an oracle.
var ErrDecrypt = errors.New("envelope: decryption failed")

// Config bounds the DEK cache. Zero values take the defaults.
type Config struct {
	// MaxCacheAge is the longest a DEK stays cached before it is unwrapped again. Default 5 minutes.
	MaxCacheAge time.Duration
	// MaxEntries bounds the cache. When full, every cached DEK is zeroed and the cache starts again. Default 1024.
	MaxEntries int
}

type cacheEntry struct {
	ref      kms.KeyRef
	dek      []byte
	cachedAt time.Time
}

// Manager seals and opens values. It is safe for concurrent use.
type Manager struct {
	provider kms.Provider
	cfg      Config

	mu    sync.Mutex
	cache map[[32]byte]*cacheEntry
}

// New returns a Manager over provider.
func New(provider kms.Provider, cfg Config) *Manager {
	if cfg.MaxCacheAge <= 0 {
		cfg.MaxCacheAge = 5 * time.Minute
	}
	if cfg.MaxEntries <= 0 {
		cfg.MaxEntries = 1024
	}
	return &Manager{provider: provider, cfg: cfg, cache: map[[32]byte]*cacheEntry{}}
}

// Seal encrypts plain under the KEK ref. label names the purpose (for example "connector_credentials"); it is
// authenticated but not encrypted, so an envelope opened under a different label fails.
func (m *Manager) Seal(ctx context.Context, ref kms.KeyRef, label string, plain []byte) ([]byte, error) {
	if err := m.requireActive(ctx, ref); err != nil {
		return nil, err
	}
	dek := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, dek); err != nil {
		return nil, err
	}
	defer zero(dek)

	wrapped, err := m.provider.WrapDEK(ctx, ref, dek)
	if err != nil {
		return nil, err
	}
	gcm, err := newGCM(dek)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	ct := gcm.Seal(nil, nonce, plain, aad(ref, label))

	out := make([]byte, 0, 1+2+len(ref)+2+len(wrapped)+len(nonce)+len(ct))
	out = append(out, version)
	out = binary.BigEndian.AppendUint16(out, uint16(len(ref)))
	out = append(out, ref...)
	out = binary.BigEndian.AppendUint16(out, uint16(len(wrapped)))
	out = append(out, wrapped...)
	out = append(out, nonce...)
	out = append(out, ct...)
	return out, nil
}

// Open decrypts an envelope produced by Seal under the same label. It confirms the KEK's status first, every time.
func (m *Manager) Open(ctx context.Context, label string, blob []byte) ([]byte, error) {
	ref, wrapped, nonce, ct, err := parse(blob)
	if err != nil {
		return nil, err
	}
	if err := m.requireActive(ctx, ref); err != nil {
		return nil, err
	}
	dek, err := m.dekFor(ctx, ref, wrapped)
	if err != nil {
		return nil, err
	}
	gcm, err := newGCM(dek)
	if err != nil {
		return nil, err
	}
	if len(nonce) != gcm.NonceSize() {
		return nil, ErrBadEnvelope
	}
	plain, err := gcm.Open(nil, nonce, ct, aad(ref, label))
	if err != nil {
		return nil, ErrDecrypt
	}
	return plain, nil
}

// Invalidate zeroes and drops every cached DEK for ref. Call it when a key is disabled, revoked or rotated.
func (m *Manager) Invalidate(ref kms.KeyRef) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for k, e := range m.cache {
		if e.ref == ref {
			zero(e.dek)
			delete(m.cache, k)
		}
	}
}

// requireActive confirms the KEK is usable. Anything but active drops that key's cached DEKs and fails.
func (m *Manager) requireActive(ctx context.Context, ref kms.KeyRef) error {
	status, err := m.provider.Status(ctx, ref)
	if err != nil {
		m.Invalidate(ref)
		if errors.Is(err, kms.ErrStatusUnknown) {
			return err
		}
		return fmt.Errorf("%w: %v", kms.ErrStatusUnknown, err)
	}
	switch status {
	case kms.StatusActive:
		return nil
	case kms.StatusDisabled:
		m.Invalidate(ref)
		return kms.ErrKeyDisabled
	case kms.StatusRevoked:
		m.Invalidate(ref)
		return kms.ErrKeyRevoked
	default:
		m.Invalidate(ref)
		return kms.ErrKeyNotFound
	}
}

// dekFor returns the DEK for a wrapped key, from the cache when it is fresh, otherwise by unwrapping it.
func (m *Manager) dekFor(ctx context.Context, ref kms.KeyRef, wrapped []byte) ([]byte, error) {
	key := sha256.Sum256(append([]byte(ref+"\x00"), wrapped...))

	m.mu.Lock()
	if e, ok := m.cache[key]; ok && time.Since(e.cachedAt) <= m.cfg.MaxCacheAge {
		dek := e.dek
		m.mu.Unlock()
		return dek, nil
	}
	m.mu.Unlock()

	dek, err := m.provider.UnwrapDEK(ctx, ref, wrapped)
	if err != nil {
		return nil, err
	}
	if len(dek) != 32 {
		zero(dek)
		return nil, ErrBadEnvelope
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	if old, ok := m.cache[key]; ok {
		zero(old.dek)
	}
	if len(m.cache) >= m.cfg.MaxEntries {
		for k, e := range m.cache {
			zero(e.dek)
			delete(m.cache, k)
		}
	}
	m.cache[key] = &cacheEntry{ref: ref, dek: dek, cachedAt: time.Now()}
	return dek, nil
}

func parse(blob []byte) (kms.KeyRef, []byte, []byte, []byte, error) {
	if len(blob) < 1 || blob[0] != version {
		return "", nil, nil, nil, ErrBadEnvelope
	}
	rest := blob[1:]
	refLen, rest, ok := takeLen(rest)
	if !ok || len(rest) < refLen {
		return "", nil, nil, nil, ErrBadEnvelope
	}
	ref := kms.KeyRef(rest[:refLen])
	rest = rest[refLen:]
	wrLen, rest, ok := takeLen(rest)
	if !ok || len(rest) < wrLen {
		return "", nil, nil, nil, ErrBadEnvelope
	}
	wrapped := rest[:wrLen]
	rest = rest[wrLen:]
	const nonceLen = 12
	if len(rest) < nonceLen+16 {
		return "", nil, nil, nil, ErrBadEnvelope
	}
	return ref, wrapped, rest[:nonceLen], rest[nonceLen:], nil
}

func takeLen(b []byte) (int, []byte, bool) {
	if len(b) < 2 {
		return 0, nil, false
	}
	return int(binary.BigEndian.Uint16(b[:2])), b[2:], true
}

// aad binds the envelope to its key and its purpose.
func aad(ref kms.KeyRef, label string) []byte {
	out := []byte{version}
	out = append(out, ref...)
	out = append(out, 0x00)
	return append(out, label...)
}

func newGCM(dek []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(dek)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
