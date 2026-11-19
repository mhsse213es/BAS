// Package kms defines the interface between Audspect and a customer-controlled key provider (a KMS, an HSM
// or a secrets engine). See docs/superpowers/specs/2026-11-11-req039-key-management-architecture.md.
//
// The central rule is that a key-encryption key (KEK) never leaves its provider. The interface offers only
// wrap and unwrap of data-encryption keys (DEKs) and a status query. No method returns KEK material, so an
// implementation cannot leak it through this package's contract.
package kms

import (
	"context"
	"errors"
)

// KeyRef names a KEK inside a provider, for example an ARN, a Vault transit key name, a PKCS#11 object label.
// It is opaque to the envelope layer and is bound into every ciphertext as authenticated data.
type KeyRef string

// Status is the provider's view of a KEK.
type Status string

const (
	StatusActive   Status = "active"
	StatusDisabled Status = "disabled" // temporarily unusable; the customer may re-enable it
	StatusRevoked  Status = "revoked"  // destroyed or withdrawn; data under it must become unreadable
)

// Errors returned by providers and by the envelope layer. Callers match them with errors.Is.
var (
	ErrKeyNotFound   = errors.New("kms: key not found")
	ErrKeyRevoked    = errors.New("kms: key revoked; data protected under it is unreadable")
	ErrKeyDisabled   = errors.New("kms: key disabled")
	ErrStatusUnknown = errors.New("kms: key status could not be confirmed; refusing to decrypt")
)

// Provider wraps and unwraps data-encryption keys under a customer-controlled KEK.
//
// Implementations must:
//   - never return or log KEK material;
//   - return an error, never a guess, when the key cannot be used;
//   - make WrapDEK and UnwrapDEK fail when the key is not active.
type Provider interface {
	// Name identifies the provider type in audit records, for example "memory-test", "vault-transit", "pkcs11".
	Name() string

	// WrapDEK encrypts a DEK under the KEK named by ref.
	WrapDEK(ctx context.Context, ref KeyRef, dek []byte) ([]byte, error)

	// UnwrapDEK recovers a DEK previously produced by WrapDEK under the same ref.
	UnwrapDEK(ctx context.Context, ref KeyRef, wrapped []byte) ([]byte, error)

	// Status reports the current state of the KEK. The envelope layer calls it before using any cached DEK.
	Status(ctx context.Context, ref KeyRef) (Status, error)
}
