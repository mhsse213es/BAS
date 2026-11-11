package secretstore

import (
	"context"
	"errors"

	"github.com/audspect/bas/internal/envelope"
	"github.com/audspect/bas/internal/kms"
	"github.com/audspect/bas/internal/kms/vault"
	"github.com/jackc/pgx/v5/pgxpool"
)

// NoLegacy is the legacy backend used when the pgcrypto key is unavailable. Every reference reports not found, so a
// value that exists only in the legacy table fails its own operation instead of being read without its key.
type NoLegacy struct{}

// Get always reports not found.
func (NoLegacy) Get(context.Context, string) (string, error) { return "", ErrNotFound }

// Put is refused: with no legacy backend there is nothing to fall back to, and writes go to the primary only.
func (NoLegacy) Put(context.Context, string, string) error {
	return errors.New("secretstore: no legacy backend")
}

// Delete is a no-op: there is no legacy row to remove.
func (NoLegacy) Delete(context.Context, string) error { return nil }

// OpenConfigured returns the credential store the process should use.
//
//   - BAS_KMS unset or "legacy": the existing pgcrypto store, unchanged.
//   - BAS_KMS=vault: values are sealed under a KEK in Vault. Required: BAS_VAULT_ADDR, BAS_VAULT_KEY_NAME and
//     BAS_VAULT_TOKEN_FILE. Optional: BAS_VAULT_MOUNT (default "transit") and BAS_VAULT_ALLOW_PLAIN_HTTP=1 (development
//     only). The legacy pgcrypto store is kept as a read fallback for values not yet migrated. If its key is missing,
//     the store still starts, and legacy-only values report not found.
//
// Any other BAS_KMS value is an error, so a typo never silently selects the legacy path.
func OpenConfigured(pool *pgxpool.Pool, legacyKeyPath string, getenv func(string) string) (Store, error) {
	switch getenv("BAS_KMS") {
	case "", "legacy":
		return OpenStore(pool, legacyKeyPath)
	case "vault":
	default:
		return nil, errors.New("secretstore: BAS_KMS must be \"legacy\" or \"vault\"")
	}
	addr, keyName, tokenFile := getenv("BAS_VAULT_ADDR"), getenv("BAS_VAULT_KEY_NAME"), getenv("BAS_VAULT_TOKEN_FILE")
	if addr == "" || keyName == "" || tokenFile == "" {
		return nil, errors.New("secretstore: BAS_KMS=vault needs BAS_VAULT_ADDR, BAS_VAULT_KEY_NAME and BAS_VAULT_TOKEN_FILE")
	}
	token, err := vault.LoadToken(tokenFile)
	if err != nil {
		return nil, err
	}
	prov, err := vault.New(vault.Config{
		Address:        addr,
		Token:          token,
		MountPath:      getenv("BAS_VAULT_MOUNT"),
		AllowPlainHTTP: getenv("BAS_VAULT_ALLOW_PLAIN_HTTP") == "1",
	})
	if err != nil {
		return nil, err
	}
	primary, err := NewEnvelopeStore(pool, envelope.New(prov, envelope.Config{}), kms.KeyRef(keyName))
	if err != nil {
		return nil, err
	}
	var legacy Store = NoLegacy{}
	if l, lerr := OpenStore(pool, legacyKeyPath); lerr == nil {
		legacy = l
	}
	return &Composite{Primary: primary, Legacy: legacy}, nil
}
