//go:build windows

package main

import (
	"encoding/hex"
	"fmt"

	"golang.org/x/sys/windows/registry"
)

// dbcredStoreDir is unused on Windows (the DPAPI registry store is used); it
// exists so the shared dbcred code and tests compile on every platform.
var dbcredStoreDir = ""

// dbcredRegValue is the registry value holding the DPAPI-protected credential
// JSON for a reference name (the env var name plus "_ENC").
func dbcredRegValue(name string) string { return dbcredEnvName(name) + "_ENC" }

// decodeDPAPIHex decrypts a hex-encoded machine-scope DPAPI blob (the format
// StoreEncryptedSecret / StoreDBCredential write).
func decodeDPAPIHex(hexBlob string) ([]byte, error) {
	blob, err := hex.DecodeString(hexBlob)
	if err != nil {
		return nil, fmt.Errorf("stored credential is not valid hex")
	}
	plain, err := DecryptSecret(blob)
	if err != nil {
		return nil, fmt.Errorf("stored credential could not be decrypted")
	}
	return []byte(plain), nil
}

// SECURITY NOTE: machine-scope DPAPI under HKLM service parameters is only as
// protected as the registry key's ACL. This code neither verifies nor sets that
// ACL (it mirrors the proxy-credential mechanism); operators must restrict the
// service Parameters key to SYSTEM/Administrators.
//
// readStoredDBCredentialPlatform reads the DPAPI-protected value from the
// service Parameters registry key. Absent value => not found.
func readStoredDBCredentialPlatform(name string) ([]byte, bool, error) {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, paramKey, registry.QUERY_VALUE)
	if err != nil {
		return nil, false, nil
	}
	defer k.Close()
	hexBlob, _, err := k.GetStringValue(dbcredRegValue(name))
	if err != nil {
		if err == registry.ErrNotExist {
			return nil, false, nil
		}
		return nil, false, fmt.Errorf("registry read failed")
	}
	if hexBlob == "" {
		return nil, false, nil
	}
	plain, err := decodeDPAPIHex(hexBlob)
	if err != nil {
		return nil, false, err
	}
	return plain, true, nil
}

// SECURITY NOTE: the value is machine-scope DPAPI, so anything that can read the
// key and run as SYSTEM/Administrator on this host can decrypt it; the key's ACL
// is neither verified nor set here and operators must restrict it.
//
// StoreDBCredential DPAPI-encrypts the credential JSON for ref name and writes
// it to the service Parameters key (operator provisioning helper, mirrors
// StoreProxyCredentials; not wired to a CLI flag in this pass).
func StoreDBCredential(name, credentialJSON string) error {
	if _, err := parseDBCredential([]byte(credentialJSON)); err != nil {
		return err
	}
	blob, err := EncryptSecret(credentialJSON)
	if err != nil {
		return fmt.Errorf("encrypt credential: %w", err)
	}
	k, _, err := registry.CreateKey(registry.LOCAL_MACHINE, paramKey, registry.SET_VALUE)
	if err != nil {
		return fmt.Errorf("registry create key: %w", err)
	}
	defer k.Close()
	return k.SetStringValue(dbcredRegValue(name), hex.EncodeToString(blob))
}
