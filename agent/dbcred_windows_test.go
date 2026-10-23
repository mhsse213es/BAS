//go:build windows

package main

import (
	"encoding/hex"
	"strings"
	"testing"
)

// The registry read itself needs HKLM; this pins the DPAPI + hex + strict JSON
// decode that readStoredDBCredentialPlatform performs on the stored value.
func TestDBCredDPAPIHexRoundTrip(t *testing.T) {
	const js = `{"user":"dpapi_user","password":"dpapi-pw"}`
	blob, err := EncryptSecret(js)
	if err != nil {
		t.Skipf("DPAPI unavailable here: %v", err)
	}
	if strings.Contains(string(blob), "dpapi-pw") {
		t.Fatal("blob is not encrypted")
	}
	plain, err := decodeDPAPIHex(hex.EncodeToString(blob))
	if err != nil {
		t.Fatal(err)
	}
	c, err := parseDBCredential(plain)
	if err != nil || c.User != "dpapi_user" || c.Password != "dpapi-pw" {
		t.Fatalf("round trip failed: %v %+v", err, c)
	}
	if _, err := decodeDPAPIHex("zz-not-hex"); err == nil {
		t.Fatal("bad hex must error")
	}
	if _, err := decodeDPAPIHex(hex.EncodeToString([]byte("not a dpapi blob"))); err == nil {
		t.Fatal("garbage blob must error")
	}
	if dbcredRegValue("lab-pg-ro") != "BAS_DBCRED_LAB_PG_RO_ENC" {
		t.Fatalf("registry value name: %s", dbcredRegValue("lab-pg-ro"))
	}
}
