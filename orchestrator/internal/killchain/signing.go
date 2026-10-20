package killchain

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/audspect/bas/internal/integrity"
)

// ErrUnsignedCampaign is returned when a campaign definition has no signature,
// or when its signature does not verify. An unsigned built-in definition is
// never loaded.
var ErrUnsignedCampaign = errors.New("killchain: campaign definition is not signed or the signature does not verify")

// VerifyCampaignSignature checks a campaign definition against its .sig file.
// The signature format is the one scenarios use: base64 text of an RSA PKCS#1
// v1.5 signature over the SHA-256 of the exact file bytes, written by
// scripts/signer.go. The same verifier as scenario content is used, so there is
// one trust root.
func VerifyCampaignSignature(content, sigFile []byte, v integrity.Verifier) error {
	trimmed := bytes.TrimSpace(sigFile)
	if len(trimmed) == 0 {
		return ErrUnsignedCampaign
	}
	raw, err := base64.StdEncoding.DecodeString(string(trimmed))
	if err != nil {
		return fmt.Errorf("%w: signature is not base64", ErrUnsignedCampaign)
	}
	ok, err := v.Verify(content, raw)
	if err != nil || !ok {
		return fmt.Errorf("%w: %v", ErrUnsignedCampaign, err)
	}
	return nil
}

// LoadSignedCampaign verifies the signature first and only then parses the
// definition. Verification runs on the bytes as read, before any decoding.
func LoadSignedCampaign(content, sigFile []byte, v integrity.Verifier) (CampaignDef, error) {
	if err := VerifyCampaignSignature(content, sigFile, v); err != nil {
		return CampaignDef{}, err
	}
	return ParseCampaignDef(content)
}
