package killchain

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/audspect/bas/internal/integrity"
)

func shippedCampaign(t *testing.T) (content, sig []byte) {
	t.Helper()
	content, err := os.ReadFile(filepath.Join("campaigns", "identity-endpoint-lateral.json"))
	if err != nil {
		t.Fatal(err)
	}
	sig, err = os.ReadFile(filepath.Join("campaigns", "identity-endpoint-lateral.json.sig"))
	if err != nil {
		t.Fatal(err)
	}
	return content, sig
}

// The shipped definition must verify with the same trust root as scenarios.
func TestSigning_ShippedCampaignVerifies(t *testing.T) {
	content, sig := shippedCampaign(t)
	if err := VerifyCampaignSignature(content, sig, integrity.CompiledVerifier{}); err != nil {
		t.Fatalf("shipped campaign does not verify: %v", err)
	}
}

// A single changed byte must fail verification, even though the JSON still parses.
func TestSigning_TamperedDefinitionIsRefused(t *testing.T) {
	content, sig := shippedCampaign(t)
	tampered := bytes.Replace(content, []byte(`"shouldBlock": true`), []byte(`"shouldBlock": false`), 1)
	if bytes.Equal(tampered, content) {
		t.Fatalf("test setup: nothing was changed")
	}
	_, err := LoadSignedCampaign(tampered, sig, integrity.CompiledVerifier{})
	if !errors.Is(err, ErrUnsignedCampaign) {
		t.Fatalf("tampered definition loaded: err = %v", err)
	}
}

func TestSigning_MissingSignatureIsRefused(t *testing.T) {
	content, _ := shippedCampaign(t)
	if _, err := LoadSignedCampaign(content, nil, integrity.CompiledVerifier{}); !errors.Is(err, ErrUnsignedCampaign) {
		t.Fatalf("unsigned definition loaded: err = %v", err)
	}
}

func TestSigning_MalformedSignatureIsRefused(t *testing.T) {
	content, _ := shippedCampaign(t)
	if err := VerifyCampaignSignature(content, []byte("not base64 !!"), integrity.CompiledVerifier{}); !errors.Is(err, ErrUnsignedCampaign) {
		t.Fatalf("malformed signature accepted: %v", err)
	}
}
