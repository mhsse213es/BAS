// Package integrity loads the BINARIES.sha256 manifest produced by
// packaging/signing/sign-binaries.sh and exposes hash lookups used to
// verify agent binary authenticity at registration time.
package integrity

import (
	"bufio"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"log"
	"os"
	"strings"
)

// Manifest holds expected SHA-256 hashes for all shipped binaries.
type Manifest struct {
	hashes map[string]string // basename → lowercase hex sha256
}

// LoadManifest reads BINARIES.sha256 from path.
// Returns an empty (non-nil) manifest if the file is absent — callers treat
// missing manifest as "hash verification disabled" rather than an error.
func LoadManifest(path string) *Manifest {
	m := &Manifest{hashes: make(map[string]string)}
	f, err := os.Open(path)
	if err != nil {
		if !os.IsNotExist(err) {
			log.Printf("[integrity] manifest open: %v", err)
		}
		return m
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// Format: "<sha256hex>  <filename>"
		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue
		}
		hashHex := strings.ToLower(parts[0])
		filename := parts[1]
		// Strip any leading "./" the manifest writer may have included
		filename = strings.TrimPrefix(filename, "./")
		m.hashes[filename] = hashHex
	}
	if err := scanner.Err(); err != nil {
		log.Printf("[integrity] manifest read: %v", err)
	}
	log.Printf("[integrity] manifest loaded: %d entries from %s", len(m.hashes), path)
	return m
}

// KnownHash returns the expected SHA-256 hex for a binary filename.
// Returns ("", false) when the manifest is empty or the file is not listed.
func (m *Manifest) KnownHash(filename string) (string, bool) {
	if len(m.hashes) == 0 {
		return "", false
	}
	h, ok := m.hashes[strings.TrimPrefix(filename, "./")]
	return h, ok
}

// Loaded reports whether the manifest contains at least one entry.
func (m *Manifest) Loaded() bool {
	return len(m.hashes) > 0
}

// HashKnown returns true if the given hex hash matches any entry in the manifest.
// Used when the exact binary filename is not known but the hash is.
func (m *Manifest) HashKnown(hexHash string) bool {
	h := strings.ToLower(hexHash)
	for _, v := range m.hashes {
		if v == h {
			return true
		}
	}
	return false
}

// VerifyResultMAC checks the X-Result-MAC header value against the expected
// HMAC-SHA256 of body using secret. Returns true when the MAC is valid,
// or when secret is empty (MAC enforcement disabled).
func VerifyResultMAC(body []byte, secret, provided string) bool {
	if secret == "" {
		return true
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	expected := hex.EncodeToString(mac.Sum(nil))
	return hmac.Equal([]byte(expected), []byte(provided))
}
