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
	"regexp"
	"sort"
	"strings"
)

// Manifest holds expected SHA-256 hashes for all shipped binaries.
type Manifest struct {
	hashes map[string]string // basename → lowercase hex sha256
	// prev holds hashes of earlier signed releases, listed on "#prev <hash>  <file>"
	// lines. An agent on one of these is outdated, not untrusted: it degrades until
	// it is upgraded, and it is never counted as a current trusted hash.
	prev map[string]bool
	// revoked holds hashes an operator has explicitly revoked, listed on "#revoked <hash>  <file>" lines. A revoked
	// binary is never trusted and never counts as a previous release, even if it is also listed as one. Revocation is
	// separate from retirement: an old release stays "outdated" until someone revokes it.
	revoked map[string]bool
	// prevVersion is the version of the release before this one, from a "#prev-version <v>" line the build writes next
	// to the "#prev" hashes. The server uses it as the default fleet minimum agent version. Empty when not recorded.
	prevVersion string
}

// LoadManifest reads BINARIES.sha256 from path.
// Returns an empty (non-nil) manifest if the file is absent — callers treat
// missing manifest as "hash verification disabled" rather than an error.
func LoadManifest(path string) *Manifest {
	f, err := os.Open(path)
	if err != nil {
		if !os.IsNotExist(err) {
			log.Printf("[integrity] manifest open: %v", err)
		}
		return &Manifest{hashes: make(map[string]string), prev: make(map[string]bool)}
	}
	defer f.Close()

	var lines []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	if err := scanner.Err(); err != nil {
		log.Printf("[integrity] manifest read: %v", err)
	}
	m := parseManifestLines(lines)
	log.Printf("[integrity] manifest loaded: %d entries (%d previous-release) from %s", len(m.hashes), len(m.prev), path)
	return m
}

// parseManifestLines is the single parser for BINARIES.sha256 content, shared by
// LoadManifest and the signature-checked LoadManifestVerified so they can't disagree.
//
//	<sha256hex>  <filename>            current release
//	#prev <sha256hex>  <filename>      previous signed release (outdated, not trusted)
//	#prev-version <version>            the previous release's version, such as 1.9.9.3
//	#revoked <sha256hex>  <filename>   revoked binary (never trusted)
//	# ...                              comment
func parseManifestLines(lines []string) *Manifest {
	m := &Manifest{hashes: make(map[string]string), prev: make(map[string]bool), revoked: make(map[string]bool)}
	for _, raw := range lines {
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "#prev-version ") {
			parts := strings.Fields(strings.TrimPrefix(line, "#prev-version "))
			if len(parts) == 1 && prevVersionPattern.MatchString(parts[0]) {
				m.prevVersion = parts[0]
			}
			continue
		}
		if strings.HasPrefix(line, "#revoked ") {
			parts := strings.Fields(strings.TrimPrefix(line, "#revoked "))
			if len(parts) >= 2 {
				m.revoked[strings.ToLower(parts[0])] = true
			}
			continue
		}
		if strings.HasPrefix(line, "#prev ") {
			parts := strings.Fields(strings.TrimPrefix(line, "#prev "))
			if len(parts) >= 2 {
				m.prev[strings.ToLower(parts[0])] = true
			}
			continue
		}
		if strings.HasPrefix(line, "#") {
			continue
		}
		// Format: "<sha256hex>  <filename>"
		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue
		}
		// Strip any leading "./" the manifest writer may have included
		filename := strings.TrimPrefix(parts[1], "./")
		m.hashes[filename] = strings.ToLower(parts[0])
	}
	return m
}

var prevVersionPattern = regexp.MustCompile(`^[0-9]+(\.[0-9]+){0,3}$`)

// PreviousReleaseVersion returns the version of the release before this one, or "" when the manifest does not say.
func (m *Manifest) PreviousReleaseVersion() string { return m.prevVersion }

// RevokedHashes returns the hashes the signed manifest revokes, sorted. They cannot be reversed from the console.
func (m *Manifest) RevokedHashes() []string {
	out := make([]string, 0, len(m.revoked))
	for h := range m.revoked {
		out = append(out, h)
	}
	sort.Strings(out)
	return out
}

// HashPreviousRelease reports whether hexHash is a previous signed release (outdated).
func (m *Manifest) HashPreviousRelease(hexHash string) bool {
	return m.prev[strings.ToLower(hexHash)]
}

// HashRevoked reports whether an operator has revoked hexHash. Revoked is checked before trust or previous release.
func (m *Manifest) HashRevoked(hexHash string) bool {
	return m.revoked[strings.ToLower(hexHash)]
}

// TrustedHash reports whether hexHash is a current signed release and is not revoked. This is the Verified flag.
func (m *Manifest) TrustedHash(hexHash string) bool {
	return m.HashKnown(hexHash) && !m.HashRevoked(hexHash)
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
